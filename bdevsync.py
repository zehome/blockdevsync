#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Inspired by blocksync.py from Justin Azoff <justin@bouncybouncy.net>

Author: Laurent Coustet <ed@zehome.com> (c) 2012
LICENCE: BSD
"""

import subprocess
import traceback
import threading
import datetime
import hashlib
import struct
import select
import json
import time
import sys
import os

DEFAULT_BLOCKSIZE = 1024 * 1024 * 4 # 4MiB

# do not modify!
TRANSFER_COMPLETE = 0
TRANSFER_DIFF = 1

def prettynumber(n):
    l = []
    for i, c in enumerate(str(n)[::-1]):
        if i%3==0 and i!=0: l += ' '
        l += c
    return "".join(l[::-1])

class SpeedTransferThread(threading.Thread):
    """
    In verbose mode, the name of this class is obvious ;)
    """
    def __init__(self, bdev):
        self.bdev = bdev 
        self.exitEvt = threading.Event()
        super(SpeedTransferThread, self).__init__()
        self.setDaemon(True)

    def stop(self):
        self.exitEvt.set()

    def run(self):
        last_position = self.bdev._current_position
        while not self.exitEvt.wait(1):
            self.exitEvt.clear()

            # WARNING: call from another thread!
            # Race possible.
            speed = (self.bdev._current_position - last_position )
            self.bdev.setspeed(speed)

            last_position = current_position

class Block(object):
    """Represent a block of data"""
    def __init__(self, position, data):
        self.update(position, data)

    def __len__(self):
        """returns the block length"""
        if self.data:
            return len(self.data)
        else:
            return 0

    def __str__(self):
        return "position: %s len: %s" % (self.position, len(self))

    def update(self, position, data):
        self.position = position
        self.data = data
        self._hash = hashlib.sha1(self.data)
        return self._hash

class BlockDeviceException(Exception): pass
class BlockDeviceReadException(Exception): BlockDeviceException

class AbstractBlockDevice(object):
    def __init__(self, path, blocksize=DEFAULT_BLOCKSIZE):
        self.path = path
        self.blocksize = blocksize
        self._reset()

    def _reset(self):
        self.fd = None
        self.filesize = 0
        self.current_speed = 0
        self.eta = datetime.timedelta(0)
        self._current_position = 0
        self._hash = hashlib.sha1()

    def check_eof(self):
        """
        Check for end of file by comparing current_position
        and filesize.
        """
        return self._current_position >= self.filesize

    def open(self):
        """Please override this!"""
        assert(False)

    def _open(self, mode):
        try:
            self.fd = open(self.path, mode)
        except OSError, e:
            raise BlockDeviceReadException(
                    "Unable to open %s for reading: %s" % (
                        self.path, e.strerror))
        try:
            self._get_size()
        except IOError, e:
            raise BlockDeviceReadException(
                    "Unable to get size of %s: %s" % (
                    self.path, e.strerror))
        return self.fd

    def close(self):
        """
        WARNING: this will reset the block device.
        (you can't read the hash after close())
        """
        assert(self.fd is not None)
        self.fd.close()
        self._reset()

    def _get_size(self):
        assert(self.fd is not None)
        self.fd.seek(0, os.SEEK_END)
        try:
            self.filesize = self.fd.tell()
        finally:
            self.fd.seek(0, os.SEEK_SET)
    
    def _update_hash(self, block):
        self._hash.update(block.data)

    def read_next_block(self):
        """
        you should call this to read the next block of data.
        """
        assert(self.fd is not None)
        newblock = self.fd.read(self.blocksize)
        if not newblock:
            if self.filesize != self._current_position:
                raise BlockDeviceException("Inconsistent reading: "
                    "%s is %d long but I've only read %d and reached EOF!" % (
                        self.path, self.filesize, self._current_position))
        return Block(self._current_position, newblock)

    def get_hash(self):
        """
        WARNING: You can't call this until check_eof returns true!
        returns the global hash of this block device.
        """
        if not self.check_eof() or self.filesize == 0:
            raise BlockDeviceException(
                "You can't read the hash before check_eof()")
        return self._hash.hexdigest()
       
class ReaderBlockDevice(AbstractBlockDevice):
    def open(self):
        return self._open("rb")

    def read_next_block(self):
        block = super(ReaderBlockDevice, self).read_next_block()
        if block:
            self._update_hash(block)
            self._current_position += len(block)
        return block
 
class WriterBlockDevice(AbstractBlockDevice):
    def __init__(self, *args, **kwargs):
        super(WriterBlockDevice, self).__init__(*args, **kwargs)

    def open(self):
        mode = "rb+"
        if not os.path.exists(self.path):
            mode = "wb+"
        fd = self._open(mode)
        if self.filesize == 0:
            sys.stderr.write("%s created.\n" % (self.path,))
        return fd

    def normalize_destination(self, filesize):
        """
        DANGER: this method will truncate the block device
        to the size specified. (fill with 0 if file is extended,
            or DESTROY data at the end of file.)
        """
        self.fd.truncate(filesize)
        self._get_size()

    def read_next_block(self):
        block = super(WriterBlockDevice, self).read_next_block()
        # Do not update overall hash here! We need to compare before.
        if block:
            self._current_position += len(block)
        return block
 
    def write_block(self, block):
        if not (len(block) == self.blocksize or
            (self.filesize - self._current_position) == len(block)):
            raise BlockDeviceException("Invalid write.")
        self.fd.seek(block.position, os.SEEK_SET)
        self.fd.write(block.data)
        self.fd.seek(self._current_position, os.SEEK_SET) # Should be useless

    def setspeed(self, speed):
        """WARNING: called from external thread!"""
        self.current_speed = speed
        if speed > 0:
            self.eta = datetime.timedelta(
                    seconds = (self.filesize-self._current_position) / speed)

    def get_progress(self):
        if self.filesize == 0: # LC: Do not divide by 0!
            return ""
        return "%3.2f%% (%s/%s) speed: %s (eta: %ss)%s" % (
            (float(self._current_position)/self.filesize)*100.0,
            prettynumber(self._current_position), prettynumber(self.filesize),
            prettynumber(self.current_speed),
            self.eta,
            " "*10)

class ProtocolError(Exception): pass
class ProtocolReadError(ProtocolError): pass

class Protocol(object):
    """
    Protocol version 1.0
    This class is used to communicate between sender and receiver.
    """
    VERSION = 1.0
    HEADER_PACK_FMT = "<I" # JSON data len
    BLOCK_PACK_FMT = "<QI" # block position, block len

    def __init__(self, blocksize, filesize, filename):
        self.blocksize = blocksize
        self.filesize = filesize
        self.filename = filename
    
    def _pack(self, fmt, *args):
        try:
            return struct.pack(fmt, *args)
        except struct.error, e:
            raise ProtocolError("Invalid packed data: %s" % (e,))
    
    def _packlen(self, fmt):
        return struct.calcsize(fmt)

    def _read(self, f, size):
        return f.read(size)
    
    def _readline(self, f):
        return f.readline()

    def _write(self, f, data):
        f.write(data)
        f.flush()

    def header_encode(self):
        """serialize header to json."""
        json_data = json.dumps({
            "blocksize": self.blocksize,
            "filesize": self.filesize,
            "filename": self.filename,
            "version": self.VERSION,
            "hash": "sha1",
        })
        return self._pack(self.HEADER_PACK_FMT, len(json_data)) + json_data

    def header_send(self, f):
        """Send json header to remote."""
        self._write(f, self.header_sencode())

    def header_decode(self, json_data):
        """ json deserializer """
        try:
            return json.loads(json_data)
        except ValueError:
            raise ProtocolReadError("Invalid json data!")

    def header_read(self, f):
        """Read and deserialize header from remote."""
        data = self._read(f, self._packlen(self.HEADER_PACK_FMT))
        try:
            (datalen, ) = struct.unpack(self.HEADER_PACK_FMT, data)
        except struct.error, e:
            raise ProtocolReadError(
                "Invalid packed data: %s. Data: %s" % (e, data))

        data = self._read(f, datalen)
        if len(data) != datalen:
            raise ProtocolReadError("Invalid datalen received.")
        return self.header_decode(data)

    def header_check(self, header):
        """Perform checks on header received from remote."""
        if self.VERSION != header["version"]:
            raise ProtocolError("protocol version mismatch.")
        if self.blocksize != header["blocksize"]:
            raise ProtocolError("blocksize mismatch.")
        if header["hash"] != "sha1": # TODO
            raise ProtocolError("hashing algorithm mismatch.")

    def block_hash(self, block):
        """Returns block hash in protocol format."""
        return block._hash.hexdigest() + "\n"
    
    def block_hash_read(self, f):
        """Read block hash from remote."""
        return self._readline(f)

    def block_hash_send(self, f, block):
        """Send block hash to remote."""
        if block:
            blockhash = self.block_hash(block)
        else:
            # Send invalid block hash to force retransmit.
            blockhash = "0"*40+"\n"
        self._write(f, block)
        return blockhash

    def block_encode(self, block):
        """Serialize block data."""
        return self._pack(self.BLOCK_PACK_FMT, 
            block.position, 
            len(block)) + block.data

    def block_read(self, f):
        """Read an actual data block from remote."""
        try:
            blockpos, blocksize = struct.unpack(self.BLOCK_PACK_FMT, 
                self._read(f, self._packlen(self.BLOCK_PACK_FMT)))
        except struct.error, e:
            raise ProtocolReadError("Invalid packed data: %s" % (e,))

        data = self._read(f, blocksize)
        if len(data) != blocksize:
            raise ProtocolReadError("Invalid datalen received.")
        return Block(blockpos, data)

    def block_send(self, f, block):
        """Sends a block of data to remote."""
        self._write(f, self.block_encode(block))

    @staticmethod
    def check_hash_len(hash):
        """Basically checks if len(hash) == 40+1."""
        if len(hash) != 40 + 1:
            raise ProtocolError("Invalid hash len!")

def read_ready(f, timeout=0.001):
    rfds, wfds, efds = select.select([f,],[],[], timeout)
    return f in rfds

if __name__ == "__main__":
    from optparse import OptionParser, SUPPRESS_HELP
    
    parser = OptionParser(
        usage="usage: %prog [options] /path/to/source host /path/to/dest")
    parser.add_option("-b", "--blocksize", dest="blocksize",
            action="store", type="int", help="block size [default %default]",
            default=DEFAULT_BLOCKSIZE)
    parser.add_option("--sender", dest="sender_mode",
            help=SUPPRESS_HELP,
            action="store_true", default=False)
    parser.add_option("-v", "--verbose", dest="verbose",
            help="Increase verbosity [default %default]",
            action="store_true", default="True")
    parser.add_option("-q", "--quiet", dest="verbose",
            help="Be quiet",
            action="store_false")
    parser.add_option("-u", "--user", dest="ssh_user",
            help="SSH username on remote host [default %default]",
            action="store", default="root")
    parser.add_option("-p", "--port", dest="ssh_port",
            help="SSH port [default %default]",
            action="store", type="int", default=22)

    (options, args) = parser.parse_args()

    if len(args) < 3:
        parser.error("Please read the manual!")

    remote_path = args[0]
    remote_host = args[1]
    local_path = args[2]

    if options.sender_mode:
        sys.stderr.write("Sender mode starting.\n")
        sys.stderr.flush()
        bdev = ReaderBlockDevice(remote_path)
        bdev.open()

        protocol = Protocol(bdev.blocksize, bdev.filesize, bdev.path)
        protocol.header_send(sys.stdout)

        # Main loop
        while True:
            block = bdev.read_next_block()
            if not block:
                # End of File
                break

            # Transmit block hash
            transmit_hash = protocol.block_hash_send(sys.stdout, block)

            # Check answer from remote
            received_hash = protocol.block_hash_read(sys.stdin)
            if received_hash != transmit_hash:
                protocol.block_send(sys.stdout, block)

        protocol._write(sys.stderr,
            "Remote Final hash: %s\n" % (bdev.get_hash(),))
        bdev.close()
    else:
        # Local mode
        if options.verbose:
            print "Connecting to %s:%s as %s" % (
                remote_host, options.ssh_port, options.ssh_user)

        remote_cmdlist = ["/usr/bin/python", "/home/ed/bdevsync.py",
               "--sender", "-q", 
               "-b", "%s" % (options.blocksize,),
               remote_path, remote_host, local_path]
        cmd = ["ssh", "-c", "blowfish",
                "-p", str(options.ssh_port),
                "%s@%s" % (options.ssh_user, remote_host),
                ' '.join(remote_cmdlist)
                ]

        ssh_pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=-1,
                shell=False)
        (remote_stdin, remote_stdout, remote_stderr) = (
                ssh_pipe.stdin, ssh_pipe.stdout, ssh_pipe.stderr)

        if read_ready(remote_stderr, 1.0):
            print "[%s]: %s" % (remote_host, remote_stderr.readline())
        if ssh_pipe.poll() is not None:
            print "Remote process crashed."
            sys.exit(0)

        sys.stderr.write("Writer mode.\n")
        sys.stderr.flush()

        bdev = WriterBlockDevice(local_path)
        bdev.open()

        if options.verbose:
            speedtransferthread = SpeedTransferThread(bdev)
            speedtransferthread.start()

        protocol = Protocol(bdev.blocksize, bdev.filesize, bdev.path)

        # Receive protocol header from remote
        remote_header = protocol.header_read(remote_stdout)
        print "Received header: %s" % (remote_header,)
        
        # Perform headers checks
        try:
            protocol.header_check(remote_header)
        except ProtocolError:
            sys.stderr.write("Protocol error!")
            sys.stderr.flush()
            bdev.close()
            raise

        # Truncate the local file, and set correct filesize
        # to match the other end.
        bdev.normalize_destination(remote_header["filesize"])

        # Main loop
        while True:
            # Reading remote stderr
            if read_ready(remote_stderr):
                sys.stderr.write("\n[%s]: %s" % (
                    remote_host, remote_stderr.readline()))
                sys.stderr.flush()

            # Check if remote is alive
            if ssh_pipe.poll() is not None:
                print "\nRemote process terminated."
                break

            block = bdev.read_next_block()
            if not block:
                # Do we reached EOF ?
                if bdef.check_eof():
                    break

            if options.verbose:
                sys.stdout.write("\r"+bdev.get_progress())
                sys.stdout.flush()

            remote_hash = protocol.block_hash_read(remote_stdout)
            protocol.check_hash_len(remote_hash)
            protocol.block_hash_send(remote_stdin, block)

            # We are waiting for the next block
            if transmit_hash != remote_hash:
                remote_block = protocol.block_read(remote_stdout)

                bdev.write_block(remote_block)
                bdev._update_hash(remote_block)
            elif block:
                bdev._update_hash(block)
        
        sys.stderr.write("\nLocal Final hash: %s\n" % (bdev.get_hash(),))
        bdev.close()

        if options.verbose:
            speedtransferthread.stop()
            speedtransferthread.join()

        if options.verbose:
            sys.stderr.write("Waiting for the other end to exit..\n")
            sys.stderr.flush()
            ssh_pipe.wait()