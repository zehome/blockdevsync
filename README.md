Block device synchronizer
=========================

Simple program to help synchronize a block device from a system to another.
For example you can sync only differences from a LVM snapshot to a file
on a backup server.

Usage
-----

TODO!

Theory of operation
-------------------
Launch bdevsync.py on a node.

 1. Read local file filesize, and perform basic checks.
 2. Connect to remote node and launch bdevsync.py in --sender mode.
 3. Sender check remote file, and send header data (Protocol version, filesize, ...)
 4. Local node performs checks on header.
 5. Truncate local file to match remote file.
 6. Compare 4MiB blocks of data using sha1 hash.
 7. Transfer block data if hash do not match.
 8. End.

Author and licence
------------------
Licenced as BSD software licence, by Laurent Coustet (c) 2012.

http://ed.zehome.com/
http://github.com/zehome/