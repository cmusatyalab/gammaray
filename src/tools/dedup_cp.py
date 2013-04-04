#!/usr/bin/env python
##############################################################################
# dedup_cp.py                                                                #
#                                                                            #
# This file implements a deduplicated version of copy which reduces write    #
# bandwidth necessary to copy a file.  It is especially useful for large     #
# files.                                                                     #
#                                                                            #
#                                                                            #
#   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                              #
#                                                                            #
#                                                                            #
#   Copyright 2013 Carnegie Mellon University                                #
#                                                                            #
#   Licensed under the Apache License, Version 2.0 (the "License");          #
#   you may not use this file except in compliance with the License.         #
#   You may obtain a copy of the License at                                  #
#                                                                            #
#       http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                            #
#   Unless required by applicable law or agreed to in writing, software      #
#   distributed under the License is distributed on an "AS IS" BASIS,        #
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. #
#   See the License for the specific language governing permissions and      #
#   limitations under the License.                                           #
##############################################################################


from hashlib import sha256
from optparse import OptionParser

CHUNK_SIZE = 4096
HASHER = sha256
HASH_SIZE = 32
USAGE = 'usage: %prog [options] source_file destination_file \
checksum file'
VERSION = '0.0'

def compute_checksums(checksum_fname, source_fname):
    counter = 0

    with open(source_fname, 'r') as sourcef:
        with open(checksum_fname, 'w') as checkf:
            chunk = sourcef.read(CHUNK_SIZE)
            while chunk:
                counter += 1
                checkf.write(HASHER(chunk).digest())
                chunk = sourcef.read(CHUNK_SIZE)
    return counter

def synchronize(source_fname, dest_fname, checksums_fname):
    counter = 0
    modified = 0

    with open(source_fname, 'r') as sourcef:
        with open(checksums_fname, 'r') as checkf:
            with open(dest_fname, 'r+') as destf:
                chunk = destf.read(CHUNK_SIZE)

                while chunk:
                    old_digest = checkf.read(HASH_SIZE)

                    if old_digest != HASHER(chunk).digest():
                        destf.seek(counter * CHUNK_SIZE)
                        sourcef.seek(counter * CHUNK_SIZE)
                        chunk = sourcef.read(CHUNK_SIZE)
                        destf.write(chunk)
                        modified += 1
                    counter += 1
                    chunk = destf.read(CHUNK_SIZE)
    return modified

if __name__ == '__main__':
    parser = OptionParser(usage=USAGE, version=VERSION)
    parser.add_option("-c", "--compute-checksums",
                      help="write checksums to FILE", dest="checksum_file",
                      metavar="FILE")
    (options, args) = parser.parse_args()

    print '-- DEDUP CP %s --' % VERSION

    if (options.checksum_file):
        print '\tComputing checksums for file: %s' % args[0]
        chunks = compute_checksums(options.checksum_file, args[0])
        print '\tComputed checksums for %d chunks' % chunks
    elif len(args) == 3:
        print '\tSynchronizing files %s --> %s' % (args[0], args[1])
        print '\twith checksum file %s' % args[2]
        chunks = synchronize(args[0], args[1], args[2])
        print '\tSynchronized %d different chunks.' % chunks
    else:
        parser.error("incorrect number of arguments")
