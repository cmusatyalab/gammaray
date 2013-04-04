#!/usr/bin/env python
##############################################################################
# bson_reader.py                                                             #
#                                                                            #
# This file can read a file with multiple BSON documents packed inside it, or#
# technically a stream of BSON documents from a file-like object.            #
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




import bson
import struct
import sys

USAGE='Usage: %s <BSON file>'
UINT32_T='=I'

# Magic function loading packed BSON documents from a file
def bson_yielder(fname):
    f = open(fname, 'rb')
    try:
        while True:
            buf = ''
            buf += f.read(4)
            doc_size, = struct.unpack(UINT32_T, buf)
            buf += f.read(doc_size - 4)
            yield bson.loads(buf)
    except:
        raise StopIteration()



if __name__ == '__main__':
    print 'BSON Python Reader Demo -- By: Wolfgang Richter <wolf@cs.cmu.edu>'

    if (len(sys.argv) != 2):
        print USAGE % sys.argv[0]

    print 'Analyzing BSON file: %s' % sys.argv[1]

    for document in bson_yielder(sys.argv[1]):
        if 'path' in document:
            print (document['path']).encode("utf-8")
