#!/usr/bin/env python

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
