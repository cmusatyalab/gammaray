#!/usr/bin/env python

import sys
import bson
import zmq

if __name__ == '__main__':

    if len(sys.argv) < 3:
        print 'Usage: %s <xray server> <HOST:VMNAME:PATH filter>' % sys.argv[0]
        exit(-1)

    server = sys.argv[1]
    filter_string = sys.argv[2]

    context= zmq.Context(1)
    socket = context.socket(zmq.SUB)

    socket.connect('tcp://%s:13738' % server)
    socket.setsockopt(zmq.SUBSCRIBE, filter_string)
    while (1):
        msg = socket.recv()[len(filter_string):]
        deserialized = bson.loads(msg)
        print deserialized['type']
        print deserialized['start_byte']
        print deserialized['end_byte']

    context.term()
