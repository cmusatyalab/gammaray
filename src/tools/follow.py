#!/usr/bin/env python

import sys
import bson
import zmq

PORT=13738

if __name__ == '__main__':

    if len(sys.argv) < 3:
        print 'Usage: %s <xray server> <HOST:VMNAME:PATH filter>' % sys.argv[0]
        exit(-1)

    server = sys.argv[1]
    filter_string = sys.argv[2]

    print 'Connecting to server \'%s\' with filter \'%s\'' % (server,
                                                              filter_string)

    context= zmq.Context(1)
    socket = context.socket(zmq.SUB)

    socket.connect('tcp://%s:%d' % (server, PORT))
    socket.setsockopt(zmq.SUBSCRIBE, filter_string)

    while (1):
        msg = socket.recv()
        channel = msg[:msg.find('\x00')]

        print 'New Message Received for: %s' % channel

        if channel != filter_string:
            continue

        msg = msg[msg.find('\x00') + 1:]
        deserialized = bson.loads(msg)

        for k in deserialized:
            if k != 'data':
                print '\t%10s : ' % (k),
                print '\t\'%s\'' % str(deserialized[k])
            else:
                print 'Received binary data.\n'

        print ''

    context.term()
