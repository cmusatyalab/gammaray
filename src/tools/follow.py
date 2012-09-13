#!/usr/bin/env python

import sys
import bson
import redis

if __name__ == '__main__':

    if len(sys.argv) < 3:
        print 'Usage: %s <xray server> <HOST:VMNAME:PATH filter>' % sys.argv[0]
        exit(-1)

    server = sys.argv[1]
    filter_string = sys.argv[2]

    print 'Connecting to server \'%s\' with filter \'%s\'' % (server,
                                                              filter_string)

    r = redis.Redis(host='localhost', port=6379, db=4)
    pubsub = r.pubsub()

    pubsub.psubscribe(filter_string)

    for m in pubsub.listen():
        print "Message on Channel: %s" % (m['channel'])
        m = bson.loads(m['data'])
        for k,v in m.items():
            print '\t%.6s\t\t:\t' % k,
            try:
                print int(v)
            except:
                print v
