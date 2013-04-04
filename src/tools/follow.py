#!/usr/bin/env python
##############################################################################
# follow.py                                                                  #
#                                                                            #
# This file implements a demo program that just follows a stream of          #
# file-level objects from a cloud-inotify stream.  It is similar to the demo #
# listed in the gammaray paper.                                              #
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

    if '*' in filter_string:
        pubsub.psubscribe(filter_string)
    else:
        pubsub.subscribe(filter_string)

    for m in pubsub.listen():
        print "\n\n-------------------\nMessage on Channel: %s" % (m['channel'])
        m = bson.loads(m['data'])
        for k,v in sorted(m.items()):
            print '\t%.6s\t\t:\t' % k,
            try:
                print int(v)
            except:
                print v
