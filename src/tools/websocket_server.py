#!/usr/bin/env python

from tornado import web, ioloop
from sockjs.tornado import SockJSRouter, SockJSConnection

class EchoConnection(SockJSConnection):
    def on_message(self, msg):
        print 'incoming message: %s' % msg
        if '*' in msg:
            nums = msg.strip().split('*')
            msg = str(int(nums[0]) * int(nums[1]))
        self.send({'test':29})
        self.send(msg)

if __name__ == '__main__':
    EchoRouter = SockJSRouter(EchoConnection, '/echo')
    app = web.Application(EchoRouter.urls)
    app.listen(9999)
    ioloop.IOLoop.instance().start()
