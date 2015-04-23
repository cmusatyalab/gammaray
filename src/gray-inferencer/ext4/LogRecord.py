#!/usr/bin/env python
# vim:set nospell:

from bson import loads
from struct import unpack

class LogRecord(object):
	def __init__(self, data):
		self.timestamp = data[0:13]
		self.__dict__.update(loads(data[13:]))
		self.serialized_length = 13 + unpack('i', data[13:17])[0]

	def __str__(self):
		retstr = '{\n'
		for k,v in self.__dict__.iteritems():
			if k == 'write': retstr += '\t"write" : BINARY,\n'
			else: retstr += '\t"%s" : "%s",\n' % (k, v)
		if self.type == 'data': retstr += '\t"writelen" : "%d",\n' % len(self.write)
		retstr += '}\n'
		return retstr

        @staticmethod
        def LogRecordGenerator(data):
            while data != '':
                    lr = LogRecord(data)
                    yield(lr)
                    data = data[lr.serialized_length:]

if __name__ == '__main__':
    print('This is a library and not meant to be executed directly.')
