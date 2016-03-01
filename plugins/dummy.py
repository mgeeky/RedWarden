#!/usr/bin/python

# Dummy plugin presenting necessary structure of 
# a proxy2 plugin to be loaded correctly.

class ProxyHandler:

	def __init__(self):
		print 'hello world from __init__ in ProxyHandler'

	def request_handler(self, req, req_body):
		print 'hello world from request_handler! Req: "%s"' % req.path

	def response_handler(self, req, req_body, res, res_body):
		print 'hello world from response_handler! Req: "%s"' % req.path