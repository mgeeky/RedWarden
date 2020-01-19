#!/usr/bin/python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod

class IProxyPlugin(ABC):
    def __init__(self, logger, proxyOptions):
        super().__init__()

    @staticmethod
    @abstractmethod
    def get_name():
        return 'IProxyPlugin'

    @staticmethod
    @abstractmethod
    def help(parser):
    	pass

    @abstractmethod
    def request_handler(self, req, req_body):
    	pass

    @abstractmethod
    def response_handler(self, req, req_body, res, res_body):
    	pass
