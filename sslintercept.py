#!/usr/bin/python3

import shutil
import os
from subprocess import Popen, PIPE

class SSLInterception:

    def __init__(self, logger, options):
        self.logger = logger
        self.options = options
        self.status = False

        if not options['no_ssl']:
            self.setup()

    def setup(self):
        def _setup(self):
            self.logger.dbg('Setting up SSL interception certificates')

            if not os.path.isabs(self.options['certdir']):
                self.logger.dbg('Certificate directory path was not absolute. Assuming relative to current programs\'s directory')
                path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.options['certdir'])
                self.options['certdir'] = path
                self.logger.dbg('Using path: "%s"' % self.options['certdir'])

            # Step 1: Create directory for certificates and asynchronous encryption keys
            if not os.path.isdir(self.options['certdir']):
                try:
                    self.logger.dbg("Creating directory for certificate: '%s'" % self.options['certdir'])
                    os.mkdir(self.options['certdir'])
                except Exception as e:
                    self.logger.err("Couldn't make directory for certificates: '%s'" % e)
                    return False

            # Step 2: Create CA key
            if not self.options['cakey']:
                self.options['cakey'] = os.path.join(self.options['certdir'], 'ca.key')

                if not os.path.isdir(self.options['cakey']):
                    self.logger.dbg("Creating CA key file: '%s'" % self.options['cakey'])
                    p = Popen(["openssl", "genrsa", "-out", self.options['cakey'], "2048"], stdout=PIPE, stderr=PIPE)
                    (out, error) = p.communicate()
                    self.logger.dbg(out + error)
                    
                    if not self.options['cakey']:
                        self.logger.err('Creating of CA key process has failed.')
                        return False
            else:
                self.logger.info('Using provided CA key file: {}'.format(self.options['cakey']))

            # Step 3: Create CA certificate
            if not self.options['cacert']:
                self.options['cacert'] = os.path.join(self.options['certdir'], 'ca.crt')

                if not os.path.isdir(self.options['cacert']):
                    self.logger.dbg("Creating CA certificate file: '%s'" % self.options['cacert'])
                    p = Popen(["openssl", "req", "-new", "-x509", "-days", "3650", "-key", self.options['cakey'], "-out", self.options['cacert'], "-subj", "/CN="+self.options['cacn']], stdout=PIPE, stderr=PIPE)
                    (out, error) = p.communicate()
                    self.logger.dbg(out + error)

                    if not self.options['cacert']:
                        self.logger.err('Creating of CA certificate process has failed.')
                        return False
            else:
                self.logger.info('Using provided CA certificate file: {}'.format(self.options['cacert']))

            # Step 4: Create certificate key file
            if not self.options['certkey']:
                self.options['certkey'] = os.path.join(self.options['certdir'], 'cert.key')

                if not os.path.isdir(self.options['certkey']):
                    self.logger.dbg("Creating Certificate key file: '%s'" % self.options['certkey'])
                    self.logger.dbg("Creating CA key file: '%s'" % self.options['cakey'])
                    p = Popen(["openssl", "genrsa", "-out", self.options['certkey'], "2048"], stdout=PIPE, stderr=PIPE)
                    (out, error) = p.communicate()
                    self.logger.dbg(out + error)

                    if not self.options['certkey']:
                        self.logger.err('Creating of Certificate key process has failed.')
                        return False
            else:
                self.logger.info('Using provided Certificate key: {}'.format(self.options['certkey']))

            self.logger.dbg('SSL interception has been setup.')
            return True

        self.logger.info('Preparing SSL certificates and keys for https traffic interception...')
        self.status = _setup(self)
        return self.status


    def cleanup(self):
        if not self.status:
            return 
            
        try:
            shutil.rmtree(self.options['certdir'])
            self.logger.dbg('SSL interception files cleaned up.')
        except Exception as e:
            self.logger.err("Couldn't perform SSL interception files cleaning: '%s'" % e)

    def __str__(self):
        return 'SSL %sbeing intercepted.' % ('NOT ' if not self.status else '')