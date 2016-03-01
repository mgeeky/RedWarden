#!/usr/bin/python

import os, sys
from optparse import OptionParser, OptionGroup

def parse_options(options, version):

    usage = "Usage: %prog [options]"
    parser = OptionParser(usage=usage, version="%prog " + version)

    # General options
    parser.add_option(  "-v", "--verbose", dest='trace',
        help="Displays verbose output along with packets' contents dumping/tracing.", action="store_true")
    parser.add_option(  "-d", "--debug", dest='debug',
        help="Displays debugging informations (implies verbose output).", action="store_true")
    parser.add_option(  "-s", "--silent", dest='silent',
        help="Surpresses all of the output logging.", action="store_true")
    parser.add_option(  "-w", "--output", dest='log',
        help="Specifies output log file.", metavar="PATH", type="string")
    parser.add_option(  "-H", "--hostname", dest='hostname', metavar='NAME',
        help="Specifies proxy's binding hostname. Default: "+ options['hostname'] +".", 
        type='string', default=options['hostname'])
    parser.add_option(  "-P", "--port", dest='port', metavar='NUM',
        help="Specifies proxy's binding port number. Default: "+ str(options['port']) +".", 
        type='int', default=options['port'])
    parser.add_option(  "-t", "--timeout", dest='timeout', metavar='SECS',
        help="Specifies timeout for proxy's response in seconds. Default: "+ str(options['timeout']) +".", 
        type='int', default=options['timeout'])
    parser.add_option(  "-u", "--proxy-url", dest='proxy_self_url', metavar='URL',
        help="Specifies proxy's self url. Default: "+ options['proxy_self_url'] +".", 
        type='string', default=options['proxy_self_url'])
    

    # SSL Interception
    sslgroup = OptionGroup(parser, "SSL Interception setup")
    parser.add_option(  "-S", "--no-ssl", dest='no_ssl',
        help="Turns off SSL interception routines and falls back on relaying.", action="store_true")
    sslgroup.add_option('', '--ssl-certdir', dest='certdir', metavar='DIR',
        help='Sets the destination for all of the SSL-related files, including keys, certificates (self and of'\
            ' the visited websites). Default: "'+ options['certdir'] +'"', default=options['certdir'])
    sslgroup.add_option('', '--ssl-cakey', dest='cakey', metavar='NAME',
        help='Sets the name of a CA key file\'s name. Default: "'+ options['cakey'] +'"', default=options['cakey'])
    sslgroup.add_option('', '--ssl-cacert', dest='cacert', metavar='NAME',
        help='Sets the name of a CA certificate file\'s name. Default: "'+ options['cacert'] +'"', default=options['cacert'])
    sslgroup.add_option('', '--ssl-certkey', dest='certkey', metavar='NAME', 
        help='Sets the name of a CA certificate key\'s file name. Default: "'+ options['certkey'] +'"', default=options['certkey'])
    sslgroup.add_option('', '--ssl-cacn', dest='cacn', metavar='CN', 
        help='Sets the common name of the proxy\'s CA authority. Default: "'+ options['cacn'] +'"', default=options['cacn'])

    parser.add_option_group(sslgroup)

    # Plugins handling
    plugins = OptionGroup(parser, "Plugins handling")
    plugins.add_option('-p', '--plugin', dest='plugin', action='append', metavar='PATH', type='string',
                        help="Specifies plugin's path to be loaded. Every plugin's module must implement class `"\
                        "%s' and respectively: `request_handler' and `response_handler' class methods that will get called." \
                        "One can find example of such plugin in plugins/dummy.py."
                        % options['plugin_class_name'])

    parser.add_option_group(plugins)

    (params, args) = parser.parse_args()
    options.update(vars(params))

    if params.plugin:
        for i, opt in enumerate(params.plugin):
            if not os.path.isfile(opt):
                logger.err('Specified plugin: "%s" does not exist.' % opt)
            else:
                options['plugins'].add(opt)

    if params.debug:
        options['trace'] = True

    if params.silent and params.log:
        parser.error("Options -s and -w are mutually exclusive.")

    if params.silent:
        options['log'] = 'none'
    elif params.log and len(params.log) > 0:
        try:
            options['log'] = open(params.log, 'w')
        except Exception as e:
            raise '[ERROR] Failed to open log file for writing. Error: "%s"' % e
    else:
        options['log'] = sys.stdout
