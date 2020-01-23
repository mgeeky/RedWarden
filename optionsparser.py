#!/usr/bin/python

import os, sys
from pluginsloader import PluginsLoader
from proxylogger import ProxyLogger
from argparse import ArgumentParser


def parse_options(opts, version):

    usage = "Usage: %%prog [options]"
    parser = ArgumentParser(usage=usage, prog="%prog " + version)

    # General options
    parser.add_argument("-v", "--verbose", dest='verbose',
        help="Displays verbose output.", action="store_true")
    parser.add_argument("-V", "--trace", dest='trace',
        help="Displays HTTP requests and responses.", action="store_true")
    parser.add_argument("-d", "--debug", dest='debug',
        help="Displays debugging informations (implies verbose output).", action="store_true")
    parser.add_argument("-s", "--silent", dest='silent',
        help="Surpresses all of the output logging.", action="store_true")
    parser.add_argument("-w", "--output", dest='log',
        help="Specifies output log file.", metavar="PATH", type=str)
    parser.add_argument("-H", "--hostname", dest='hostname', metavar='NAME',
        help="Specifies proxy's binding hostname along with protocol to serve (http/https). If scheme is specified here, don't add another scheme specification to the listening port number (123/https). Default: "+ opts['hostname'] +".", 
        type=str, default=opts['hostname'])
    parser.add_argument("-P", "--port", dest='port', metavar='NUM',
        help="Specifies proxy's binding port number(s). A value can be followed with either '/http' or '/https' to specify which type of server to bound on this port. Supports multiple binding ports by repeating this option: '--port 80 --port 443/https'. Default: "+ str(opts['port'][0]) +".", 
        type=str, action="append", default = [])
    parser.add_argument("-t", "--timeout", dest='timeout', metavar='SECS',
        help="Specifies timeout for proxy's response in seconds. Default: "+ str(opts['timeout']) +".", 
        type=int, default=opts['timeout'])
    parser.add_argument("-u", "--proxy-url", dest='proxy_self_url', metavar='URL',
        help="Specifies proxy's self url. Default: "+ opts['proxy_self_url'] +".", 
        type=str, default=opts['proxy_self_url'])
    

    # SSL Interception
    sslgroup = parser.add_argument_group("SSL Interception setup")
    sslgroup.add_argument("-S", "--no-ssl-mitm", dest='no_ssl',
        help="Turns off SSL interception/MITM and falls back on straight forwarding.", action="store_true")
    sslgroup.add_argument('--ssl-certdir', dest='certdir', metavar='DIR',
        help='Sets the destination for all of the SSL-related files, including keys, certificates (self and of'\
            ' the visited websites). If not specified, a default value will be used to create a directory and remove it upon script termination. Default: "'+ opts['certdir'] +'"', default=opts['certdir'])
    sslgroup.add_argument('--ssl-cakey', dest='cakey', metavar='NAME',
        help='Sets the name of a CA key file\'s name. Default: "'+ opts['cakey'] +'"', default=opts['cakey'])
    sslgroup.add_argument('--ssl-cacert', dest='cacert', metavar='NAME',
        help='Sets the name of a CA certificate file\'s name. Default: "'+ opts['cacert'] +'"', default=opts['cacert'])
    sslgroup.add_argument('--ssl-certkey', dest='certkey', metavar='NAME', 
        help='Sets the name of a CA certificate key\'s file name. Default: "'+ opts['certkey'] +'"', default=opts['certkey'])
    sslgroup.add_argument('--ssl-cacn', dest='cacn', metavar='CN', 
        help='Sets the common name of the proxy\'s CA authority. Default: "'+ opts['cacn'] +'"', default=opts['cacn'])

    # Plugins handling
    plugins = parser.add_argument_group("Plugins handling")
    plugins.add_argument('-L', '--list-plugins', action='store_true', help='List available plugins.')
    plugins.add_argument('-p', '--plugin', dest='plugin', action='append', metavar='PATH', type=str,
                        help="Specifies plugin's path to be loaded.")

    feed_with_plugin_options(opts, parser)

    params = parser.parse_args()
    opts.update(vars(params))

    if params.list_plugins:
        files = sorted([f for f in os.scandir(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'plugins/'))], key = lambda f: f.name)
        for _, entry in enumerate(files):
            if entry.name.endswith(".py") and entry.is_file() and entry.name.lower() not in ['iproxyplugin.py', '__init__.py']:
                print('[+] Plugin: {}'.format(entry.name))

        sys.exit(0)

    if params.plugin:
        for i, opt in enumerate(params.plugin):
            decomposed = PluginsLoader.decompose_path(opt)
            if not os.path.isfile(decomposed['path']):
                opt = opt.replace('.py', '')
                opt2 = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'plugins/{}.py'.format(opt)))
                if not os.path.isfile(opt2):
                    raise Exception('Specified plugin: "%s" does not exist.' % decomposed['path'])
                else:
                    opt = opt2
            
            opts['plugins'].add(opt)

    #if params.debug:
    #   opts['trace'] = True

    if params.silent and params.log:
        parser.error("Options -s and -w are mutually exclusive.")

    if params.silent:
        opts['log'] = 'none'
    elif params.log and len(params.log) > 0:
        try:
            with open(params.log, 'w') as f:
                pass
            opts['log'] = params.log
        except Exception as e:
            raise Exception('[ERROR] Failed to open log file for writing. Error: "%s"' % e)
    else:
        opts['log'] = sys.stdout

    if opts['log'] and opts['log'] != sys.stdout: opts['log'] = os.path.normpath(opts['log'])
    if opts['cakey']: opts['cakey'] = os.path.normpath(opts['cakey'])
    if opts['certdir']: opts['certdir'] = os.path.normpath(opts['certdir'])
    if opts['certkey']: opts['certkey'] = os.path.normpath(opts['certkey'])

def feed_with_plugin_options(opts, parser):
    logger = ProxyLogger()
    plugins = []
    files = sorted([f for f in os.scandir(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'plugins/'))], key = lambda f: f.name)
    for _, entry in enumerate(files):
        if entry.name.endswith(".py") and entry.is_file() and entry.name.lower() not in ['iproxyplugin.py', '__init__.py']:
            plugins.append(entry.path)

    options = opts.copy()
    options['plugins'] = plugins

    plugin_own_options = {}

    pl = PluginsLoader(logger, options, False)
    for name, plugin in pl.get_plugins().items():
        logger.dbg("Fetching plugin {} options.".format(name))
        if hasattr(plugin, 'help'):
            plugin_options = parser.add_argument_group("Plugin '{}' options".format(plugin.get_name()))

            help = getattr(plugin, 'help')
            help(plugin_options)
