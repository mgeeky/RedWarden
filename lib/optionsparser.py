#!/usr/bin/python

import yaml
import os, sys
from lib.pluginsloader import PluginsLoader
from lib.proxylogger import ProxyLogger
from argparse import ArgumentParser

ProxyOptionsDefaultValues = {
}

ImpliedParams = {
    'plugin' : ['malleable_redirector',],
}

def parse_options(opts, version):

    global ProxyOptionsDefaultValues
    ProxyOptionsDefaultValues.update(opts)

    usage = "Usage: %%prog [options]"
    parser = ArgumentParser(usage=usage, prog="%prog " + version)

    parser.add_argument("-c", "--config", dest='config',
        help="External configuration file. Defines values for below options, however specifying them on command line will supersed ones from file.")

    # General options
    parser.add_argument("-v", "--verbose", dest='verbose',
        help="Displays verbose output.", action="store_true")
    parser.add_argument("-d", "--debug", dest='debug',
        help="Displays debugging informations (implies verbose output).", action="store_true")
    parser.add_argument("-s", "--silent", dest='silent',
        help="Surpresses all of the output logging.", action="store_true")
    parser.add_argument("-z", "--allow-invalid", dest='allow_invalid',
        help="Process invalid HTTP requests. By default if a stream not resembling HTTP protocol reaches RedWarden listener - it will be dropped.", action="store_true")
    parser.add_argument("-N", "--no-proxy", dest='no_proxy',
        help="Disable standard HTTP/HTTPS proxy capability (will not serve CONNECT requests). Useful when we only need plugin to run.", action="store_true")
    parser.add_argument("-W", "--tee", dest='tee',
        help="While logging to output file, print to stdout also.", action="store_true")
    parser.add_argument("-w", "--output", dest='log', 
        help="Specifies output log file.", metavar="PATH", type=str)
    parser.add_argument("-A", "--access-log", dest='access_log', 
        help="Specifies where to write access attempts in Apache2 combined log format.", metavar="PATH", type=str)
    parser.add_argument("-B", "--bind", dest='bind', metavar='NAME',
        help="Specifies proxy's binding address along with protocol to serve (http/https). If scheme is specified here, don't add another scheme specification to the listening port number (123/https). Default: "+ opts['bind'] +".", 
        type=str, default=opts['bind'])
    parser.add_argument("-P", "--port", dest='port', metavar='NUM',
        help="Specifies proxy's binding port number(s). A value can be followed with either '/http' or '/https' to specify which type of server to bound on this port. Supports multiple binding ports by repeating this option: '--port 80 --port 443/https'. The port specification may also override globally used --bind address by preceding it with address and colon (--port 127.0.0.1:80/http). Default: "+ str(opts['port'][0]) +".", 
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
        help='Specifies this proxy server\'s (CA) certificate private key. Default: "'+ opts['cakey'] +'"', default=opts['cakey'])
    sslgroup.add_argument('--ssl-cacert', dest='cacert', metavar='NAME',
        help='Specifies this proxy server\'s (CA) certificate. Default: "'+ opts['cacert'] +'"', default=opts['cacert'])
    sslgroup.add_argument('--ssl-certkey', dest='certkey', metavar='NAME', 
        help='Specifies CA certificate\'s public key. Default: "'+ opts['certkey'] +'"', default=opts['certkey'])
    sslgroup.add_argument('--ssl-cacn', dest='cacn', metavar='CN', 
        help='Sets the common name of the proxy\'s CA authority. If this option is not set, will use --hostname instead. It is required only when no --ssl-cakey/cert were specified and RedWarden will need to generate ones automatically. Default: "'+ opts['cacn'] +'"', default=opts['cacn'])

    # Plugins handling
    plugins = parser.add_argument_group("Plugins handling")
    plugins.add_argument('-L', '--list-plugins', action='store_true', help='List available plugins.')
    plugins.add_argument('-p', '--plugin', dest='plugin', action='append', metavar='PATH', type=str,
                        help="Specifies plugin's path to be loaded.")

    feed_with_plugin_options(opts, parser)

    params = parser.parse_args()

    for k, v in ImpliedParams.items():
        setattr(params, k, v)

    if hasattr(params, 'config') and params.config != '':
        try:
            params = parseParametersFromConfigFile(params)
        except Exception as e:
            parser.error(str(e))

        opts.update(params)
    else:
        opts.update(vars(params))

    if opts['list_plugins']:
        files = sorted([f for f in os.scandir(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../plugins/'))], key = lambda f: f.name)
        for _, entry in enumerate(files):
            if entry.name.endswith(".py") and entry.is_file() and entry.name.lower() not in ['iproxyplugin.py', '__init__.py']:
                print('[+] Plugin: {}'.format(entry.name))

        sys.exit(0)

    if opts['plugin'] != None and len(opts['plugin']) > 0:
        for i, opt in enumerate(opts['plugin']):
            decomposed = PluginsLoader.decompose_path(opt)
            if not os.path.isfile(decomposed['path']):
                opt = opt.replace('.py', '')
                opt2 = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../plugins/{}.py'.format(opt)))
                if not os.path.isfile(opt2):
                    raise Exception('Specified plugin: "%s" does not exist.' % decomposed['path'])
                else:
                    opt = opt2
            
            opts['plugins'].add(opt)

    if opts['silent'] and opts['log']:
        parser.error("Options -s and -w are mutually exclusive.")

    if opts['silent']:
        opts['log'] = 'none'
    elif opts['log'] and len(opts['log']) > 0:
        try:
            if not os.path.isfile(opts['log']):
                with open(opts['log'], 'w') as f:
                    pass
            opts['log'] = opts['log']

        except Exception as e:
            raise Exception('[ERROR] Failed to open log file for writing. Error: "%s"' % e)
    else:
        opts['log'] = sys.stdout

    if opts['log'] and opts['log'] != sys.stdout: opts['log'] = os.path.normpath(opts['log'])
    if opts['cakey']: opts['cakey'] = os.path.normpath(opts['cakey'])
    if opts['certdir']: opts['certdir'] = os.path.normpath(opts['certdir'])
    if opts['certkey']: opts['certkey'] = os.path.normpath(opts['certkey'])

def parseParametersFromConfigFile(_params):
    parametersRequiringDirectPath = (
        'log',
        'output',
        'access_log',
        'certdir',
        'certkey',
        'cakey',
        'cacert',
        'ssl_certdir',
        'ssl_certkey',
        'ssl_cakey',
        'ssl_cacert',
    )

    translateParamNames = {
        'output' : 'log',
        'proxy_url' : 'proxy_self_url',
        'no_ssl_mitm' : 'no_ssl',
        'ssl_certdir' : 'certdir',
        'ssl_certkey' : 'certkey',
        'ssl_cakey' : 'cakey',
        'ssl_cacert' : 'cacert',
        'ssl_cacn' : 'cacn',
        'drop_invalid_http_requests': 'allow_invalid',
    }

    valuesThatNeedsToBeList = (
        'port',
        'plugin',
    )

    outparams = vars(_params)
    config = {}
    configBasePath = ''

    if outparams['config'] != None and len(outparams['config']) > 0:
        if not 'config' in outparams.keys() or not os.path.isfile(outparams['config']):
            raise Exception(f'RedWarden config file not found: ({outparams["config"]}) or --config not specified!') 
    else:
        return outparams

    try:
        with open(outparams['config']) as f:
            try:
                config = yaml.load(f, Loader=yaml.FullLoader)
            except:
                config = yaml.load(f)

        outparams.update(config)

        for val in valuesThatNeedsToBeList:
            if val in outparams.keys() and val in config.keys():
                if type(config[val]) == str:
                    outparams[val] = [config[val], ]
                else:
                    outparams[val] = config[val]

        for k, v in ProxyOptionsDefaultValues.items():
            if k not in outparams.keys():
                outparams[k] = v

        for k, v in translateParamNames.items():
            if k in outparams.keys():
                outparams[v] = outparams[k]
            if v in outparams.keys():
                outparams[k] = outparams[v]

        configBasePath = os.path.dirname(os.path.abspath(outparams['config']))

        for paramName in parametersRequiringDirectPath:
            if paramName in outparams.keys() and \
                outparams[paramName] != '' and outparams[paramName] != None:
                outparams[paramName] = os.path.join(configBasePath, outparams[paramName])

        return outparams

    except FileNotFoundError as e:
        raise Exception(f'RedWarden config file not found: ({outparams["config"]})!')

    except Exception as e:
        raise Exception(f'Unhandled exception occured while parsing RedWarden config file: {e}')

    return outparams

def feed_with_plugin_options(opts, parser):
    logger = ProxyLogger()
    plugins = []
    files = sorted([f for f in os.scandir(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../plugins/'))], key = lambda f: f.name)
    for _, entry in enumerate(files):
        if entry.name.endswith(".py") and entry.is_file() and entry.name.lower() not in ['iproxyplugin.py', '__init__.py']:
            plugins.append(entry.path)

    options = opts.copy()
    options['plugins'] = plugins
    options['verbose'] = True
    options['debug'] = False

    plugin_own_options = {}

    pl = PluginsLoader(logger, options)
    for name, plugin in pl.get_plugins().items():
        logger.dbg("Fetching plugin {} options.".format(name))
        if hasattr(plugin, 'help'):
            plugin_options = parser.add_argument_group("Plugin '{}' options".format(plugin.get_name()))
            plugin.help(plugin_options)
