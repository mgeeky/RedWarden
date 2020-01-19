#!/usr/bin/python3
import os
import sys
import inspect
from io import StringIO
from proxylogger import ProxyLogger
import csv

#
# Plugin that attempts to load all of the supplied plugins from 
# program launch options.
class PluginsLoader:   
    class InjectedLogger(ProxyLogger):
        def __init__(self, name, options = None):
            self.name = name
            super().__init__(options)

        def _text(self, txt):
            return '[{}] {}'.format(self.name, txt)

        # Info shall be used as an ordinary logging facility, for every desired output.
        def info(self, txt, forced = False, **kwargs):
            super().info(self._text(txt), forced, **kwargs)

        # Trace by default does not uses [TRACE] prefix. Shall be used
        # for dumping packets, headers, metadata and longer technical output.
        def trace(self, txt, **kwargs):
            super().trace(self._text(txt), **kwargs)

        def dbg(self, txt, **kwargs):
            super().dbg(self._text(txt), **kwargs)

        def err(self, txt, **kwargs):
            super().err(self._text(txt), **kwargs)

        def fatal(self, txt, **kwargs):
            super().fatal(self._text(txt), **kwargs)

    def __init__(self, logger, options, instantiate = True):
        self.options = options
        self.plugins = {}
        self.called = False
        self.logger = logger
        self.instantiate = instantiate
        plugins_count = len(self.options['plugins'])

        if plugins_count > 0:
            self.logger.info('Loading %d plugin%s...' % (plugins_count, '' if plugins_count == 1 else 's'))
            
            for plugin in self.options['plugins']:
                self.load(plugin)

        self.called = True
        
    # Output format:
    #   plugins = {'plugin1': instance, 'plugin2': instance, ...}
    def get_plugins(self):
        return self.plugins

    #
    # Following function parses input plugin path with parameters and decomposes
    # them to extract plugin's arguments along with it's path.
    # For instance, having such string:
    #   -p "plugins/my_plugin.py",argument1="test",argument2,argument3=test2
    #
    # It will return:
    #   {'path':'plugins/my_plugin.py', 'argument1':'t,e,s,t', 'argument2':'', 'argument3':'test2'}
    #
    @staticmethod
    def decompose_path(p):
        decomposed = {}
        f = StringIO(p)
        rows = list(csv.reader(f, quoting=csv.QUOTE_ALL, skipinitialspace=True))

        for i in range(len(rows[0])):
            row = rows[0][i]
            if i == 0:
                decomposed['path'] = row
                continue

            if '=' in row:
                s = row.split('=')
                decomposed[s[0]] = s[1].replace('"', '')
            else:
                decomposed[row] = ''

        return decomposed


    def load(self, path):
        instance = None

        self.logger.dbg('Plugin string: "%s"' % path)
        decomposed = PluginsLoader.decompose_path(path)
        self.logger.dbg('Decomposed as: %s' % str(decomposed))

        plugin = decomposed['path'].strip()
        name = os.path.basename(plugin).lower().replace('.py', '')

        if name in self.plugins or name in ['iproxyplugin', '__init__']:
            # Plugin already loaded.
            return

        self.logger.dbg('Attempting to load plugin: %s ("%s")...' % (name, plugin))
       
        try:
            sys.path.append(os.path.dirname(plugin))
            __import__(name)
            module = sys.modules[name]
            self.logger.dbg('Module imported.')

            try:
                handler = getattr(module, self.options['plugin_class_name'])

                found = False
                for base in inspect.getmro(handler):
                    if base.__name__ == 'IProxyPlugin':
                        found = True
                        break

                if not found:
                    raise TypeError('Plugin does not inherit from IProxyPlugin.')
                
                # Call plugin's __init__ with the `logger' instance passed to it.
                if self.instantiate:
                    instance = handler(PluginsLoader.InjectedLogger(name), self.options)
                else:
                    instance = handler
                
                self.logger.dbg('Found class "%s".' % self.options['plugin_class_name'])

            except AttributeError as e:
                self.logger.err('Plugin "%s" loading has failed: "%s".' % 
                    (name, self.options['plugin_class_name']))
                self.logger.err('\tError: %s' % e)
                if self.options['debug']:
                    raise

            except TypeError as e:
                self.logger.err('Plugin "{}" instantiation failed due to interface incompatibility.'.format(name))
                raise

            if not instance:
                self.logger.err('Didn\'t find supported class in module "%s"' % name)
            else:
                self.plugins[name] = instance
                self.logger.info('Plugin "%s" has been installed.' % name)

        except ImportError as e:
            self.logger.err('Couldn\'t load specified plugin: "%s". Error: %s' % (plugin, e))
            if self.options['debug']:
                raise