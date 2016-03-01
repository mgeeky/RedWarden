#!/usr/bin/python
import os
import sys

#
# Plugin that attempts to load all of the supplied plugins from 
# program launch options.
class PluginsLoader:   
    def __init__(self, logger, options):
        self.options = options
        self.plugins = {}
        self.called = False
        self.logger = logger
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

    def load(self, path):
        plugin = path.strip()
        instance = None
        
        name = os.path.basename(plugin).lower().replace('.py', '')

        if name in self.plugins:
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
                
                # Call plugin's __init__ with the `logger' instance passed to it.
                instance = handler(self.logger)
                
                self.logger.dbg('Found class "%s".' % self.options['plugin_class_name'])

            except AttributeError as e:
                self.logger.err('Plugin "%s" loading has failed: "%s".' % 
                    (name, self.options['plugin_class_name']))
                self.logger.err('\tError: %s' % e)
                return

            if not instance:
                self.logger.err('Didn\'t find supported class in module "%s"' % name)
            else:
                self.plugins[name] = instance
                self.logger.info('Plugin "%s" has been installed.' % name)

        except ImportError as e:
            self.logger.err('Couldn\' load specified plugin: "%s". Error: %s' % (plugin, e))