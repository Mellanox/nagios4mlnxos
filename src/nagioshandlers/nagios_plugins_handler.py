"""
@copyright:
    Copyright (C) Mellanox Technologies Ltd. 2001-2015. ALL RIGHTS RESERVED.

    This software product is a proprietary product of Mellanox Technologies
    Ltd. (the "Company") and all right, title, and interest in and to the
    software product, including all associated intellectual property rights,
    are and shall remain exclusively with the Company.

    This software product is governed by the End User License Agreement
    provided with the software product.

@summary: Copy Nagios plugins for Mellanox switches
@author: Kobi Bar
@date:   April 28, 2015

"""

import os
import shutil
import logging
from errors import NagiosPluginsError


logger = logging.getLogger('pluginshandler')


class NagiosPluginsHandler(object):
    plugins = ['check_snmp_load.pl',
               'check_snmp_netint.pl',
               'check_mlnxos_entity_status.py',
               'check_mlnxos_memory_utilization.py']

    def __init__(self, nagios_basedir):
        working_dir = os.path.dirname(os.path.abspath(__file__))
        self.src_plugins_dir = os.path.join(working_dir, '..', 'plugins')
        self.dst_plugins_dir = os.path.join(nagios_basedir, 'plugins')
        self.errors = []

    def validate_plugins(self):
        logger.debug('Validating the Nagios plugins')
        self._validate()
        self._validate_summary()

    def _validate(self):
        for plugin in self.plugins:
            plugin_path = os.path.join(self.src_plugins_dir, plugin)
            if not os.path.isfile(plugin_path):
                self.errors.append('plugin "%s" is missing' % plugin_path)

    def _validate_summary(self):
        if self.errors:
            err_msg = 'The following errors were found during plugins validation:\n'
            for err in self.errors:
                err_msg += '-E %s\n' % err
            raise NagiosPluginsError(err_msg)

    def copy_plugins(self):
        logger.debug('Copying the Nagios plugins')
        self._make_plugins_dir()
        self._copy_plugins()
        self._copy_plugins_summary()

    def _make_plugins_dir(self):
        logger.debug('Creating the directory "%s" for Nagios plugins' % self.dst_plugins_dir)
        os.mkdir(self.dst_plugins_dir)

    def _copy_plugins(self):
        for plugin in self.plugins:
            plugin_path = os.path.join(self.src_plugins_dir, plugin)
            logger.debug('Copying the plugin "%s" to "%s"' % (plugin, self.dst_plugins_dir))
            shutil.copy2(plugin_path, self.dst_plugins_dir)

    def _copy_plugins_summary(self):
        msg = 'Nagios plugins for mlnxos are placed in "%s" directory' % self.dst_plugins_dir
        logger.info(msg)
        print msg
