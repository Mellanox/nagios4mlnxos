"""
@copyright:
    Copyright (C) Mellanox Technologies Ltd. 2001-2015. ALL RIGHTS RESERVED.

    This software product is a proprietary product of Mellanox Technologies
    Ltd. (the "Company") and all right, title, and interest in and to the
    software product, including all associated intellectual property rights,
    are and shall remain exclusively with the Company.

    This software product is governed by the End User License Agreement
    provided with the software product.

@summary: Create Nagios configuration files for Mellanox switches

@author: Kobi Bar
@date:   April 20, 2015

"""

import os
import re
import logging
import yaml
from voluptuous import Schema, Required, All, Any, Range, Length, Coerce, MultipleInvalid
from errors import NagiosConfError


logger = logging.getLogger('confhandler')
switch_header_record = 'name,address,alias'


class NagiosConfValidator(object):
    snmpv2_schema = {
        Required('community', default='public'): All(Coerce(str), Length(min=1))
    }

    snmpv3_schema = {
        Required('username', default='admin'): All(Coerce(str), Length(min=1)),
        Required('auth_protocol', default='MD5'): Any('MD5', 'SHA'),
        Required('auth_password'): All(Coerce(str), Length(min=8)),
        Required('privacy_protocol', default='DES'): Any('DES', 'AES'),
        Required('privacy_password'): All(Coerce(str), Length(min=8))
    }

    snmp_schema = Schema({
        Required('port', default=161): All(int, Range(min=1, max=65536)),
        Required('timeout', default=5): All(int, Range(min=1, max=10)),
        Required('retries', default=3): All(int, Range(min=1, max=6)),
        Required('version', default=2): Any(2, 3),
        Required('snmpv2'): snmpv2_schema,
        Required('snmpv3'): snmpv3_schema
    })

    ping_srv_schema = {
        Required('warning_threshold'): All(Coerce(str)),
        Required('critical_threshold'): All(Coerce(str))
    }

    cpuload_srv_schema = {
        Required('warning_threshold', default=60): All(int, Range(min=1, max=99)),
        Required('critical_threshold', default=80): All(int, Range(min=1, max=99))
    }

    memutil_srv_schema = {
        Required('warning_threshold', default=80): All(int, Range(min=1, max=99)),
        Required('critical_threshold', default=90): All(int, Range(min=1, max=99))
    }

    services_schema = Schema({
        Required('ping'): ping_srv_schema,
        Required('cpu_load'): cpuload_srv_schema,
        Required('memory_utilization'): memutil_srv_schema
    })

    switch_record_regexp = re.compile(r'(?P<name>\S+),(?P<address>\S+),(?P<alias>.+)')

    def __init__(self, conf_file):
        self.conf_file = conf_file
        self.configuration = {}
        self.errors = []

    def validate(self):
        logger.debug('Validating the configuration file "%s"' % self.conf_file)
        self._read_configuration()
        self._validate_snmp_configuration()
        self._validate_services_configuration()
        self._validate_hostgroups_configuration()
        self._summary()

    def _read_configuration(self):
        logger.debug('Reading the configuration file "%s"' % self.conf_file)
        with open(self.conf_file, 'r') as f:
            self.configuration = yaml.load(f)

    def _validate_snmp_configuration(self):
        logger.debug('Validating the snmp configuration')
        snmp_conf = self.configuration.get('snmp', None)
        if snmp_conf is None:
            self.errors.append('snmp configuration is missing')
            return
        try:
            self.snmp_schema(snmp_conf)
        except MultipleInvalid as e:
            self.errors.extend(e.errors)

    def _validate_services_configuration(self):
        logger.debug('Validating the services configuration')
        services_conf = self.configuration.get('services', None)
        if services_conf is None:
            self.errors.append('services configuration is missing')
            return
        try:
            self.services_schema(services_conf)
        except MultipleInvalid as e:
            self.errors.extend(e.errors)

    def _validate_hostgroups_configuration(self):
        logger.debug('Validating the hostgroups configuration')
        hostgroups_conf = self.configuration.get('hostgroups', None)
        if hostgroups_conf is None:
            self.errors.append('hostgroups configuration is missing')
            return

        for hostgroup in hostgroups_conf:
            hostgroup_file = hostgroups_conf[hostgroup]
            if not os.path.isfile(hostgroup_file):
                self.errors.append('hostgroup "%s" file "%s" is missing' %
                                   (hostgroup, hostgroup_file))

            self._validate_hostgroup_switches_configuration(hostgroup, hostgroup_file)

    def _summary(self):
        if self.errors:
            err_msg = 'The following errors were found during configuration validation:\n'
            for err in self.errors:
                err_msg += '-E %s\n' % err
            raise NagiosConfError(err_msg)

    def _validate_hostgroup_switches_configuration(self, hostgroup, hostgroup_file):
        logger.debug('Validating the switches file "%s" of hostgroup "%s"' %
                     (hostgroup_file, hostgroup))
        with open(hostgroup_file, 'r') as f:
            switches_records = f.read().splitlines()

        for switch_record in switches_records:
            if switch_header_record in switch_record or switch_record.startswith('#'):
                continue
            if self.switch_record_regexp.search(switch_record) is None:
                self.errors.append('switch record "%s" in hostgroup file "%s" is invalid' %
                                   (switch_record, hostgroup_file))


class NagiosConfGenerator(object):
    commands_cfg_header = '''\
#########################################################################################
#
# commands.cfg - command definitions for Mellanox switches
#
#########################################################################################
'''

    hostgroups_cfg_header = '''\
#########################################################################################
#
# hostgroups.cfg - hostgroup definitions for Mellanox switches
#
#########################################################################################

'''

    services_cfg_header = '''\
#########################################################################################
#
# services.cfg - hostgroup service definitions for Mellanox switches
#
#########################################################################################
'''

    switch_cfg_header = '''\
#########################################################################################
#
# Configuration file for monitoring Mellanox switch
#
#########################################################################################
'''

    host_defs_header = '''
#########################################################################################
#
# Host definitions
#
#########################################################################################
'''

    service_defs_header = '''
###############################################################################
#
# Service definitions
#
###############################################################################
'''

    check_snmpv2_template = '-p %d -t %d -e %d -P 2c -C %s'
    check_snmpv3_template = '-p %d -t %d -e %d -P 3 -L authPriv -U %s -a %s -A "%s" -x %s -X "%s"'

    check_snmpv2_netifc_template = '-p %d -t %d -2 -C %s'
    check_snmpv3_netifc_template = '-p %d -t %d -l %s -x "%s" -X "%s" -L %s,%s'

    check_snmpv2_load_template = '-p %d -t %d -2 -C %s'
    check_snmpv3_load_template = '-p %d -t %d -l %s -x "%s" -X "%s" -L %s,%s'

    check_snmpv2_mlnx_template = '-p %d -t %d -r %d -P 2 -C %s'
    check_snmpv3_mlnx_template = '-p %d -t %d -r %d -P 3 -U %s -a %s -A "%s" -x %s -X "%s"'

    hostgroup_template = '''
define hostgroup{
    hostgroup_name           %s
    alias                    %s
}
'''

    host_template = '''
define host{
    use                      generic-switch
    host_name                %s
    alias                    %s
    address                  %s
    hostgroups               %s
}
'''

    ifc_oper_status_srv_template = '''
define service{
    use                      generic-service
    host_name                %s
    service_description      Network Interfaces Operational Status
    check_command            check_snmp_netint!%s -n "Eth"
}
'''

    ifc_admin_status_srv_template = '''
define service{
    use                      generic-service
    host_name                %s
    service_description      Network Interfaces Administrative Status
    check_command            check_snmp_netint!%s -n "Eth" -a
}
'''

    ping_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      PING
    check_command            check_ping!%s!%s
}
'''

    uptime_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      Uptime
    check_command            check_snmp!%s -o sysUpTime.0
}
'''

    sw_version_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      SW Version
    check_command            check_snmp!%s -o sysDescr.0
}
'''

    cpu_load_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      CPU Load
    check_command            check_snmp_load!%s -w %d -c %d
}
'''

    memory_utilization_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      Memory Utilization
    check_command            check_mlnxos_memory_utilization!%s -w %d -c %d
}
'''

    ps_status_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      PS Status
    check_command            check_mlnxos_entity_status!%s -e "Power Supply"
}
'''

    fan_status_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      Fan Status
    check_command            check_mlnxos_entity_status!%s -e Fan
}
'''

    temperature_status_srv_template = '''
define service{
    use                      generic-service
    hostgroup_name           %s
    service_description      Temperature Status
    check_command            check_mlnxos_entity_status!%s -e "Temperature sensor"
}
'''

    ifc_status_command = '''
define command{
    command_name             check_snmp_netint
    command_line             $USER1$/check_snmp_netint.pl -H $HOSTADDRESS$ $ARG1$
}
'''

    cpu_load_command = '''
define command{
    command_name             check_snmp_load
    command_line             $USER1$/check_snmp_load.pl -H $HOSTADDRESS$ $ARG1$
}
'''

    memory_utilization_command = '''
define command{
    command_name             check_mlnxos_memory_utilization
    command_line             $USER1$/check_mlnxos_memory_utilization.py -H $HOSTADDRESS$ $ARG1$
}
'''

    entity_status_command = '''
define command{
    command_name             check_mlnxos_entity_status
    command_line             $USER1$/check_mlnxos_entity_status.py -H $HOSTADDRESS$ $ARG1$
}
'''

    def __init__(self, conf_file, nagios_basedir):
        self.conf_file = conf_file
        self.conf_dir = os.path.join(nagios_basedir, 'conf')
        self.configuration = {}
        self.check_snmp = ""
        self.check_snmp_netifc = ""
        self.check_snmp_load = ""
        self.check_snmp_mlnx = ""

    def generate(self):
        logger.debug('Generating Nagios configuration files')
        self._make_conf_dir()
        self._read_configuration()
        self._generate_commands_configuration()
        self._handle_hostgroups()
        self._summary()

    def _make_conf_dir(self):
        logger.debug('Creating the directory "%s" for Nagios configuration' % self.conf_dir)
        os.mkdir(self.conf_dir)

    def _read_configuration(self):
        logger.debug('Reading the configuration file "%s"' % self.conf_file)
        with open(self.conf_file, 'r') as f:
            self.configuration = yaml.load(f)

    def _generate_commands_configuration(self):
        logger.debug('Generating the commands configuration')
        commands = []
        commands.append(self.commands_cfg_header)
        commands.append(self.ifc_status_command)
        commands.append(self.cpu_load_command)
        commands.append(self.memory_utilization_command)
        commands.append(self.entity_status_command)
        command_conf_file = os.path.join(self.conf_dir, 'commands.cfg')
        logger.debug('Writing the commands configuration to file "%s"' % command_conf_file)
        with open(command_conf_file, 'w') as f:
            f.writelines(commands)

    def _handle_hostgroups(self):
        logger.debug('Handling the hostgroups')
        groups = []
        groups.append(self.hostgroups_cfg_header)
        hostgroups = self.configuration['hostgroups']
        for hostgroup in hostgroups:
            groups.append(self.hostgroup_template % (hostgroup, hostgroup + ' switches'))

            hostgroup_dir = os.path.join(self.conf_dir, '%s' % hostgroup)
            switches_file = hostgroups[hostgroup]
            self._handle_hostgroup(hostgroup, hostgroup_dir, switches_file)

        hostgroups_conf_file = os.path.join(self.conf_dir, 'hostgroups.cfg')
        logger.debug('Writing the hostgroups configuration to file "%s"' % hostgroups_conf_file)
        with open(hostgroups_conf_file, 'w') as f:
            f.writelines(groups)

    def _summary(self):
        msg = 'Nagios configuration for mlnxos is placed in "%s" directory' % self.conf_dir
        logger.info(msg)
        print msg

    def _handle_hostgroup(self, hostgroup, hostgroup_dir, switches_file):
        logger.debug('Handling hostgroup "%s": hostgroup_dir="%s", switches_file="%s"' %
                     (hostgroup, hostgroup_dir, switches_file))
        self._make_hostgroup_directory(hostgroup_dir)
        self._initialize_services_snmp_args()
        self._generate_hostgroup_services_configuration(hostgroup, hostgroup_dir)
        self._handle_hostgroup_switches(hostgroup, hostgroup_dir, switches_file)

    def _make_hostgroup_directory(self, hostgroup_dir):
        logger.debug('Creating hostgroup directory "%s"' % hostgroup_dir)
        os.mkdir(hostgroup_dir)

    def _initialize_services_snmp_args(self):
        snmp_version = self.configuration['snmp']['version']
        logger.debug('Initializing snmp version %d arguments for Nagios services' % snmp_version)
        snmp_port = self.configuration['snmp']['port']
        snmp_timeout = self.configuration['snmp']['timeout']
        snmp_retries = self.configuration['snmp']['retries']
        if snmp_version == 3:
            snmpv3 = self.configuration['snmp']['snmpv3']
            self.check_snmp = self.check_snmpv3_template % (
                snmp_port,
                snmp_timeout,
                snmp_retries,
                snmpv3['username'],
                snmpv3['auth_protocol'],
                snmpv3['auth_password'],
                snmpv3['privacy_protocol'],
                snmpv3['privacy_password'])
            self.check_snmp_netifc = self.check_snmpv3_netifc_template % (
                snmp_port,
                snmp_timeout,
                snmpv3['username'],
                snmpv3['auth_password'],
                snmpv3['privacy_password'],
                snmpv3['auth_protocol'].lower(),
                snmpv3['privacy_protocol'].lower())
            self.check_snmp_load = self.check_snmpv3_load_template % (
                snmp_port,
                snmp_timeout,
                snmpv3['username'],
                snmpv3['auth_password'],
                snmpv3['privacy_password'],
                snmpv3['auth_protocol'].lower(),
                snmpv3['privacy_protocol'].lower())
            self.check_snmp_mlnx = self.check_snmpv3_mlnx_template % (
                snmp_port,
                snmp_timeout,
                snmp_retries,
                snmpv3['username'],
                snmpv3['auth_protocol'],
                snmpv3['auth_password'],
                snmpv3['privacy_protocol'],
                snmpv3['privacy_password'])
        else:
            snmpv2 = self.configuration['snmp']['snmpv2']
            self.check_snmp = self.check_snmpv2_template % (
                snmp_port,
                snmp_timeout,
                snmp_retries,
                snmpv2['community'])
            self.check_snmp_netifc = self.check_snmpv2_netifc_template % (
                snmp_port,
                snmp_timeout,
                snmpv2['community'])
            self.check_snmp_load = self.check_snmpv2_load_template % (
                snmp_port,
                snmp_timeout,
                snmpv2['community'])
            self.check_snmp_mlnx = self.check_snmpv2_mlnx_template % (
                snmp_port,
                snmp_timeout,
                snmp_retries,
                snmpv2['community'])

    def _generate_hostgroup_services_configuration(self, hostgroup, hostgroup_dir):
        logger.debug('Generating hostgroup "%s" services configuration' % hostgroup)
        hostgroup_services = []
        hostgroup_services.append(self.services_cfg_header)
        ping = self.configuration['services']['ping']
        hostgroup_services.append(
            self.ping_srv_template % (
                hostgroup,
                ping['warning_threshold'],
                ping['critical_threshold']))
        hostgroup_services.append(self.uptime_srv_template % (hostgroup, self.check_snmp))
        hostgroup_services.append(self.sw_version_srv_template % (hostgroup, self.check_snmp))
        cpuload = self.configuration['services']['cpu_load']
        hostgroup_services.append(self.cpu_load_srv_template % (
            hostgroup,
            self.check_snmp_load,
            cpuload['warning_threshold'],
            cpuload['critical_threshold']))
        memutil = self.configuration['services']['memory_utilization']
        hostgroup_services.append(self.memory_utilization_srv_template % (
            hostgroup,
            self.check_snmp_mlnx,
            memutil['warning_threshold'],
            memutil['critical_threshold']))
        hostgroup_services.append(self.ps_status_srv_template % (hostgroup, self.check_snmp_mlnx))
        hostgroup_services.append(self.fan_status_srv_template % (hostgroup, self.check_snmp_mlnx))
        hostgroup_services.append(self.temperature_status_srv_template %
                                  (hostgroup, self.check_snmp_mlnx))

        services_conf_file = os.path.join(hostgroup_dir, 'services.cfg')
        logger.debug('Writing hostgroup "%s" services configuration to file "%s"' %
                     (hostgroup, services_conf_file))
        with open(services_conf_file, 'w') as f:
            f.writelines(hostgroup_services)

    def _handle_hostgroup_switches(self, hostgroup, hostgroup_dir, switches_file):
        logger.debug('Handling hostgroup "%s" switches configuration' % hostgroup)
        with open(switches_file, 'r') as f:
            switches_records = f.read().splitlines()

        for switch_record in switches_records:
            if switch_header_record in switch_record or switch_record.startswith('#'):
                logger.debug('Skipping switch record "%s" of hostgroup "%s"' %
                             (switch_record, hostgroup))
                continue
            logger.debug('Handling switch record "%s" of hostgroup "%s"' %
                         (switch_record, hostgroup))
            self._generate_hostgroup_switch_configuration(hostgroup, hostgroup_dir, switch_record)

    def _generate_hostgroup_switch_configuration(self, hostgroup, hostgroup_dir, switch_record):
        logger.debug('Generating hostgroup "%s" switch configuration' % hostgroup)
        switch_cfg = []
        switch_cfg.append(self.switch_cfg_header)
        name, address, alias = switch_record.split(',')
        switch_cfg.append(self.host_defs_header)
        switch_cfg.append(self.host_template % (name, alias, address, hostgroup))
        switch_cfg.append(self.service_defs_header)
        switch_cfg.append(self.ifc_oper_status_srv_template % (name, self.check_snmp_netifc))
        switch_cfg.append(self.ifc_admin_status_srv_template % (name, self.check_snmp_netifc))

        switch_conf_file = os.path.join(hostgroup_dir, '%s.cfg' % name)
        logger.debug('Writing switch "%s" configuration of hostgroup "%s" to file "%s"' %
                     (name, hostgroup, switch_conf_file))
        with open(switch_conf_file, 'w') as f:
            f.writelines(switch_cfg)


class NagiosConfHandler(object):

    def __init__(self, conf_file, nagios_basedir):
        self.conf_validator = NagiosConfValidator(conf_file)
        self.conf_generator = NagiosConfGenerator(conf_file, nagios_basedir)

    def validate_configuration(self):
        self.conf_validator.validate()

    def generate_configuration(self):
        self.conf_generator.generate()
