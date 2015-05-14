#!/usr/bin/python

"""
@copyright:
    Copyright (C) Mellanox Technologies Ltd. 2001-2015. ALL RIGHTS RESERVED.

    This software product is a proprietary product of Mellanox Technologies
    Ltd. (the "Company") and all right, title, and interest in and to the
    software product, including all associated intellectual property rights,
    are and shall remain exclusively with the Company.

    This software product is governed by the End User License Agreement
    provided with the software product.

@summary: check_mlnxos_entity_status is a nagios plugin which checks
          the status of Mellanox switch entity (e.g. psu, fan, temperature sensor) via SNMP

@author: Kobi Bar
@date:   April 15, 2015

"""

import sys
import netsnmp
from argparse import ArgumentParser

status = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3}


class SnmpException(Exception):
    pass


class SnmpManager(object):
    GETBULK_NONREPEATERS = 0
    GETBULK_MAXREPETITIONS = 50

    def __init__(self):
        pass

    def _is_prefix_of(self, oid, value):
        """Returns true if argument OID resides deeper in the OID tree"""
        l = len(oid)
        if l <= len(value):
            if oid[:l] == value[:l]:
                return 1
        return 0

    def _table_index(self, oid, table_oid, last_index):
        """Returns the table index"""
        l = len(oid)
        table_len = len(table_oid)
        if l > table_len:
            table_index = oid[table_len + 1:]
            table_index.append(last_index)
            return tuple(table_index)
        return ()

    def _str_oid_to_list(self, value):
        """Convert a string OID to a list OID"""
        r = []
        for element in [x for x in value.split('.') if x != '']:
            try:
                r.append(int(element, 0))
            except ValueError:
                raise SnmpException('Malformed Object ID %s' % value)
        return r

    def _get_session(self, args):
        """Configure the net-snmp session according to the SNMP protocol version"""
        if args.snmp_protocol == 3:
            return netsnmp.Session(DestHost='%s:%d' % (args.hostname, args.port),
                                   Version=args.snmp_protocol,
                                   Retries=args.retries,
                                   Timeout=args.timeout * 1000000,
                                   SecName=args.sec_name,
                                   SecLevel='authPriv',
                                   AuthProto=args.auth_protocol,
                                   AuthPass=args.auth_password,
                                   PrivProto=args.privacy_protocol,
                                   PrivPass=args.privacy_password,
                                   UseNumeric=1)
        else:
            return netsnmp.Session(DestHost='%s:%d' % (args.hostname, args.port),
                                   Version=args.snmp_protocol,
                                   Community=args.community,
                                   Retries=args.retries,
                                   Timeout=args.timeout * 1000000,
                                   UseNumeric=1)

    def get_table(self, oid, args, col_list):
        session = self._get_session(args)
        read_bulk = True
        last_oid = oid
        result = {}
        table_oid = self._str_oid_to_list(oid)
        table_oid_len = len(table_oid)
        read_full_table = False
        if col_list is None:
            read_full_table = True
        else:
            if len(col_list) == 0:
                return result
            col_list.sort()
            col_index = 0

        while read_bulk:
            varlist = netsnmp.VarList(netsnmp.Varbind(last_oid,),)
            session.getbulk(self.GETBULK_NONREPEATERS,
                            self.GETBULK_MAXREPETITIONS,
                            varlist)
            if session.ErrorStr != '':
                raise SnmpException('Error value in response: %s' % session.ErrorStr)

            # check if all data is none this case is timeout for several operating systems
            read_data = False
            for var in varlist:
                if var.val is not None:
                    read_data = True
                    break
            if not read_data:
                raise SnmpException('General error in SNMP response')

            for var in varlist:
                if var.tag is None:
                    continue
                var_oid = self._str_oid_to_list(var.tag)
                if not self._is_prefix_of(table_oid, var_oid):
                    read_bulk = False
                    break
                if len(var_oid) == table_oid_len:
                    continue
                # test if column in list
                if not read_full_table and var_oid[table_oid_len + 1] > col_list[col_index]:
                    col_index = col_index + 1
                    if col_index >= len(col_list):
                        read_bulk = False
                        break
                if read_full_table or var_oid[table_oid_len + 1] == col_list[col_index]:
                    if var.val is None:
                        raise SnmpException('Error no data: tag=%s, iid=%s' % (var.tag, var.iid))
                    table_index = self._table_index(
                        var_oid, table_oid, int(var.iid))
                    if len(table_index) > 0 and var.iid != '' and (var.val is not None):
                        result[table_index] = var.val
                    last_oid = var.tag + '.' + var.iid
                else:
                    # move to the next column
                    var_oid[table_oid_len + 1] = col_list[col_index]
                    for x in range(table_oid_len + 2, len(var_oid)):
                        var_oid[x] = 0
                    last_oid = '.' + '.'.join(str(x) for x in var_oid)
        return result


class MibNode:

    def __init__(self, oid, access, indexes):
        self.name = None  # will be filled on loading
        self.oid = oid
        self.access = access
        self.indexes = indexes
        self.column = int(self.oid[-1])

        for x in oid.split('.'):
            if x != '':
                self.column = int(x)


class SnmpAccessMode(object):
    READ_ONLY = 'ReadOnly'
    NO_ACCESS = 'NoAccess'
    READ_WRITE = 'ReadWrite'
    CREATE = 'Create'


class EntityMib:
    nodes = {
        'entPhysicalTable':
        MibNode('.1.3.6.1.2.1.47.1.1.1', SnmpAccessMode.NO_ACCESS, None),
        'entPhysicalDescr':
        MibNode('.1.3.6.1.2.1.47.1.1.1.1.2', SnmpAccessMode.READ_ONLY, None),
        'entPhysicalName':
        MibNode('.1.3.6.1.2.1.47.1.1.1.1.7', SnmpAccessMode.READ_ONLY, None)
    }


class EntityStateMib:
    nodes = {
        'entStateTable':
        MibNode('.1.3.6.1.2.1.131.1.1', SnmpAccessMode.NO_ACCESS, None),
        'entStateAlarm':
        MibNode('.1.3.6.1.2.1.131.1.1.1.5', SnmpAccessMode.READ_ONLY, None)
    }


class CLIError(Exception):
    pass


class ESArgumentParser(ArgumentParser):

    def error(self, message):
        """
        Override this function in order to raise exception
        """
        raise CLIError(message)


class EntityStatus(object):
    ent_desc_col = EntityMib.nodes['entPhysicalDescr'].column
    ent_name_col = EntityMib.nodes['entPhysicalName'].column
    ent_state_col = EntityStateMib.nodes['entStateAlarm'].column
    warning_state_mask = 67  # 67 = 01000011
    critical_state_mask = 28  # 28 = 00011100

    def __init__(self):
        self.snmp_manager = SnmpManager()

    def run(self):
        (args, parser) = self._parse_args()
        self._validate_args(args, parser)
        return self._probe(args)

    def _parse_args(self):
        parser = ESArgumentParser(
            description='Check entity status of Mellanox switch via SNMP',
            usage='%(prog)s -H <address> -e <name> [options]')

        parser.add_argument('-V', '--version',
                            action='version',
                            help='Print version information',
                            version='%(prog)s v1.0.0')
        parser.add_argument('-H', '--hostname',
                            help='Host name or IP Address',
                            metavar='<address>',
                            required=True)
        parser.add_argument('-p', '--port',
                            help='SNMP server port number (default: 161)',
                            metavar='<port>',
                            choices=xrange(1, 65536),
                            default=161,
                            type=int)
        parser.add_argument('-e', '--entity-name',
                            help='Entity name (Fan|Power Supply|Temperature sensor)',
                            metavar='<name>',
                            required=True)
        parser.add_argument('-P', '--snmp-protocol',
                            help='SNMP protocol version (default: 2)',
                            metavar='[2|3]',
                            choices=[2, 3],
                            default=2,
                            type=int)
        parser.add_argument('-v', '--verbose',
                            action='store_true',
                            help='Show details for command-line debugging')

        v2group = parser.add_argument_group('SNMP version 2 specific')
        v2group.add_argument('-C', '--community',
                             help='Community string (default: public)',
                             metavar='<community>',
                             default='public')

        v3group = parser.add_argument_group('SNMP version 3 specific')
        v3group.add_argument('-U', '--sec-name',
                             help='Security username (default: admin)',
                             metavar='<username>',
                             default='admin')
        v3group.add_argument('-a', '--auth-protocol',
                             help='Authentication protocol (default: MD5)',
                             metavar='[MD5|SHA]',
                             choices=['MD5', 'SHA'],
                             default='MD5')
        v3group.add_argument('-A', '--auth-password',
                             help='Authentication password',
                             metavar='<password>')
        v3group.add_argument('-x', '--privacy-protocol',
                             help='Privacy protocol (default: DES)',
                             metavar='[DES|AES]',
                             choices=['DES', 'AES'],
                             default='DES')
        v3group.add_argument('-X', '--privacy-password',
                             help='Privacy password',
                             metavar='<password>')

        commgroup = parser.add_argument_group('General SNMP communication options')
        commgroup.add_argument('-t', '--timeout',
                               help='Request timeout in seconds (default: 5)',
                               metavar='<timeout>',
                               choices=xrange(1, 11),
                               default=5,
                               type=int)
        commgroup.add_argument('-r', '--retries',
                               help='Number of retries (default: 3)',
                               metavar='<retries>',
                               choices=xrange(1, 7),
                               default=3,
                               type=int)

        args = parser.parse_args()
        if args.verbose:
            print args
        return (args, parser)

    def _validate_args(self, args, parser):
        if args.snmp_protocol == 3:
            if args.auth_password is None:
                parser.error('argument -A/--auth-password is required')
            if args.privacy_password is None:
                parser.error('argument -X/--privacy-password is required')

    def _probe(self, args):
        res = self.snmp_manager.get_table(
            EntityMib.nodes['entPhysicalTable'].oid, args,
            [self.ent_desc_col, self.ent_name_col])
        entity_indexes = set([x[1] for x in res])
        entity = {}
        for index in entity_indexes:
            ent_desc = res[(self.ent_desc_col, index)]
            ent_name = res[(self.ent_name_col, index)]
            if ent_name == args.entity_name:
                entity[index] = ent_desc
        if args.verbose:
            print 'entity: %s' % entity
        if len(entity) == 0:
            print 'OK - no "%s" entities are present' % args.entity_name
            return status['OK']

        res = self.snmp_manager.get_table(
            EntityStateMib.nodes['entStateTable'].oid, args,
            [self.ent_state_col])
        entity_state_indexes = set([x[1] for x in res])
        entity_status = []
        for index in entity_state_indexes:
            if index in entity:
                ent_state = ord(res[(self.ent_state_col, index)])
                if ent_state & self.critical_state_mask != 0:
                    entity_status.append("%s:CRITICAL" % entity[index])
                elif ent_state & self.warning_state_mask != 0:
                    entity_status.append("%s:WARNING" % entity[index])
                else:
                    entity_status.append("%s:OK" % entity[index])
        if args.verbose:
            print 'entity status: %s' % entity_status

        entity_status_str = ', '.join(entity_status)
        if 'CRITICAL' in entity_status_str:
            print 'CRITICAL - ' + entity_status_str
            return status['CRITICAL']
        elif 'WARNING' in entity_status_str:
            print 'WARNING - ' + entity_status_str
            return status['WARNING']

        print 'OK - ' + entity_status_str
        return status['OK']


def main():
    try:
        return EntityStatus().run()
    except KeyboardInterrupt:
        # handle keyboard interrupt
        return status['OK']
    except Exception, e:
        print 'UNKNOWN - ' + str(e)
        return status['UNKNOWN']

if __name__ == "__main__":
    sys.exit(main())
