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

@summary: Create Nagios configuration files for Mellanox switches

@author: Kobi Bar
@date:   April 16, 2015

"""

import sys
import os
import shutil
import logging
from argparse import ArgumentParser
from nagioshandlers.logger import init_root_logger, update_root_logger_level
from nagioshandlers.errors import NagiosConfError, NagiosPluginsError
from nagioshandlers.nagios_conf_handler import NagiosConfHandler
from nagioshandlers.nagios_plugins_handler import NagiosPluginsHandler


logname = '/tmp/nagios4mlnxos_%s.log' % os.getpid()
init_root_logger(logname)
logger = logging.getLogger()


def parse_args():
    parser = ArgumentParser(
        description='Generate Nagios configuration and copy plugins for Mellanox switches',
        usage='%(prog)s -c <file> [options]')

    parser.add_argument('-V', '--version',
                        action='version',
                        help='Print version information',
                        version='%(prog)s v1.0.0')
    parser.add_argument('-c', '--conf-file',
                        help='Configuration file',
                        metavar='<file>',
                        required=True)
    parser.add_argument('-o', '--output',
                        help='Output directory (default: /tmp)',
                        metavar='<outdir>',
                        default='/tmp')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help='Validate the user configuration only')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Show details for command-line debugging')

    args = parser.parse_args()
    return (args, parser)


def validate_args(args, parser):
    if not os.path.isfile(args.conf_file):
        parser.error('The configuration file "%s" does not exist' % args.conf_file)
    if not os.path.isdir(args.output):
        parser.error('The output directory "%s" does not exist' % args.output)


def make_nagios_basedir(nagios_basedir):
    if os.path.isdir(nagios_basedir):
        shutil.rmtree(nagios_basedir)
    os.mkdir(nagios_basedir)


def main():
    try:
        (args, parser) = parse_args()
        validate_args(args, parser)

        if not args.verbose:
            update_root_logger_level('INFO')

        print 'Logfile: %s' % logname

        nagios_basedir = os.path.join(args.output, 'nagios4mlnxos_output')
        conf_handler = NagiosConfHandler(args.conf_file, nagios_basedir)
        plugins_handler = NagiosPluginsHandler(nagios_basedir)

        conf_handler.validate_configuration()
        plugins_handler.validate_plugins()

        if args.dry_run:
            msg = 'Dry run has completed successfully'
            logger.info(msg)
            print msg
            return 0

        make_nagios_basedir(nagios_basedir)
        conf_handler.generate_configuration()
        plugins_handler.copy_plugins()
        return 0
    except KeyboardInterrupt:
        # handle keyboard interrupt
        return 0
    except (NagiosConfError, NagiosPluginsError), e:
        logger.error(str(e))
        print str(e)
        return 1
    except Exception, e:
        msg = 'Unknown error: %s' % str(e)
        logger.error(msg)
        print msg
        return 1

if __name__ == "__main__":
    sys.exit(main())
