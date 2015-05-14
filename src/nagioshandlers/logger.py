"""
@copyright:
    Copyright (C) Mellanox Technologies Ltd. 2001-2015. ALL RIGHTS RESERVED.

    This software product is a proprietary product of Mellanox Technologies
    Ltd. (the "Company") and all right, title, and interest in and to the
    software product, including all associated intellectual property rights,
    are and shall remain exclusively with the Company.

    This software product is governed by the End User License Agreement
    provided with the software product.

@author: Kobi Bar
@date:   April 27, 2015

"""

import logging


def get_formatter():
    msg_fmt = '%(asctime)s.%(msecs)03d %(name)-5s %(levelname)-7s %(message)s'
    return logging.Formatter(msg_fmt, datefmt='%Y-%m-%d %H:%M:%S')


def get_file_handler(file_name, level):
    formatter = get_formatter()
    handler = logging.FileHandler(file_name)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    return handler


def init_file_logger(logger, file_name, level):
    handler = get_file_handler(file_name, level)
    logger.setLevel(level)
    logger.addHandler(handler)


def init_root_logger(file_name, level=logging.DEBUG):
    logger = logging.getLogger()
    init_file_logger(logger, file_name, level)


def update_root_logger_level(level):
    logger = logging.getLogger()
    try:
        numLevel = int(logging.getLevelName(level))
    except ValueError, e:
        logger.error("Failed to update root logger level '%s': %s." % (level, str(e)))
        return
    logger.setLevel(numLevel)
