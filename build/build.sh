#!/bin/bash
# Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of Mellanox Technologies Ltd.
# (the "Company") and all right, title, and interest in and to the software product,
# including all associated intellectual property rights, are and shall
# remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.

initialize() {
    _logfile="/tmp/$(basename $0).$$"
    exec 5>&1
    exec > $_logfile
    exec 2>&1
    set -x

    pushd $(dirname $0) &>/dev/null
    _build_dir=$(pwd)
    popd &>/dev/null

    _src_dir=$(dirname $_build_dir)
    _conf_files=$(ls $_src_dir/conf/*.yaml)
    _plugins=$(ls $_src_dir/plugins/*.pl $_src_dir/src/plugins/*.py)
    _handlers_scripts=$(ls $_src_dir/src/nagioshandlers/*.py)
    _main_script="$_src_dir/src/nagios4mlnxos.py"
    _readme="$_src_dir/README"
    _license="$_src_dir/LICENSE"
    _files="$_conf_files $_plugins $_handlers_scripts $_main_script $_readme"

    _tmp_dir=$(mktemp -d /tmp/build_nagios4mlnxos.XXXXXXXXXX)
    _dst_dir=$_tmp_dir/nagios4mlnxos
    _conf_dir=$_dst_dir/conf
    _plugins_dir=$_dst_dir/plugins
    _handlers_dir=$_dst_dir/nagioshandlers
    _package=nagios4mlnxos-1.0.0.tar.gz
}

copy_files() {
    for _file in $_conf_files; do
        cp -p $_file $_conf_dir
    done
    for _file in $_plugins; do
        cp -p $_file $_plugins_dir
    done
    for _file in $_handlers_scripts; do
        cp -p $_file $_handlers_dir
    done
    cp -p $_main_script $_dst_dir
    cp -p $_readme $_dst_dir
    cp -p $_license $_dst_dir
}

create_package() {
    pushd $_tmp_dir &>/dev/null
    tar cjf $_package $(basename $_dst_dir) 
    cp -f $_package $_build_dir
    rm -rf $_tmp_dir
    popd &>/dev/null
}

initialize
echo "Building the package $_package" >&5
echo "Logfile: $_logfile" >&5
mkdir $_dst_dir $_conf_dir $_plugins_dir $_handlers_dir
copy_files
create_package
echo "Done" >&5
exit 0
