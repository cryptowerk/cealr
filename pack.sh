#!/usr/bin/env bash
# This script creates packages for various unixes. Requires fpm
# read version from VERSION file
VERSION=`(cat VERSION | tr -d '"')`
cd build/release
fpm -s dir -t deb -n cealr -v $VERSION --prefix /usr/local/bin cealr
