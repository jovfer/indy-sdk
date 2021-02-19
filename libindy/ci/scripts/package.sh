#!/bin/bash

#if [ $# -ne 1 ]
#  then
#    echo "ERROR: Incorrect number of arguments"
#    echo "Usage:"
#    echo "$0 <build-num>"
#    exit 1
#fi
#
#BUILD_NUM=$1

set -eux

PACKAGE_TYPE=$(lsb_release -cs)
REVISION=$(git rev-parse HEAD | cut -c 1-7)
VERSION=1.15.0.${REVISION}-${PACKAGE_TYPE}  # TODO: Autodetect main part

pushd libindy
cp Cargo.toml Cargo.toml.backup
sed -i -E -e "s/provides = \"libindy \(= [(,),0-9,.]+\)\"/provides = \"libindy \(= ${VERSION}\)\"/g" Cargo.toml
sed -i -E -e "s/name = \"libindy\"/name = \"libindy-async\"/g" Cargo.toml
cargo deb --no-build --deb-version ${VERSION} --variant libindy-${PACKAGE_TYPE}
cp Cargo.toml.backup Cargo.toml
popd
