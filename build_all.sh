#!/usr/bin/env bash

set -e

./build_dependencies.sh
./autogen.sh
./configure --enable-socket-vpp --enable-libipsec --enable-kernel-vpp --sysconfdir=/etc --with-piddir=/etc/ipsec.d/run
make
