#!/usr/bin/env bash

set -e

WS="`pwd`"

sudo apt-get -y install libgmp-dev automake autoconf libtool pkg-config gettext \
    perl python flex bison gperf

git submodule update --init

cd ${WS}/grpc
git checkout v1.27.0
git submodule update --init
CFLAGS="-Wno-implicit-fallthrough -Wno-stringop-overflow -Wno-error=conversion" make
sudo make install
sudo ldconfig

cd /tmp/
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout v3.11.2
git submodule update --init --recursive
./autogen.sh
./configure
make
sudo make install
sudo ldconfig

cd ${WS}/api
./gen.sh
autoreconf --install
./configure
make
sudo make install-strip
sudo ldconfig
