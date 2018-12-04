#!/usr/bin/env bash

# builds all dependencies used by kernel_vpp and socket_vpp plugins
set -e

WS="`pwd`"

echo "Building dependency: grpc-c"
cd ${WS}/third_party/grpc-c
git submodule update --init
autoreconf --install
./builddeps.sh
mkdir build; cd build
../configure
make

echo "Generating app-agent API files"
cd ${WS}/third_party/vpp-agent
git submodule update --init
git checkout pantheon-dev
cd ${WS}
./gen_api.sh

echo "Building vpp-agent API C lib"
cd ${WS}/third_party/vpp_agent_c_api
./autogen.sh
./configure
make
