#!/usr/bin/env bash

WS="`pwd`"
AGENT_ROOT=${WS}/third_party/vpp-agent/plugins
API_DEST=third_party/vpp_agent_c_api

vpp_plugins=(
    acl
    bfd
    ipsec
    interfaces
    l2
    l3
    l4
    nat
    stn
    rpc
    punt
)

linux_plugins=(
    interfaces
    l3
)

# Workaround #1: fix messed up import paths in rpc.proto
sed 's/github.com\/ligato\/vpp-agent\/plugins\///' \
     ${AGENT_ROOT}/vpp/model/rpc/rpc.proto > ${AGENT_ROOT}/vpp/model/rpc/rpc.proto.new
rm ${AGENT_ROOT}/vpp/model/rpc/rpc.proto
mv ${AGENT_ROOT}/vpp/model/rpc/rpc.proto.new ${AGENT_ROOT}/vpp/model/rpc/rpc.proto

for file in ${linux_plugins[@]}
do
    echo "generating linux $file.proto"
    protoc -I ${AGENT_ROOT}/linux/model/${file} \
        --grpc-c_out=${AGENT_ROOT}/linux/model/${file} \
        --plugin=third_party/grpc-c/build/compiler/protoc-gen-grpc-c \
        ${AGENT_ROOT}/linux/model/${file}/${file}.proto
done

for file in ${vpp_plugins[@]}
do
    echo "generating vpp $file.proto"
    protoc -Ithird_party/vpp-agent/plugins -I ${AGENT_ROOT}/vpp/model/${file} \
        --grpc-c_out=${AGENT_ROOT}/vpp/model/${file} \
        --plugin=third_party/grpc-c/build/compiler/protoc-gen-grpc-c \
        ${AGENT_ROOT}/vpp/model/${file}/${file}.proto
done


# Workaround #2 for vpp-agent v1 API

cp -r ${AGENT_ROOT}/vpp ${API_DEST}
cp -r ${AGENT_ROOT}/linux ${API_DEST}

sed 's/PROTOBUF_C_l3_2eproto__INCLUDED/PROTO_L3_H/' \
    ${API_DEST}/vpp/model/l3/l3.grpc-c.h > ${API_DEST}/vpp/model/l3/l3.grpc-c.h.new
sed 's/PROTOBUF_C_interfaces_2eproto__INCLUDED/PROTO_INTERFACES_H/' \
    ${API_DEST}/vpp/model/interfaces/interfaces.grpc-c.h > ${API_DEST}/vpp/model/interfaces/interfaces.grpc-c.h.new

rm ${API_DEST}/vpp/model/l3/l3.grpc-c.h
rm ${API_DEST}/vpp/model/interfaces/interfaces.grpc-c.h

mv ${API_DEST}/vpp/model/interfaces/interfaces.grpc-c.h.new \
    ${API_DEST}/vpp/model/interfaces/interfaces.grpc-c.h
mv ${API_DEST}/vpp/model/l3/l3.grpc-c.h.new \
    ${API_DEST}/vpp/model/l3/l3.grpc-c.h
