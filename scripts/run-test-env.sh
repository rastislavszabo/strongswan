#!/bin/bash

# Copyright (c) 2018 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VPP_CFG_DIR="/tmp/vpp"
AGENT_CFG_DIR="/tmp/vpp-agent"
INITIATOR_CFG_DIR="/tmp/initiator"

vpp_conf() {
  sudo mkdir -p $VPP_CFG_DIR
  sudo bash -c "cat << EOF > $VPP_CFG_DIR/vpp.conf
unix {
  nodaemon
  cli-listen 0.0.0.0:5002
  cli-no-pager
}
plugins {
  plugin dpdk_plugin.so {
    disable
  }
}
punt {
  socket /etc/vpp/punt.sock
}
EOF"
}

grpc_conf() {
  sudo mkdir -p $AGENT_CFG_DIR
  sudo bash -c "cat << EOF > $AGENT_CFG_DIR/grpc.conf
# GRPC endpoint defines IP address and port (if tcp type) or unix domain socket file (if unix type).
endpoint: 127.0.0.1:9111

# If unix domain socket file is used for GRPC communication, permissions to the file can be set here.
# Permission value uses standard three-or-four number linux binary reference.
permission: 000

# If socket file exists in defined path, it is not removed by default, GRPC plugin tries to use it.
# Set the force removal flag to 'true' ensures that the socket file will be always re-created
force-socket-removal: false

# Available socket types: tcp, tcp4, tcp6, unix, unixpacket. If not set, defaults to tcp.
network: tcp

# Maximum message size in bytes for inbound mesages. If not set, GRPC uses the default 4MB.
max-msg-size: 4096

# Limit of server streams to each server transport.
max-concurrent-streams: 0
EOF"
}

responder_conf() {
  sudo bash -c "cat << EOF > /etc/ipsec.conf
conn responder
# defaults?
  auto=add
  compress=no
  fragmentation=yes
  forceencaps=yes

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1-esn!

# local:
  left=172.16.0.2
  leftauth=psk

  leftsubnet=10.10.10.0/24

# remote: (roadwarrior)
  rightauth=psk

EOF"
  sudo bash -c "cat << EOF > /etc/ipsec.secrets
: PSK 'Vpp123'
EOF"
}

initiator_conf() {
  sudo mkdir -p $INITIATOR_CFG_DIR
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/ipsec.conf
conn initiator
# defaults?
  auto=add
  compress=no
  fragmentation=yes
  forceencaps=yes

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1-esn!

# local:
  leftauth=psk

# remote: (gateway)
  right=172.16.0.2
  rightauth=psk

  rightsubnet=10.10.10.0/24

EOF"
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/ipsec.secrets
: PSK 'Vpp123'
EOF"
}

responder_conf
initiator_conf
grpc_conf
vpp_conf

# responder aka vpn server (gateway)
sudo docker run --name responder -d --rm --net=host --privileged -it -e INITIAL_LOGLVL=debug -e ETCD_CONFIG=DISABLED -e KAFKA_CONFIG=DISABLED -v $VPP_CFG_DIR:/etc/vpp -v $AGENT_CFG_DIR:/opt/vpp-agent/dev ligato/vpp-agent:pantheon-dev

# initiator aka vpn client
sudo docker run --name initiator -d --rm --privileged -v $INITIATOR_CFG_DIR:/etc/ipsec.d philplckthun/strongswan

# dummy network behind vpn
sleep 2
sudo docker exec responder vppctl -s localhost:5002 tap connect tap0
sudo docker exec responder vppctl -s localhost:5002 set int state tapcli-0 up
sudo docker exec responder vppctl -s localhost:5002 set int ip address tapcli-0 10.10.10.1/24

# if we register veth interface in docker namespace docker will automatically
# delete the interface after container is destroied
# alternatively try to remove the interface: sudo ip link del wan0

# 1) create veth pair
sudo ip link add wan0 type veth peer name wan1
# 2) add one side of the veth pair to responder
sudo docker exec responder vppctl -s localhost:5002 create host-interface name wan0
sudo docker exec responder vppctl -s localhost:5002 set int state host-wan0 up
sudo docker exec responder vppctl -s localhost:5002 set int ip address host-wan0 172.16.0.2/24
# 3) add other side of the veth pair to the initiator container
sudo ip link set netns $(docker inspect --format '{{.State.Pid}}' initiator) dev wan1
sudo docker exec initiator ip addr add 172.16.0.1/24 dev wan1
sudo docker exec initiator ip link set wan1 up

# 1) try to connect to responder over ikev2 vpn
# sudo docker exec initiator ipsec up initiator

# to debug (responder):
# sudo docker exec -it responder vppctl -s localhost:5002
# to debug (initiator):
# sudo docker exec -it initiator /bin/bash

