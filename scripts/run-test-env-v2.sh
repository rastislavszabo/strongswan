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


RESPONDER_CFG_DIR="/tmp/responder"
INITIATOR_CFG_DIR="/tmp/initiator"

responder_conf() {
  sudo mkdir -p $RESPONDER_CFG_DIR
  sudo bash -c "cat << EOF > $RESPONDER_CFG_DIR/ipsec.conf
config setup
  strictcrlpolicy=no

conn responder
  mobike=no
  auto=add

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1-esn!

# local:
  left=172.16.0.2
  leftauth=psk

  leftsubnet=10.10.10.0/24

# remote: (roadwarrior)
#  right=172.16.0.1
  rightauth=psk

EOF"
  sudo bash -c "cat << EOF > $RESPONDER_CFG_DIR/strongswan.conf
charon {
  load_modular = yes
  plugins {
    include strongswan.d/charon/*.conf
    attr {
      dns = 8.8.8.8, 8.8.4.4
    }
  }
  filelog {
    charon {
      path=/var/log/charon.log
      time_format = %b %e %T
      ike_name = yes
      append = no
      default = 4
      flush_line = yes
    }
  }
}
include strongswan.d/*.conf
EOF"
  sudo bash -c "cat << EOF > $RESPONDER_CFG_DIR/ipsec.secrets
: PSK 'Vpp123'
EOF"
}

initiator_conf() {
  sudo mkdir -p $INITIATOR_CFG_DIR
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/ipsec.conf
config setup
  strictcrlpolicy=no

conn initiator
  mobike=no
  auto=add

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1-esn!

# local:
#  left=172.16.0.1
  leftauth=psk

# remote: (gateway)
  right=172.16.0.2
  rightauth=psk

  rightsubnet=10.10.10.0/24

EOF"
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/strongswan.conf
charon {
  load_modular = yes
  plugins {
    include strongswan.d/charon/*.conf
    attr {
      dns = 8.8.8.8, 8.8.4.4
    }
  }
  filelog {
    charon {
      path=/var/log/charon.log
      time_format = %b %e %T
      ike_name = yes
      append = no
      default = 4
      flush_line = yes
    }
  }
}
include strongswan.d/*.conf
EOF"
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/ipsec.secrets
: PSK 'Vpp123'
EOF"
}

responder_conf
initiator_conf

# initiator aka vpn client
sudo docker run --name responder -d --rm --privileged -v $RESPONDER_CFG_DIR:/conf -v $RESPONDER_CFG_DIR:/etc/ipsec.d philplckthun/strongswan

# initiator aka vpn client
sudo docker run --name initiator -d --rm --privileged -v $INITIATOR_CFG_DIR:/conf -v $INITIATOR_CFG_DIR:/etc/ipsec.d philplckthun/strongswan


# if we register veth interface in docker namespace docker will automatically
# delete the interface after container is destroied
# alternatively try to remove the interface: sudo ip link del wan0

# 1) create veth pair
#sudo ip link add wan0 type veth peer name wan1

# 2) add side one of the veth pair to the responder
#sudo ip link set netns $(docker inspect --format '{{.State.Pid}}' responder) dev wan0
sudo docker exec responder ip addr add 172.16.0.2/24 dev eth0
#sudo docker exec responder ip link set wan0 up

# 3) add side two of the veth pair to the initiator
#sudo ip link set netns $(docker inspect --format '{{.State.Pid}}' initiator) dev wan1
sudo docker exec initiator ip addr add 172.16.0.1/24 dev eth0
#sudo docker exec initiator ip link set wan1 up

