/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include "vpp/model/rpc/rpc.grpc-c.h"

int main()
{
    grpc_c_client_t *client;
    grpc_c_init(GRPC_THREADS, NULL);

    client = grpc_c_client_init_by_host("127.0.0.1:9111", "strongswan", NULL,
            NULL);

    Rpc__DataRequest rq = RPC__DATA_REQUEST__INIT;
    Rpc__ResyncResponse *rsp = NULL;
    char *tap_ips, *af_ips;
    Interfaces__Interfaces__Interface *ifs[2];

    Interfaces__Interfaces__Interface tap = INTERFACES__INTERFACES__INTERFACE__INIT;
    tap.name = "tap0";
    tap.has_enabled = 1;
    tap.enabled = 1;
    tap.has_type = 1;
    tap.type = INTERFACES__INTERFACE_TYPE__TAP_INTERFACE;

    tap.tap = calloc(1, sizeof(Interfaces__Interfaces__Interface__Tap));
    interfaces__interfaces__interface__tap__init(tap.tap);
    tap.tap->host_if_name = "tap0";

    tap.n_ip_addresses = 1;
    tap.ip_addresses = &tap_ips;
    tap.ip_addresses[0] = "10.10.10.1/24";

    Interfaces__Interfaces__Interface af = INTERFACES__INTERFACES__INTERFACE__INIT;
    af.name = "wan0";
    af.has_type = 1;
    af.type = INTERFACES__INTERFACE_TYPE__AF_PACKET_INTERFACE;
    af.has_enabled = 1;
    af.enabled = 1;
    af.n_ip_addresses = 1;
    af.ip_addresses = &af_ips;
    af.ip_addresses[0] = "172.16.0.2/24";

    Interfaces__Interfaces__Interface__Afpacket af_data =
        INTERFACES__INTERFACES__INTERFACE__AFPACKET__INIT;

    af.afpacket = &af_data;
    af_data.host_if_name = "wan0";

    rq.n_interfaces = 2;
    rq.interfaces = ifs;
    rq.interfaces[0] = &tap;
    rq.interfaces[1] = &af;

    int rpc_status = rpc__data_resync_service__resync(client,
            NULL, /* metadata array */
            0, /* flags */
            &rq,
            &rsp,
            NULL /* status */,
            -1 /* timeout */);

    printf("rc: %d\n", rpc_status);

    return rpc_status;
}
