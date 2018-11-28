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
#include <library.h>
#include <utils/debug.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <collections/array.h>
#include <collections/hashtable.h>

#include "vpp/model/rpc/rpc.grpc-c.h"
#include "kernel_vpp_grpc.h"

#define VPP_AGENT_DEFAULT_HOST "localhost:9111"

typedef struct private_vac_t private_vac_t;

/**
 * VPP-agent client (gRPC based)
 */
vac_t *vac;

/**
 * Private variables and functions of vac_t class.
 */
struct private_vac_t {

    /**
     * public part of the vac_t object.
     */
    vac_t public;

    grpc_c_client_t *grpc_client;

    const char *host;
};

METHOD(vac_t, vac_put, status_t, private_vac_t *this,
        Rpc__DataRequest *rq, Rpc__PutResponse **rp)
{
    int rpc_status = rpc__data_change_service__put (this->grpc_client,
            NULL, /* metadata array */
            0, /* flags */
            rq,
            rp,
            NULL /* status */,
            -1 /* timeout */);

    return rpc_status ? FAILED : SUCCESS;
}

METHOD(vac_t, vac_del, status_t, private_vac_t *this,
        Rpc__DataRequest *rq, Rpc__DelResponse **rp)
{
    int rpc_status = rpc__data_change_service__del (this->grpc_client,
            NULL, /* metadata array */
            0, /* flags */
            rq,
            rp,
            NULL /* status */,
            -1 /* timeout */);

    return rpc_status ? FAILED : SUCCESS;
}

METHOD(vac_t, vac_dump_interfaces, status_t, private_vac_t *this,
        Rpc__DumpRequest *rq, Rpc__InterfaceResponse **rp)
{
    int rpc_status = rpc__data_dump_service__dump_interfaces(this->grpc_client,
            NULL, /* metadata array */
            0, /* flags */
            rq,
            rp,
            NULL /* status */,
            -1 /* timeout */);
    return rpc_status ? FAILED : SUCCESS;
}

METHOD(vac_t, vac_dump_routes, status_t, private_vac_t *this,
        Rpc__DumpRequest *rq, Rpc__RoutesResponse **rp)
{
    int rpc_status = rpc__data_dump_service__dump_routes(
            this->grpc_client,
            NULL, /* metadata array */
            0, /* flags */
            rq,
            rp,
            NULL /* status */,
            -1 /* timeout */);
    return rpc_status ? FAILED : SUCCESS;
}

METHOD(vac_t, vac_dump_fibs, status_t, private_vac_t *this,
        Rpc__DumpRequest *rq, Rpc__FibResponse **rp)
{
    int rpc_status = rpc__data_dump_service__dump_fibs(
            this->grpc_client,
            NULL, /* metadata array */
            0, /* flags */
            rq,
            rp,
            NULL /* status */,
            -1 /* timeout */);
    return rpc_status ? FAILED : SUCCESS;
}

METHOD(vac_t, vac_dump_ipsec_tunnels, status_t, private_vac_t *this,
        Rpc__DumpRequest *rq, Rpc__IPSecTunnelResponse **rp)
{
    int rpc_status = rpc__data_dump_service__dump_ipsec_tunnels(
            this->grpc_client,
            NULL, /* metadata array */
            0, /* flags */
            rq,
            rp,
            NULL /* status */,
            -1 /* timeout */);
    return rpc_status ? FAILED : SUCCESS;
}


METHOD(vac_t, destroy, void, private_vac_t *this)
{
    grpc_c_client_free(this->grpc_client);
}

vac_t *vac_create(char *name)
{
    private_vac_t *this;

    INIT(this,
        .public = {
            .put = _vac_put,
            .del = _vac_del,
            .destroy = _destroy,
            .dump_interfaces = _vac_dump_interfaces,
            .dump_routes = _vac_dump_routes,
            .dump_fibs = _vac_dump_fibs,
            .dump_ipsec_tunnels = _vac_dump_ipsec_tunnels,
        },
        .host = lib->settings->get_str(lib->settings,
            "%s.plugins.kernel-vpp.host",
            VPP_AGENT_DEFAULT_HOST, lib->ns),
    );

    this->grpc_client = grpc_c_client_init_by_host(this->host,
            name, NULL, NULL);

    if (!this->grpc_client)
    {
        DBG1(DBG_KNL, "cannot connect to gRPC host: %s!", this->host);
        return NULL;
    }

    vac = &this->public;
    return &this->public;
}
