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
#include <unistd.h>
#include <utils/chunk.h>
#include <utils/debug.h>
#include <threading/thread.h>
#include <threading/mutex.h>

#include "vpp/model/rpc/rpc.grpc-c.h"
#include "kernel_vpp_net.h"
#include "kernel_vpp_grpc.h"

#define NOTIF_TYPE_UPDOWN INTERFACES__INTERFACE_NOTIFICATION__NOTIF_TYPE__UPDOWN
#define EV_STATUS_DEL INTERFACES__INTERFACES_STATE__INTERFACE__STATUS__DELETED
#define EV_STATUS_UP INTERFACES__INTERFACES_STATE__INTERFACE__STATUS__UP
#define EV_STATUS_DOWN INTERFACES__INTERFACES_STATE__INTERFACE__STATUS__DOWN

typedef struct private_kernel_vpp_net_t private_kernel_vpp_net_t;

/**
 * Private data of kernel_vpp_net implementation.
 */
struct private_kernel_vpp_net_t {

    /**
     * Public interface.
     */
    kernel_vpp_net_t public;

    /**
     * Mutex to access interface list
     */
    mutex_t *mutex;

    /**
     * Known interfaces, as iface_t
     */
    linked_list_t *ifaces;

    /**
     * Inteface update thread
     */
    thread_t *net_update;

    /**
     * TRUE if interface events enabled
     */
    bool events_on;
};

/**
 * Interface entry
 */
typedef struct {
    /** interface name */
    char if_name[64];
    /** list of known addresses, as host_t */
    linked_list_t *addrs;
    /** TRUE if up */
    bool up;
} iface_t;

/**
 * Address enumerator
 */
typedef struct {
    /** implements enumerator_t */
    enumerator_t public;
    /** what kind of address should we enumerate? */
    kernel_address_type_t which;
    /** enumerator over interfaces */
    enumerator_t *ifaces;
    /** current enumerator over addresses, or NULL */
    enumerator_t *addrs;
    /** mutex to unlock on destruction */
    mutex_t *mutex;
} addr_enumerator_t;

/**
 * FIB path entry
 */
typedef struct {
    char *if_name;
    chunk_t next_hop;
    uint32_t sw_if_index;
    uint8_t preference;
} fib_path_t;

/**
 * Get an iface entry for a local address
 */
static iface_t* address2entry(private_kernel_vpp_net_t *this, host_t *ip)
{
    enumerator_t *ifaces, *addrs;
    iface_t *entry, *found = NULL;
    host_t *host;

    ifaces = this->ifaces->create_enumerator(this->ifaces);
    while (!found && ifaces->enumerate(ifaces, &entry))
    {
        addrs = entry->addrs->create_enumerator(entry->addrs);
        while (!found && addrs->enumerate(addrs, &host))
        {
            if (host->ip_equals(host, ip))
            {
                found = entry;
            }
        }
        addrs->destroy(addrs);
    }
    ifaces->destroy(ifaces);

    return found;
}

/**
 * Add or remove a route
 */
static status_t manage_route(private_kernel_vpp_net_t *this, bool add,
                             chunk_t dst, uint8_t prefixlen, host_t *gtw,
                             char *name)
{
    int rc;
    host_t *dst_ip_addr;
    int family;
    char ippref[128];
    Rpc__DataRequest rq = RPC__DATA_REQUEST__INIT;
    Rpc__PutResponse *put_rsp = NULL;
    Rpc__DelResponse *del_rsp = NULL;
    L3__StaticRoutes__Route route = L3__STATIC_ROUTES__ROUTE__INIT;

    if (dst.len == 4)
    {
        family = AF_INET;
    }
    else if (dst.len == 16)
    {
        family = AF_INET6;
    }
    else
    {
        DBG1(DBG_KNL, "cannot determine IP family (length = %d)!", dst.len);
        return FAILED;
    }

    dst_ip_addr = host_create_from_chunk(family, dst, 0);
    if (!dst_ip_addr)
    {
        DBG1(DBG_KNL, "cannot build host address!");
        return FAILED;
    }

    route.outgoing_interface = name;
    if (snprintf(ippref, sizeof(ippref), "%H/%d", dst_ip_addr, prefixlen)
            >= sizeof(ippref))
    {
        return FAILED;
    }
    route.dst_ip_addr = ippref;
    dst_ip_addr->destroy(dst_ip_addr);

    if (gtw)
    {
        char nh_addr[INET6_ADDRSTRLEN];
        if (snprintf(nh_addr, sizeof(nh_addr), "%H", gtw) >= sizeof(nh_addr))
        {
            return FAILED;
        }
        route.next_hop_addr = nh_addr;
    }

    rq.n_staticroutes = 1;
    rq.staticroutes = calloc(1, sizeof(L3__StaticRoutes__Route *));
    rq.staticroutes[0] = &route;
    if (add)
    {
        rc = vac->put(vac, &rq, &put_rsp);
    }
    else
    {
        rc = vac->del(vac, &rq, &del_rsp);
    }
    free(rq.staticroutes);

    if (put_rsp)
        rpc__put_response__free_unpacked(put_rsp, 0);

    if (del_rsp)
        rpc__del_response__free_unpacked(del_rsp, 0);

    if (rc)
    {
        DBG1(DBG_KNL, "vac %sing route failed", add ? "add" : "remov");
        return FAILED;
    }

    return SUCCESS;
}

/**
 * Check if an address or net (addr with prefix net bits) is in
 * subnet (net with net_len net bits)
 */
static bool addr_in_subnet(chunk_t addr, int prefix, chunk_t net, int net_len)
{
    static const u_char mask[] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
    int byte = 0;

    if (net_len == 0)
    {   /* any address matches a /0 network */
        return TRUE;
    }
    if (addr.len != net.len || net_len > 8 * net.len || prefix < net_len)
    {
        return FALSE;
    }
    /* scan through all bytes in network order */
    while (net_len > 0)
    {
        if (net_len < 8)
        {
            return (mask[net_len] & addr.ptr[byte]) == (mask[net_len] & net.ptr[byte]);
        }
        else
        {
            if (addr.ptr[byte] != net.ptr[byte])
            {
                return FALSE;
            }
            byte++;
            net_len -= 8;
        }
    }
    return TRUE;
}

static status_t find_ip_route(fib_path_t *path, int prefix, host_t *dest)
{
    Rpc__RoutesResponse *rp = NULL;
    L3__StaticRoutes__Route *route;
    size_t i;
    bool is_in_sub;
    int address_len = 0;

    status_t status = vac->dump_routes(vac, &rp);
    if (SUCCESS != status)
    {
        DBG1(DBG_KNL, "failed to dump routes from VPP agent!");
        return status;
    }

    for (i = 0; i < rp->n_staticroutes; i++)
    {
        route = rp->staticroutes[i];

        host_t *net = host_create_from_subnet(route->dst_ip_addr,
                &address_len);
        if (!net)
        {
            DBG1(DBG_KNL, "failed to convert subnet: %s!", route->dst_ip_addr);
            return status;
        }
        if (net->get_family(net) != dest->get_family(dest))
        {
            net->destroy(net);
            continue;
        }

        is_in_sub = addr_in_subnet(dest->get_address(dest),
                prefix, net->get_address(net), address_len);

        if (!is_in_sub)
            continue;

        if (!route->has_type
                || route->type == L3__STATIC_ROUTES__ROUTE__ROUTE_TYPE__DROP)
            continue;

        if ((route->has_preference && route->preference < path->preference)
                || (path->if_name == NULL))
        {
            if (path->if_name)
                free(path->if_name);
            path->if_name = strdup(route->outgoing_interface);
            path->preference = route->preference;
            chunk_clear(&path->next_hop);
            host_t *tmp = host_create_from_string(route->next_hop_addr, 0);
            path->next_hop = chunk_clone(tmp->get_address(tmp));
            tmp->destroy(tmp);
        }
        net->destroy(net);
    }

    if (rp)
        rpc__routes_response__free_unpacked(rp, 0);

    return SUCCESS;
}

/**
 * Get a route: If "nexthop" the nexthop is returned, source addr otherwise
 */
static host_t *get_route(private_kernel_vpp_net_t *this, host_t *dest,
                         int prefix, bool nexthop, char **iface, host_t *src)
{
    fib_path_t path;
    host_t *addr = NULL;

    path.if_name = NULL;
    path.sw_if_index = ~0;
    path.preference = ~0;
    path.next_hop = chunk_empty;

    if (dest->get_family(dest) == AF_INET)
    {
        if (prefix == -1)
            prefix = 32;
    }
    else
    {
        if (prefix == -1)
            prefix = 128;
    }

    if (SUCCESS != find_ip_route(&path, prefix, dest))
        return NULL;

    if (path.next_hop.len)
    {
        if (nexthop)
        {
            if (iface)
                *iface = path.if_name;

            addr = host_create_from_chunk(dest->get_family(dest),
                    path.next_hop, 0);
        }
        else
        {
            if (src)
            {
                addr = src->clone(src);
            }
        }
    }

    return addr;
}

METHOD(enumerator_t, addr_enumerate, bool, addr_enumerator_t *this, va_list args)
{
    iface_t *entry;
    host_t **host;

    VA_ARGS_VGET(args, host);

    while (TRUE)
    {
        while (!this->addrs)
        {
            if (!this->ifaces->enumerate(this->ifaces, &entry))
            {
                return FALSE;
            }
            if (!entry->up && !(this->which & ADDR_TYPE_DOWN))
            {
                continue;
            }
            this->addrs = entry->addrs->create_enumerator(entry->addrs);
        }
        if (this->addrs->enumerate(this->addrs, host))
        {
            return TRUE;
        }
        this->addrs->destroy(this->addrs);
        this->addrs = NULL;
    }
}

METHOD(enumerator_t, addr_destroy, void, addr_enumerator_t *this)
{
    DESTROY_IF(this->addrs);
    this->ifaces->destroy(this->ifaces);
    this->mutex->unlock(this->mutex);
    free(this);
}

METHOD(kernel_net_t, get_interface_name, bool,
    private_kernel_vpp_net_t *this, host_t* ip, char **name)
{
    iface_t *entry;

    this->mutex->lock(this->mutex);
    entry = address2entry(this, ip);
    if (entry && name)
    {
        *name = strdup(entry->if_name);
    }
    this->mutex->unlock(this->mutex);

    return entry != NULL;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
    private_kernel_vpp_net_t *this, kernel_address_type_t which)
{
    addr_enumerator_t *enumerator;

    if (!(which & ADDR_TYPE_REGULAR))
    {
        /* we currently have no virtual, but regular IPs only */
        return enumerator_create_empty();
    }

    this->mutex->lock(this->mutex);

    INIT(enumerator,
        .public = {
            .enumerate = enumerator_enumerate_default,
            .venumerate = _addr_enumerate,
            .destroy = _addr_destroy,
        },
        .which = which,
        .ifaces = this->ifaces->create_enumerator(this->ifaces),
        .mutex = this->mutex,
    );
    return &enumerator->public;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
    private_kernel_vpp_net_t *this, host_t *dest, host_t *src)
{
    return get_route(this, dest, -1, FALSE, NULL, src);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
    private_kernel_vpp_net_t *this, host_t *dest, int prefix, host_t *src,
    char **iface)
{
    return get_route(this, dest, prefix, TRUE, iface, src);
}

METHOD(kernel_net_t, add_ip, status_t,
    private_kernel_vpp_net_t *this, host_t *virtual_ip, int prefix,
    char *iface_name)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_ip, status_t,
    private_kernel_vpp_net_t *this, host_t *virtual_ip, int prefix,
    bool wait)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_net_t, add_route, status_t,
    private_kernel_vpp_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
    host_t *gateway, host_t *src_ip, char *if_name)
{
    return manage_route(this, TRUE, dst_net, prefixlen, gateway, if_name);
}

METHOD(kernel_net_t, del_route, status_t,
    private_kernel_vpp_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
    host_t *gateway, host_t *src_ip, char *if_name)
{
    return manage_route(this, FALSE, dst_net, prefixlen, gateway, if_name);
}

static void iface_destroy(iface_t *this)
{
    this->addrs->destroy_offset(this->addrs, offsetof(host_t, destroy));
    free(this);
}

METHOD(kernel_net_t, destroy, void,
    private_kernel_vpp_net_t *this)
{
    this->net_update->cancel(this->net_update);
    this->mutex->destroy(this->mutex);
    this->ifaces->destroy_function(this->ifaces, (void*)iface_destroy);
    free(this);
}

/**
 * Update addresses for an iface entry
 */
static void update_addrs(private_kernel_vpp_net_t *this, iface_t *entry,
        Interfaces__Interfaces__Interface *iface)
{
    size_t i;
    char *addr;
    int prefix;
    linked_list_t *addrs;
    host_t *host;

    addrs = linked_list_create();
    for (i = 0; i < iface->n_ip_addresses; i++)
    {
        addr = iface->ip_addresses[i];
        if (!addr)
            continue;

        prefix = 0;
        host = host_create_from_subnet(addr, &prefix);
        addrs->insert_last(addrs, host);
    }

    entry->addrs->destroy(entry->addrs);
    entry->addrs = linked_list_create_from_enumerator(
            addrs->create_enumerator(addrs));
    addrs->destroy(addrs);
}

static void update_interfaces(private_kernel_vpp_net_t *this,
                              Rpc__InterfaceResponse *rp,
                              enumerator_t *enumerator)
{
    size_t i;
    Interfaces__Interfaces__Interface *iface;
    bool exists = FALSE;
    iface_t *entry;

    if (!rp)
        return;

    for (i = 0; i < rp->n_interfaces; i++)
    {
        iface = rp->interfaces[i];

        exists = FALSE;
        while (enumerator->enumerate(enumerator, &entry))
        {
            if (!strncmp(entry->if_name, iface->name, sizeof(entry->if_name)))
            {
                exists = TRUE;
                break;
            }
        }

        if (!exists)
        {
            INIT(entry,
                    .up = iface->enabled ? TRUE : FALSE,
                    .addrs = linked_list_create(),
            );
            strncpy(entry->if_name, iface->name, sizeof(entry->if_name));
            DBG2(DBG_KNL, "IF %s %s", entry->if_name,
                    entry->up ? "UP" : "DOWN");
            this->ifaces->insert_last(this->ifaces, entry);
        }
        update_addrs(this, entry, iface);
    }

    rpc__interface_response__free_unpacked(rp, 0);
}

static void process_iface_event(private_kernel_vpp_net_t *this,
        Rpc__NotificationsResponse *rp)
{
    Interfaces__InterfacesState__Interface *iface;
    iface_t *entry;
    enumerator_t *enumerator;

    if (!rp->nif || !rp->nif->state)
        return;

    iface = rp->nif->state;

    this->mutex->lock(this->mutex);
    enumerator = this->ifaces->create_enumerator(this->ifaces);
    while (enumerator->enumerate(enumerator, &entry))
    {
        if (!strncmp(entry->if_name, iface->name, sizeof(entry->if_name)))
        {
            int is_up = iface->admin_status == EV_STATUS_UP ? TRUE : FALSE;

            if (iface->admin_status == EV_STATUS_DEL)
            {
                this->ifaces->remove_at(this->ifaces, enumerator);
                DBG2(DBG_NET, "interface deleted %s", entry->if_name);
                iface_destroy(entry);
            }
            else if (entry->up != is_up)
            {
                entry->up = is_up;
                DBG2(DBG_NET, "interface state changed %s %s",
                     entry->if_name, entry->up ? "UP" : "DOWN");
            }
            break;
        }
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);
}

static void
event_cb(grpc_c_context_t *context, void *tag, int success)
{
    Rpc__NotificationsResponse *rp = NULL;

    do {
        if (context->gcc_stream->read(context, (void **)&rp, 0, -1)) {
            DBG1(DBG_KNL, "failed to read streaming data!");
            continue;
        }

        if (rp) {
            process_iface_event(tag, rp);
            rpc__notifications_response__free_unpacked(rp, 0);
        }

    } while(rp);
}

static status_t register_for_iface_events(private_kernel_vpp_net_t *this)
{
    status_t status;
    Rpc__NotificationRequest rq = RPC__NOTIFICATION_REQUEST__INIT;

    status = vac->register_events(vac, &rq, event_cb, this);

    return status;
}

/**
 * Inteface update thread (update interface list and interface address)
 */
static void *net_update_thread_fn(private_kernel_vpp_net_t *this)
{
    status_t rv;
    Rpc__InterfaceResponse *rp;
    enumerator_t *enumerator;

    while (1)
    {
        rp = NULL;
        status_t status = vac->dump_interfaces(vac, &rp);
        if (status == SUCCESS)
        {
            this->mutex->lock(this->mutex);
            enumerator = this->ifaces->create_enumerator(this->ifaces);
            update_interfaces(this, rp, enumerator);
            enumerator->destroy(enumerator);
            this->mutex->unlock(this->mutex);
        }

        if (!this->events_on)
        {
            rv = register_for_iface_events(this);

            if (!rv)
                this->events_on = TRUE;
        }

        sleep(5);
    }

    return NULL;
}

kernel_vpp_net_t *kernel_vpp_net_create()
{
    private_kernel_vpp_net_t *this;

    INIT(this,
        .public = {
            .interface = {
                .get_interface = _get_interface_name,
                .create_address_enumerator = _create_address_enumerator,
                .get_source_addr = _get_source_addr,
                .get_nexthop = _get_nexthop,
                .add_ip = _add_ip,
                .del_ip = _del_ip,
                .add_route = _add_route,
                .del_route = _del_route,
                .destroy = _destroy,
            },
        },
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .ifaces = linked_list_create(),
        .events_on = FALSE,
    );

    this->net_update = thread_create((thread_main_t)net_update_thread_fn, this);

    return &this->public;
}
