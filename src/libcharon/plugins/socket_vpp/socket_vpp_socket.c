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
#include "socket_vpp_socket.h"

#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <ipsec.h>
#include <daemon.h>
#include <threading/thread.h>
#include <kernel_vpp_grpc.h>
#include <ip_packet.h>

#define READ_PATH "/tmp/strongswan-uds-socket"

typedef struct private_socket_vpp_socket_t private_socket_vpp_socket_t;
typedef struct vpp_packetdesc_t vpp_packetdesc_t;
typedef struct ether_header_t ether_header_t;

/**
 * Private data of an socket_t object
 */
struct private_socket_vpp_socket_t {

    /**
     * public functions
     */
    socket_vpp_socket_t public;

    /**
     * Configured IKEv2 port
     */
    uint16_t port;

    /**
     * maximum packet size to receive
     */
    int max_packet;

    /**
     * socket
     */
    int sock;

    /**
     * Write socket
     */
    struct sockaddr_un write_addr;

    /**
     * Read socket
     */
    struct sockaddr_un read_addr;

    vac_t *vac;
};

/**
 * VPP punt socket action
 */
enum {
    PUNT_L2 = 0,
    PUNT_IP4_ROUTED,
    PUNT_IP6_ROUTED,
};

/**
 * VPP punt socket packet descriptor header
 */
struct vpp_packetdesc_t {
    /** RX or TX interface */
    u_int sw_if_index;
    /** action */
    int action;
} __attribute__((packed));

/**
 * Ethernet header
 */
struct ether_header_t {
    /** src MAC */
    uint8_t src[6];
    /** dst MAC */
    uint8_t dst[6];
    /** EtherType */
    uint16_t type;
} __attribute__((packed));

METHOD(socket_t, receiver, status_t,
    private_socket_vpp_socket_t *this, packet_t **out)
{
    char buf[this->max_packet];
    packet_t *pkt;
    host_t *src = NULL, *dst = NULL;
    int bytes_read = 0;
    bool old;
    struct pollfd pfd[] = {
            {.fd = this->sock, .events = POLLIN,},
    };

    DBG2(DBG_NET, "waiting for data on vpp sockets");
    old = thread_cancelability(TRUE);
    if (poll(pfd, countof(pfd), -1) <= 0)
    {
        thread_cancelability(old);
        DBG1(DBG_NET, "poll failed");
        return FAILED;
    }
    thread_cancelability(old);

    if (pfd[0].revents & POLLIN)
    {
        struct msghdr msg;
        struct iovec iov[3];
        vpp_packetdesc_t packetdesc;
        ether_header_t eh;
        ip_packet_t *packet;
        chunk_t raw, data;

        iov[0].iov_base = &packetdesc;
        iov[0].iov_len = sizeof(packetdesc);
        iov[1].iov_base = &eh;
        iov[1].iov_len = sizeof(eh);
        iov[2].iov_base = buf;
        iov[2].iov_len = this->max_packet;
        msg.msg_iov = iov;
        msg.msg_iovlen = 3;
        msg.msg_name = &this->read_addr;
        msg.msg_namelen = sizeof(this->read_addr);
        msg.msg_control = 0;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        bytes_read = recvmsg(pfd[0].fd, &msg, 0);
        if (bytes_read < 0)
        {
            DBG1(DBG_NET, "error reading vpp socket: %s", strerror(errno));
            return FAILED;
        }
        DBG3(DBG_NET, "received vpp packet %b", buf, bytes_read);

        raw = chunk_create(buf, bytes_read);
        packet = ip_packet_create(raw);
        if (!packet)
        {
            DBG1(DBG_NET, "invalid IP packet read from vpp socket");
        }
        src = packet->get_source(packet);
        dst = packet->get_destination(packet);
        pkt = packet_create();
        pkt->set_source(pkt, src);
        pkt->set_destination(pkt, dst);
        DBG2(DBG_NET, "received vpp packet: from %#H to %#H", src, dst);
        data = packet->get_payload(packet);
        /* remove UDP header */
        data = chunk_skip(data, 8);
        pkt->set_data(pkt, chunk_clone(data));
    }
    else
    {
        return FAILED;
    }

    *out = pkt;
    return SUCCESS;
}

METHOD(socket_t, sender, status_t,
    private_socket_vpp_socket_t *this, packet_t *packet)
{
    struct msghdr msg;
    struct iovec iov[2];
    vpp_packetdesc_t packetdesc;
    ssize_t bytes_sent;
    chunk_t data, raw;
    host_t *src, *dst;
    int family;
    ip_packet_t *ip_packet;

    src = packet->get_source(packet);
    dst = packet->get_destination(packet);
    data = packet->get_data(packet);
    if (!src->get_port(src))
    {
        src->set_port(src, this->port);
    }

    DBG2(DBG_NET, "sending vpp packet: from %#H to %#H", src, dst);

    family = dst->get_family(dst);

    packetdesc.sw_if_index = 0;
    if (family == AF_INET)
    {
        packetdesc.action = PUNT_IP4_ROUTED;
    }
    else
    {
        packetdesc.action = PUNT_IP6_ROUTED;
    }

    ip_packet = ip_packet_create_udp_from_data(src, dst, data);
    if (!ip_packet)
    {
        DBG1(DBG_NET, "create IP packet failed");
        return FAILED;
    }
    raw = ip_packet->get_encoding(ip_packet);
    memset(&msg, 0, sizeof(struct msghdr));
    iov[0].iov_base = &packetdesc;
    iov[0].iov_len = sizeof(packetdesc);
    iov[1].iov_base = raw.ptr;
    iov[1].iov_len = raw.len;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_name = &this->write_addr;
    msg.msg_namelen = sizeof(this->write_addr);
    msg.msg_flags = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    bytes_sent = sendmsg(this->sock, &msg, 0);
    if (bytes_sent < 0)
    {
        DBG1(DBG_NET, "error writing to vpp socket: %s", strerror(errno));
        return FAILED;
    }

    return SUCCESS;
}

METHOD(socket_t, get_port, uint16_t,
    private_socket_vpp_socket_t *this, bool nat)
{
    return this->port;
}

METHOD(socket_t, supported_families, socket_family_t,
    private_socket_vpp_socket_t *this)
{
    return SOCKET_FAMILY_BOTH;
}

METHOD(socket_t, destroy, void,
    private_socket_vpp_socket_t *this)
{
    close(this->sock);
    unlink(this->read_addr.sun_path);
    free(this);
}

static status_t create_and_bind_socket(private_socket_vpp_socket_t *this,
        const char *write_path, const char *read_path)
{
    status_t status = FAILED;
    memset(&this->write_addr, 0, sizeof(this->write_addr));
    strncpy(this->write_addr.sun_path, write_path,
            sizeof(this->write_addr.sun_path));

    if (this->write_addr.sun_path[sizeof(this->write_addr.sun_path) - 1] != '\0')
    {
        /* path was truncated */
        DBG1(DBG_LIB, "write socket path is too long!");
        goto out;
    }

    this->write_addr.sun_family = AF_UNIX;

    memset(&this->read_addr, 0, sizeof(this->read_addr));
    strncpy(this->read_addr.sun_path, read_path,
            sizeof(this->read_addr.sun_path));

    if (this->read_addr.sun_path[sizeof(this->read_addr.sun_path) - 1] != '\0')
    {
        /* path was truncated */
        DBG1(DBG_LIB, "read socket path is too long!");
        goto out;
    }
    this->read_addr.sun_family = AF_UNIX;

    this->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (this->sock < 0)
    {
        DBG1(DBG_LIB, "opening vpp socket failed: %m");
        goto out;
    }

    unlink(this->read_addr.sun_path);
    if (bind(this->sock, (struct sockaddr*)&this->read_addr,
                sizeof(this->read_addr)) < 0)
    {
        DBG1(DBG_LIB, "binding vpp read socket failed: %m");
        close(this->sock);
        goto out;
    }

    status = SUCCESS;
out:
    return status;
}

static status_t get_vpp_socket_path(vac_t *vac, char **path)
{
    Rpc__PuntResponse *rp = NULL;
    status_t status = FAILED;
    Rpc__PuntResponse__PuntEntry *punt;

    status = vac->dump_punts(vac, &rp);
    if (status != SUCCESS)
    {
        DBG1(DBG_LIB, "failed to dump punts from VPP!");
        goto out;
    }

    if (!rp)
        goto out;

    if (rp->n_punt_entries != 1)
    {
        DBG1(DBG_LIB, "expected a single punt entry, got: %d!",
                rp->n_punt_entries);
        goto out;
    }

    punt = rp->punt_entries[0];
    if (!punt || !punt->has_pathname)
        goto out;

    /* convert to string */
    *path = calloc(punt->pathname.len + 1, sizeof(char));
    if (*path == NULL)
    {
        DBG1(DBG_LIB, "mem alloc");
        goto out;
    }
    memcpy(*path, punt->pathname.data, punt->pathname.len);

    status = SUCCESS;
out:
    if (rp)
        rpc__punt_response__free_unpacked(rp, 0);

    return status;
}

static status_t register_punt_socket(vac_t *vac,
                                     uint16_t port,
                                     char *read_path)
{
    Rpc__DataRequest rq = RPC__DATA_REQUEST__INIT;
    Rpc__PutResponse *rp = NULL;
    status_t status;
    Punt__Punt punt = PUNT__PUNT__INIT;

    rq.n_punts = 1;
    rq.punts = calloc(1, sizeof(Punt__Punt *));
    rq.punts[0] = &punt;

    punt.has_l3_protocol = 1;
    punt.l3_protocol = PUNT__L3_PROTOCOL__ALL;
    punt.has_l4_protocol = 1;
    punt.l4_protocol = PUNT__L4_PROTOCOL__UDP;
    punt.has_port = 1;
    punt.port = port;
    punt.socket_path = read_path;

    /* Register punt socket for IKEv2 port in VPP */
    status = vac->put(vac, &rq, &rp);
    if (status != SUCCESS)
    {
        DBG1(DBG_LIB, "register vpp ip punt socket faield!");
    }
    if (rp)
        rpc__put_response__free_unpacked(rp, 0);

    free(rq.punts);
    return status;
}

/*
 * See header for description
 */
socket_vpp_socket_t *socket_vpp_socket_create()
{
    private_socket_vpp_socket_t *this;
    char *read_path;
    char *write_path = NULL;

    INIT(this,
        .public = {
            .socket = {
                .send = _sender,
                .receive = _receiver,
                .get_port = _get_port,
                .supported_families = _supported_families,
                .destroy = _destroy,
            },
        },
        .max_packet = lib->settings->get_int(lib->settings,
                            "%s.max_packet", PACKET_MAX_DEFAULT, lib->ns),
        .port = lib->settings->get_int(lib->settings, "%s.port",
                            CHARON_UDP_PORT, lib->ns),
    );

    read_path = lib->settings->get_str(lib->settings,
                        "%s.plugins.socket-vpp.path", READ_PATH, lib->ns);

    this->vac = lib->get(lib, "kernel-vpp-vac");
    if (!this->vac)
    {
        DBG1(DBG_LIB, "no vac available (plugin missing?)");
        return NULL;
    }

    status_t status = register_punt_socket(this->vac, this->port, read_path);
    if (SUCCESS != status)
        return NULL;

    status = get_vpp_socket_path(this->vac, &write_path);
    if (SUCCESS != status)
        return NULL;

    status = create_and_bind_socket(this, write_path, read_path);
    if (SUCCESS != status)
    {
        free(write_path);
        return NULL;
    }

    free(write_path);
    return &this->public;
}
