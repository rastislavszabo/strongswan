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

#define PUNT_NAME_1 "SocPunt1"
#define PUNT_NAME_2 "SocPunt2"

#define READ_PATH_1 "/etc/vpp/charon_500"
#define READ_PATH_2 "/etc/vpp/charon_4500"

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
     * maximum packet size to receive
     */
    int max_packet;

    /**
     * Write socket
     */
    struct sockaddr_un write_addr;

    /**
     * Sockets
     */
    int socks[2];

    /**
     * Configured IKEv2 port
     */
    uint16_t ports[2];

    /**
     * Array of 2 read sockets.
     * Only when we use default
     * ports 500 and 4500 they
     * are both used.
     */
    struct sockaddr_un addrs[2];

    /**
     * When ikev2 init and auth
     * are send to separate
     * ports we would need
     * to capture packets
     * on both ports (500
     * and 4500).
     */
    bool split;

    vac_t *vac;

    int rr_index;
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
    int rr, ri, count, i, bytes_read = 0;
    host_t *src = NULL, *dst = NULL;
    char buf[this->max_packet];
    packet_t *pkt;
    bool old;

    // we use 2 only if we have 2
    struct pollfd pfd[] = {
            {.fd = this->socks[0], .events = POLLIN },
            {.fd = this->socks[1], .events = POLLIN }
    };

    count =  this->split ? 2 : 1;

    DBG2(DBG_NET, "socket_vpp: waiting for packets");
    old = thread_cancelability(TRUE);
    if (poll(pfd, count, -1) <= 0)
    {
        thread_cancelability(old);
        DBG1(DBG_NET, "socket_vpp: error polling sockets");
        return FAILED;
    }
    thread_cancelability(old);

    ri = -1;
    rr = ++this->rr_index;
    this->rr_index = rr = (rr % count) != rr ? 0 : rr;

    if (!(pfd[rr].revents & POLLIN))
    {
        // do 0 -> rr and rr -> count
        for (i = 0; i < count; i++)
        {
            if (i == rr)
                continue;
            if (pfd[i].revents & POLLIN)
            {
                this->rr_index = ri = i;
                break;
            }
        }
    }
    else
    {
        ri = rr;
    }

    if (ri >= 0)
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
        msg.msg_name = this->addrs[0].sun_path;
        msg.msg_namelen = sizeof(this->addrs[0].sun_path);
        msg.msg_control = 0;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        bytes_read = recvmsg(pfd[ri].fd, &msg, 0);
        if (bytes_read < 0)
        {
            DBG1(DBG_NET, "socket_vpp: error reading data '%s'",
                 strerror(errno));
            return FAILED;
        }
        DBG3(DBG_NET, "socket_vpp: received packet '%b'", buf, bytes_read);

        raw = chunk_create(buf, bytes_read);
        packet = ip_packet_create(raw);
        if (!packet)
        {
            DBG1(DBG_NET, "socket_vpp: invalid IP packet read from vpp socket");
        }
        src = packet->get_source(packet);
        dst = packet->get_destination(packet);
        pkt = packet_create();
        pkt->set_source(pkt, src);
        pkt->set_destination(pkt, dst);

        data = packet->get_payload(packet);

        /* remove UDP header */
        data = chunk_skip(data, 8);
        pkt->set_data(pkt, chunk_clone(data));

        DBG2(DBG_NET, "socket_vpp: received packet from %#H to %#H", src, dst);
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
        src->set_port(src, this->ports[0]);
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

    DBG1(DBG_NET, "kernel_vpp: write addr: %s", this->write_addr.sun_path);

    bytes_sent = sendmsg(this->socks[0], &msg, 0);
    if (bytes_sent < 0)
    {
        DBG1(DBG_NET, "kernel_vpp: error writing: %s", strerror(errno));
        return FAILED;
    }

    return SUCCESS;
}

METHOD(socket_t, get_port, uint16_t,
    private_socket_vpp_socket_t *this, bool nat)
{
    return nat ? this->split ? this->ports[0] : this->ports[1] : this->ports[0];
}

METHOD(socket_t, supported_families, socket_family_t,
    private_socket_vpp_socket_t *this)
{
    return SOCKET_FAMILY_BOTH;
}

METHOD(socket_t, destroy, void,
    private_socket_vpp_socket_t *this)
{
    if (this->split)
    {
        close(this->socks[1]);
        unlink(this->addrs[1].sun_path);
    }
    close(this->socks[0]);
    unlink(this->addrs[0].sun_path);
    free(this);
}

static status_t register_punt_socket(vac_t *vac,
                                     uint16_t port,
                                     char *read_path,
                                     char *name)
{
    Rpc__DataRequest rq = RPC__DATA_REQUEST__INIT;
    Punt__Punt punt = PUNT__PUNT__INIT;
    Rpc__PutResponse *rp = NULL;
    Punt__Punt *punts[1];

    punt.has_port = 1;
    punt.has_l3_protocol = 1;
    punt.has_l4_protocol = 1;

    punt.name = name;
    punt.port = port;
    punt.socket_path = read_path;
    punt.l3_protocol = PUNT__L3_PROTOCOL__ALL;
    punt.l4_protocol = PUNT__L4_PROTOCOL__UDP;

    rq.n_punts = 1;
    rq.punts = punts;
    rq.punts[0] = &punt;

    /* Register punt socket for IKEv2 port in VPP */
    if (vac->put(vac, &rq, &rp) != SUCCESS)
    {
        DBG1(DBG_LIB, "socket_vpp: register punt socket faield!");
        return FAILED;
    }
    if (rp)
        rpc__put_response__free_unpacked(rp, 0);
    return SUCCESS;
}

static status_t set_addr_name(struct sockaddr_un *saddr, char *path,
                              size_t len)
{

    DBG1(DBG_LIB, "socket_vpp: path: %s", path);

    if (sizeof(saddr->sun_path) <= len)
    {
        DBG1(DBG_LIB, "socket_vpp: socket path is too long");
        return FAILED;
    }

    memset(saddr, 0, sizeof(*saddr));

    strncpy(saddr->sun_path, path, len);
    saddr->sun_family = AF_UNIX;

    return SUCCESS;
}

static status_t bind_punt_socket(private_socket_vpp_socket_t *this,
                                 struct sockaddr_un *saddr, char *path,
                                 size_t len, int port, int *out,
                                 char *punt_name)
{
    int sock;

    if (set_addr_name(saddr, path, len) != SUCCESS)
        return FAILED;

    if (register_punt_socket(this->vac, port, path, punt_name) != SUCCESS)
    {
        DBG1(DBG_LIB, "socket_vpp: error registering punt socket");
        return FAILED;
    }

    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        DBG1(DBG_LIB, "socket_vpp: opening socket failed");
        return FAILED;
    }

    unlink(saddr->sun_path);
    if (bind(sock, (struct sockaddr *)saddr,
              sizeof(*saddr)) < 0)
    {
        DBG1(DBG_LIB, "socket_vpp: binding socket failed");
        return FAILED;
    }

    *out = sock;
    return SUCCESS;
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

    if (rp->n_punt_entries < 1)
    {
        DBG1(DBG_LIB, "expected punt entry, got none!");
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

/*
 * See header for description
 */
socket_vpp_socket_t *socket_vpp_socket_create()
{
    private_socket_vpp_socket_t *this;
    char *read_path_1, *read_path_2;
    char *write_path = NULL;
    status_t rc;
    int port;

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
        .vac = lib->get(lib, "kernel-vpp-vac"),
        .max_packet = lib->settings->get_int(lib->settings, "%s.max_packet",
                                             PACKET_MAX_DEFAULT, lib->ns),
        .ports = { 500, 4500 },
        .split = FALSE,
        .rr_index = 0
    );
    
    if (!this->vac)
    {
        DBG1(DBG_LIB, "socket_vpp: vac not available (missing plugin?)");
        return NULL;
    }

    // if port is specified in charon configuration
    // both INIT and AUTH ikev2 packets will use custom
    // port and not 500 for INIT and 4500 for AUTH ofc
    // this happens only if NAT is detected.

    port = lib->settings->get_int(lib->settings, "%s.port", 0, lib->ns);
    if (port > 0)
        this->ports[0] = port;

    read_path_1 = lib->settings->get_str(lib->settings,
                        "%s.plugins.socket-vpp.path-pri",
                        READ_PATH_1, lib->ns);
    rc = bind_punt_socket(this, &(this->addrs[0]), read_path_1,
                          strlen(read_path_1), this->ports[0],
                          &(this->socks[0]), PUNT_NAME_1);
    if (SUCCESS != rc)
    {
        DBG1(DBG_LIB, "socket_vpp: error binding pri. punt socket");
        return NULL;
    }

    if (!port)
    {
        this->split = TRUE;

        read_path_2 = lib->settings->get_str(lib->settings,
                          "%s.plugins.socket-vpp.path-sec",
                          READ_PATH_2, lib->ns);
        rc = bind_punt_socket(this, &(this->addrs[1]), read_path_2,
                              strlen(read_path_2), this->ports[1],
                              &(this->socks[1]), PUNT_NAME_2);
        if (SUCCESS != rc)
        {
            DBG1(DBG_LIB, "socket_vpp: error binding sec. punt socket");
            close(this->socks[0]);
            return NULL;
        }
    }

    rc = get_vpp_socket_path(this->vac, &write_path);
    if (SUCCESS != rc)
    {
        close(this->socks[0]);
        return NULL;
    }

    rc = set_addr_name(&(this->write_addr), write_path, strlen(write_path));
    if (SUCCESS != rc)
    {
        if (this->split)
            close(this->socks[1]);
        close(this->socks[0]);
        free(write_path);
        return NULL;
    }

    DBG2(DBG_LIB, "socket_vpp: success initializing plugin");

    free(write_path);
    return &this->public;
}

