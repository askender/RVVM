/*
net_wasm.c - Networking backend for Emscripten builds.
Transports guest network traffic over a WebSocket relay using a
SharedArrayBuffer control block shared with the embedder's main thread.

Copyright (C) 2026  askender

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#include <emscripten.h>
#include "networking.h"

#include <emscripten.h>
#include "networking.h"
#include "utils.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

// JS transport glue (netjslib.js)
extern void  netjs_poll_wait(uint32_t wake_addr, uint32_t old_val, uint32_t timeout_ms);
extern void  netjs_notify(uint32_t wake_addr);
extern void  netjs_dns_submit(void);
extern double netjs_now_ms(void);

// ---- shared control block (mirrored by the embedder JS) ----
#define NSH_OFF_MAGIC      0x00
#define NSH_OFF_MAIN_READY 0x04
#define NSH_OFF_NET_READY  0x08
#define NSH_OFF_DOWN       0x0C
#define NSH_OFF_WAKE       0x10
#define NSH_OFF_SOCK_PTR   0x14   // u32[16]
#define NSH_OFF_SOCK_CNT   0x54
#define NSH_OFF_RELAY_URL  0x58   // char[256]
#define NSH_OFF_RELAY_LEN  0x158

#define NS_MAGIC  0x4E57534Du // "MSWN"
#define NS_MAX_SOCKS 16
#define NS_RING     8192

#define NS_KIND_TCP  0
#define NS_KIND_UDP  1
#define NS_KIND_ICMP 2

enum { NS_ST_FREE = 0, NS_ST_CONNECTING, NS_ST_OPEN, NS_ST_EOF, NS_ST_RESET, NS_ST_UDP };

struct net_sock {
    uint32_t   magic2;      // 0x4B4F5357
    uint32_t   id;
    int32_t    kind;
    int32_t    state;
    net_addr_t addr;        // remote endpoint (TCP peer / last UDP dst)
    uint32_t   rx_head, rx_tail, tx_head, tx_tail, rx_oom;
    uint8_t    rx[NS_RING];
    uint8_t    tx[NS_RING];
    uint32_t   dg_head, dg_tail;                    // UDP synth datagram queue
    struct { uint32_t used, len, src_ip; uint16_t src_port; uint8_t data[1536]; } dg[8];
};

static struct {
    uint32_t magic;
    uint32_t main_ready, net_ready, down, wake;
    uint32_t sock_ptr[NS_MAX_SOCKS];
    uint32_t sock_cnt;
    char     relay_url[256];
    uint32_t relay_len;
    struct {
        uint32_t state;     // 0 idle, 1 pending, 2 done, 3 fail
        uint32_t ip;        // spoofed source (queried server)
        uint16_t port;
        uint32_t qlen;
        uint32_t rlen;
        uint8_t  q[512];
        uint8_t  r[512];
    } dns[2];
    struct net_sock socks[NS_MAX_SOCKS];
} g_ns;

static bool g_inited = false;

static void ns_init_once(void)
{
    if (g_inited) return;
    memset(&g_ns, 0, sizeof(g_ns));
    g_ns.magic = NS_MAGIC;
    g_ns.net_ready = 1;
    for (uint32_t i = 0; i < NS_MAX_SOCKS; ++i) {
        g_ns.socks[i].magic2 = 0x4B4F5357u;
        g_ns.socks[i].id = i;
        g_ns.sock_ptr[i] = (uint32_t)(uintptr_t)&g_ns.socks[i];
    }
    g_inited = true;
    atomic_store_uint32(&g_ns.net_ready, 1);
}

static struct net_sock* ns_sock_by_id(uint32_t id)
{
    ns_init_once();
    if (id >= NS_MAX_SOCKS) return NULL;
    struct net_sock* s = &g_ns.socks[id];
    return s->magic2 == 0x4B4F5357u ? s : NULL;
}

static void ns_wake_js(void)
{
    atomic_store_uint32(&g_ns.wake, atomic_load_uint32(&g_ns.wake) + 1);
    netjs_notify((uint32_t)(uintptr_t)&g_ns.wake);
}

// ---- address globals ----
const net_addr_t net_ipv4_any_addr   = { NET_TYPE_IPV4, 0, {0} };
const net_addr_t net_ipv6_any_addr   = { NET_TYPE_IPV6, 0, {0} };
const net_addr_t net_ipv4_local_addr = { NET_TYPE_IPV4, 0, {127, 0, 0, 1} };
const net_addr_t net_ipv6_local_addr = { NET_TYPE_IPV6, 0, {0} };

size_t net_parse_ipv6(net_addr_t* addr, const char* str)
{
    UNUSED(addr); UNUSED(str);
    return 0; // IPv6 unsupported on this backend
}

size_t net_parse_ipv4(net_addr_t* addr, const char* str)
{
    uint32_t ip = 0; size_t len = 0; int oct = 0, dots = 0;
    while (str[len] && len < 16) {
        char c = str[len];
        if (c >= '0' && c <= '9') { oct = oct * 10 + (c - '0'); if (oct > 255) return 0; }
        else if (c == '.') { ip = (ip << 8) | oct; oct = 0; dots++; }
        else break;
        len++;
    }
    if (dots != 3) return 0;
    ip = (ip << 8) | oct;
    memset(addr, 0, sizeof(net_addr_t));
    addr->type = NET_TYPE_IPV4;
    addr->ip[0] = ip >> 24; addr->ip[1] = ip >> 16; addr->ip[2] = ip >> 8; addr->ip[3] = ip;
    return len;
}

size_t net_parse_addr(net_addr_t* addr, const char* str)
{
    size_t len = net_parse_ipv4(addr, str);
    if (len && str[len] == ':') {
        uint32_t port = 0; len++;
        while (str[len] >= '0' && str[len] <= '9') { port = port * 10 + (str[len] - '0'); len++; }
        addr->port = port;
    }
    return len;
}

// ---- TCP ----

net_sock_t* net_tcp_connect(const net_addr_t* dst, const net_addr_t* src, bool block)
{
    UNUSED(src); UNUSED(block);
    ns_init_once();
    struct net_sock* s = NULL;
    for (uint32_t i = 0; i < NS_MAX_SOCKS; ++i) {
        if (g_ns.socks[i].state == NS_ST_FREE) { s = &g_ns.socks[i]; break; }
    }
    if (!s) return NULL;
    memset(s->rx, 0, NS_RING); memset(s->tx, 0, NS_RING);
    s->rx_head = s->rx_tail = s->tx_head = s->tx_tail = s->rx_oom = 0;
    s->addr = *dst;
    s->kind = NS_KIND_TCP;
    s->state = NS_ST_CONNECTING;
    // The embedder pump opens the relay WebSocket when it sees CONNECTING;
    // bump wake so its poll notices the new connection early.
    atomic_store_uint32(&g_ns.wake, atomic_load_uint32(&g_ns.wake) + 1);
    netjs_notify((uint32_t)(uintptr_t)&g_ns.wake);
    return s;
}

bool net_tcp_sockpair(net_sock_t* pair[2])
{
    UNUSED(pair);
    return false; // unused on this backend
}

bool net_tcp_status(net_sock_t* sock)
{
    if (!sock || sock->kind != NS_KIND_TCP) return false;
    return sock->state == NS_ST_OPEN;
}

bool net_tcp_shutdown(net_sock_t* sock)
{
    if (!sock || sock->kind != NS_KIND_TCP) return false;
    if (sock->state == NS_ST_OPEN) {
        sock->state = NS_ST_EOF;
    }
    return true;
}

int32_t net_tcp_send(net_sock_t* sock, const void* buffer, size_t size)
{
    if (!sock || sock->kind != NS_KIND_TCP) return NET_ERR_UNKNOWN;
    if (sock->state == NS_ST_RESET) return NET_ERR_RESET;
    if (sock->state != NS_ST_OPEN) return NET_ERR_BLOCK;
    uint32_t used = (sock->tx_head - sock->tx_tail) & (NS_RING - 1);
    uint32_t room = (NS_RING - 1) - used;
    if (!room) return NET_ERR_BLOCK;
    uint32_t n = (uint32_t)EVAL_MIN(size, room);
    const uint8_t* src = (const uint8_t*)buffer;
    for (uint32_t i = 0; i < n; ++i) {
        sock->tx[(sock->tx_head + i) & (NS_RING - 1)] = src[i];
    }
    atomic_store_uint32(&sock->tx_head, sock->tx_head + n);
    return (int32_t)n;
}

int32_t net_tcp_recv(net_sock_t* sock, void* buffer, size_t size)
{
    if (!sock || sock->kind != NS_KIND_TCP) return NET_ERR_UNKNOWN;
    uint32_t avail = (sock->rx_head - sock->rx_tail) & (NS_RING - 1);
    if (!avail) {
        if (sock->state == NS_ST_EOF) return NET_ERR_DISCONNECT;
        if (sock->state == NS_ST_RESET) return NET_ERR_RESET;
        return NET_ERR_BLOCK;
    }
    uint32_t got = EVAL_MIN(size, avail);
    for (uint32_t i = 0; i < got; ++i) {
        ((uint8_t*)buffer)[i] = sock->rx[(sock->rx_tail + i) & (NS_RING - 1)];
    }
    sock->rx_tail += got;
    if (sock->state == NS_ST_EOF && sock->rx_head == sock->rx_tail) return NET_ERR_DISCONNECT;
    return (int32_t)got;
}

// Inbound listeners unsupported: relay connections are outbound-only
net_sock_t* net_tcp_listen(const net_addr_t* addr)
{
    UNUSED(addr);
    return NULL;
}

net_sock_t* net_tcp_accept(net_sock_t* listener)
{
    UNUSED(listener);
    return NULL;
}

// ---- UDP: DNS via DoH, NTP synth, other datagrams dropped ----

net_sock_t* net_udp_bind(const net_addr_t* addr)
{
    ns_init_once();
    struct net_sock* s = NULL;
    for (uint32_t i = 0; i < NS_MAX_SOCKS; ++i) {
        if (g_ns.socks[i].state == NS_ST_FREE) { s = &g_ns.socks[i]; break; }
    }
    if (!s) return NULL;
    memset(s->rx, 0, NS_RING);
    s->addr = *addr;
    s->kind = NS_KIND_UDP;
    s->state = NS_ST_UDP;
    return s;
}

size_t net_udp_send(net_sock_t* sock, const void* buffer, size_t size, const net_addr_t* addr)
{
    if (!sock || sock->kind != NS_KIND_UDP || !addr || !size) return 0;
    sock->addr = *addr;
    if (addr->port == 53) {
        // DNS: hand the query to the embedder for DoH resolution
        uint32_t slot = 0xFFFFFFFFu;
        for (uint32_t i = 0; i < 2; ++i) {
            if (g_ns.dns[i].state == 0 || g_ns.dns[i].state == 3) { slot = i; break; }
        }
        if (slot == 0xFFFFFFFFu) return size; // both slots busy: drop, guest retries
        uint32_t qlen = (uint32_t)EVAL_MIN(size, 508u);
        memcpy(g_ns.dns[slot].q, buffer, qlen);
        g_ns.dns[slot].qlen = qlen;
        g_ns.dns[slot].ip = ((uint32_t)addr->ip[0] << 24) | ((uint32_t)addr->ip[1] << 16) |
                            ((uint32_t)addr->ip[2] << 8) | (uint32_t)addr->ip[3];
        g_ns.dns[slot].port = addr->port;
        g_ns.dns[slot].state = 1; // pending
        netjs_dns_submit();
        return size;
    }
    // Other UDP (NTP etc): dropped for now
    return size;
}

static int32_t ns_udp_pop(net_sock_t* sock, void* buffer, size_t size, net_addr_t* addr)
{
    uint32_t used = (sock->dg_head - sock->dg_tail) & 7;
    if (!used) return NET_ERR_BLOCK;
    uint32_t i = sock->dg_tail & 7;
    if (!sock->dg[i].used) { sock->dg_tail++; return NET_ERR_BLOCK; }
    uint32_t len = EVAL_MIN(size, sock->dg[i].len);
    memcpy(buffer, sock->dg[i].data, len);
    memset(addr, 0, sizeof(net_addr_t));
    addr->type = NET_TYPE_IPV4;
    addr->port = sock->dg[i].src_port;
    addr->ip[0] = sock->dg[i].src_ip >> 24; addr->ip[1] = sock->dg[i].src_ip >> 16;
    addr->ip[2] = sock->dg[i].src_ip >> 8;  addr->ip[3] = sock->dg[i].src_ip;
    sock->dg[i].used = 0;
    sock->dg_tail++;
    return (int32_t)len;
}

int32_t net_udp_recv(net_sock_t* sock, void* buffer, size_t size, net_addr_t* addr)
{
    if (!sock || sock->kind != NS_KIND_UDP) return NET_ERR_UNKNOWN;
    // Deliver completed DoH responses first
    for (uint32_t i = 0; i < 2; ++i) {
        if (g_ns.dns[i].state == 2 && g_ns.dns[i].rlen) {
            uint32_t len = (uint32_t)EVAL_MIN(size, g_ns.dns[i].rlen);
            memcpy(buffer, g_ns.dns[i].r, len);
            memset(addr, 0, sizeof(net_addr_t));
            addr->type = NET_TYPE_IPV4;
            addr->port = (uint16_t)g_ns.dns[i].port;
            addr->ip[0] = g_ns.dns[i].ip >> 24; addr->ip[1] = g_ns.dns[i].ip >> 16;
            addr->ip[2] = g_ns.dns[i].ip >> 8;  addr->ip[3] = g_ns.dns[i].ip;
            g_ns.dns[i].state = 0;
            return (int32_t)len;
        }
    }
    return ns_udp_pop(sock, buffer, size, addr);
}

// ---- ICMP stubs (guest ping is unsupported) ----

net_sock_t* net_icmp_bind(const net_addr_t* addr)
{
    UNUSED(addr);
    ns_init_once();
    struct net_sock* s = NULL;
    for (uint32_t i = 0; i < NS_MAX_SOCKS; ++i) {
        if (g_ns.socks[i].state == NS_ST_FREE) { s = &g_ns.socks[i]; break; }
    }
    if (!s) return NULL;
    s->addr = *addr;
    s->kind = NS_KIND_ICMP;
    s->state = NS_ST_UDP;
    return s;
}

uint16_t net_icmp_id(net_sock_t* sock)
{
    return sock ? (uint16_t)sock->id : 0;
}

size_t net_icmp_send(net_sock_t* sock, const void* buffer, size_t size, const net_addr_t* addr)
{
    UNUSED(sock); UNUSED(buffer); UNUSED(addr);
    return size; // pretend success; no reply will come
}

int32_t net_icmp_recv(net_sock_t* sock, void* buffer, size_t size, net_addr_t* addr)
{
    UNUSED(sock); UNUSED(buffer); UNUSED(size); UNUSED(addr);
    return NET_ERR_BLOCK;
}

// ---- generic ----

net_addr_t* net_sock_addr(net_sock_t* sock)
{
    return sock ? &sock->addr : NULL;
}

uint16_t net_sock_port(net_sock_t* sock)
{
    return sock ? sock->addr.port : 0;
}

bool net_sock_set_blocking(net_sock_t* sock, bool block)
{
    UNUSED(sock); UNUSED(block);
    return true; // sockets are always non-blocking here
}

void net_sock_close(net_sock_t* sock)
{
    if (!sock) return;
    sock->state = NS_ST_FREE;
}

// ---- event poll ----

struct net_poll {
    struct net_sock* socks[32];
    void*            data[32];
    uint32_t         want[32];
    size_t           cnt;
};

net_poll_t* net_poll_create(void)
{
    struct net_poll* poll = calloc(1, sizeof(struct net_poll));
    return (net_poll_t*)poll;
}

bool net_poll_add(net_poll_t* poll, net_sock_t* sock, const net_event_t* event)
{
    struct net_poll* np = (struct net_poll*)poll;
    if (!np || !sock || np->cnt >= 32) return false;
    for (size_t i = 0; i < np->cnt; ++i) {
        if (np->socks[i] == sock) {
            np->want[i] |= event->flags;
            np->data[i] = event->data;
            return true;
        }
    }
    np->socks[np->cnt] = sock;
    np->data[np->cnt] = event->data;
    np->want[np->cnt] = event->flags;
    np->cnt++;
    return true;
}

bool net_poll_mod(net_poll_t* poll, net_sock_t* sock, const net_event_t* event)
{
    struct net_poll* np = (struct net_poll*)poll;
    if (!np || !sock) return false;
    for (size_t i = 0; i < np->cnt; ++i) {
        if (np->socks[i] == sock) {
            np->want[i] = event->flags;
            np->data[i] = event->data;
            return true;
        }
    }
    return false;
}

bool net_poll_remove(net_poll_t* poll, net_sock_t* sock)
{
    struct net_poll* np = (struct net_poll*)poll;
    if (!np || !sock) return false;
    for (size_t i = 0; i < np->cnt; ++i) {
        if (np->socks[i] == sock) {
            if (i + 1 < np->cnt) {
                memmove(&np->socks[i], &np->socks[i + 1], (np->cnt - i - 1) * sizeof(void*));
                memmove(&np->data[i], &np->data[i + 1], (np->cnt - i - 1) * sizeof(void*));
                memmove(&np->want[i], &np->want[i + 1], (np->cnt - i - 1) * sizeof(uint32_t));
            }
            np->cnt--;
            return true;
        }
    }
    return false;
}

static uint32_t ns_poll_flags(struct net_sock* s)
{
    uint32_t flags = 0;
    if (s->kind == NS_KIND_TCP) {
        uint32_t avail = (s->rx_head - s->rx_tail) & (NS_RING - 1);
        if (avail || s->state == NS_ST_EOF) flags |= NET_POLL_RECV;
        if (s->state == NS_ST_OPEN) flags |= NET_POLL_SEND;
        if (s->state == NS_ST_RESET) flags |= NET_POLL_RECV;
    } else if (s->kind == NS_KIND_UDP) {
        for (uint32_t i = 0; i < 2; ++i) {
            if (g_ns.dns[i].state == 2 && g_ns.dns[i].rlen) flags |= NET_POLL_RECV;
        }
        uint32_t used = (s->dg_head - s->dg_tail) & 7;
        if (used) flags |= NET_POLL_RECV;
    }
    return flags;
}

static size_t ns_collect(struct net_poll* np, net_event_t* events, size_t size)
{
    size_t n = 0;
    for (size_t i = 0; i < np->cnt && n < size; ++i) {
        uint32_t flags = ns_poll_flags(np->socks[i]) & np->want[i];
        if (flags) {
            events[n].flags = flags;
            events[n].data = np->data[i];
            n++;
        }
    }
    return n;
}

size_t net_poll_wait(net_poll_t* poll, net_event_t* events, size_t size, uint32_t wait_ms)
{
    struct net_poll* np = (struct net_poll*)poll;
    size_t n = ns_collect(np, events, size);
    if (n || atomic_load_uint32(&g_ns.down)) return n;
    uint32_t wake_addr = (uint32_t)(uintptr_t)&g_ns.wake;
    while (wait_ms) {
        uint32_t old = atomic_load_uint32(&g_ns.wake);
        n = ns_collect(np, events, size);
        if (n) return n;
        uint32_t chunk = EVAL_MIN(wait_ms, 190);
        netjs_poll_wait(wake_addr, old, chunk);
        wait_ms -= chunk;
        n = ns_collect(np, events, size);
        if (n) return n;
    }
    return 0;
}

void net_poll_close(net_poll_t* poll)
{
    free(poll);
}

// ---- Layout exports for the embedder JS transport ----
// Field offsets are exported (not hardcoded in JS) to prevent drift.

EMSCRIPTEN_KEEPALIVE uint32_t rvvm_net_shm(void)
{
    ns_init_once();
    atomic_store_uint32(&g_ns.main_ready, 1);
    return (uint32_t)(uintptr_t)&g_ns;
}

EMSCRIPTEN_KEEPALIVE uint32_t rvvm_net_shm_size(void)
{
    return (uint32_t)sizeof(g_ns);
}

EMSCRIPTEN_KEEPALIVE uint32_t rvvm_net_stride(void)
{
    return (uint32_t)sizeof(struct net_sock);
}

EMSCRIPTEN_KEEPALIVE uint32_t rvvm_net_off(uint32_t which)
{
    switch (which) {
    case 0: return (uint32_t)offsetof(struct net_sock, magic2);
    case 1: return (uint32_t)offsetof(struct net_sock, state);
    case 2: return (uint32_t)offsetof(struct net_sock, addr);
    case 3: return (uint32_t)offsetof(struct net_sock, addr.port);
    case 4: return (uint32_t)offsetof(struct net_sock, rx_head);
    case 5: return (uint32_t)offsetof(struct net_sock, rx_tail);
    case 6: return (uint32_t)offsetof(struct net_sock, tx_head);
    case 7: return (uint32_t)offsetof(struct net_sock, tx_tail);
    case 8: return (uint32_t)offsetof(struct net_sock, rx_oom);
    case 9: return (uint32_t)offsetof(struct net_sock, rx);
    case 10: return (uint32_t)offsetof(struct net_sock, tx);
    }
    return 0;
}
