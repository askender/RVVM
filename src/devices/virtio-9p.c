/*
virtio-9p.c - virtio-mmio 9P2000.L device (plan 9 directory sharing)
Copyright (C) 2026  askender <github.com/askender>

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

/*
 * Minimal virtio-mmio (spec v2.0) transport + virtio-9p device.
 *
 * Single request queue, synchronous host-side 9P2000.L backend rooted
 * at a host directory. Guest needs CONFIG_VIRTIO_MMIO + CONFIG_NET_9P_VIRTIO:
 *
 *   mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/9p
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <rvvm/rvvm.h>
#include <rvvm/rvvm_fdt.h>
#include <rvvm/rvvm_region.h>

#include "mem_ops.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

PUSH_OPTIMIZATION_SIZE

/* ---------- virtio-mmio v2 register offsets ---------- */
#define VMM_MAGIC            0x000
#define VMM_VERSION          0x004
#define VMM_DEVID            0x008
#define VMM_VENDOR           0x00C
#define VMM_DEVFEAT          0x010
#define VMM_DEVFEAT_SEL      0x014
#define VMM_DRVFEAT          0x020
#define VMM_DRVFEAT_SEL      0x024
#define VMM_QUEUE_SEL        0x030
#define VMM_QUEUE_NUM_MAX    0x034
#define VMM_QUEUE_NUM        0x038
#define VMM_QUEUE_READY      0x044
#define VMM_QUEUE_DESC_LOW   0x080
#define VMM_QUEUE_DESC_HIGH  0x084
#define VMM_QUEUE_AVAIL_LOW  0x090
#define VMM_QUEUE_AVAIL_HIGH 0x094
#define VMM_QUEUE_USED_LOW   0x0A0
#define VMM_QUEUE_USED_HIGH  0x0A4
#define VMM_QUEUE_NOTIFY     0x050
#define VMM_IRQ_STATUS       0x060
#define VMM_IRQ_ACK          0x064
#define VMM_STATUS           0x070
#define VMM_CFG_GEN          0x0FC
#define VMM_CFG              0x100

#define VMM_MAGIC_VAL   0x74726976 /* "virt" */
#define VMM_VERSION_VAL 2
#define V9P_DEVID       9
#define VMM_VENDOR_VAL  0x564D5652 /* "RVVM" */

#define VIRTIO_F_VERSION_1 32

#define VIRTIO_STATUS_ACK      0x1
#define VIRTIO_STATUS_FAILED   0x80

#define VIRTIO_IRQ_USED_RING 0x1

#define VMM_QUEUE_MAX_NUM 64
#define VMM_CFG_SIZE      0x100

#define VMM_IRQ_BASE 0x11 /* First free PLIC line past built-ins */

/* ---------- 9P2000.L message types ---------- */
#define P9_RLERROR   7
#define P9_TSTATFS   8
#define P9_RSTATFS   9
#define P9_TLOPEN    12
#define P9_RLOPEN    13
#define P9_TLCREATE  14
#define P9_RLCREATE  15
#define P9_TGETATTR  24
#define P9_RGETATTR  25
#define P9_TSETATTR  26
#define P9_RSETATTR  27
#define P9_TREADDIR  32
#define P9_RREADDIR  33
#define P9_TREAD     116
#define P9_RREAD     117
#define P9_TWRITE    118
#define P9_RWRITE    119
#define P9_TCLUNK    120
#define P9_RCLUNK    121
#define P9_TVERSION  100
#define P9_RVERSION  101
#define P9_TATTACH   104
#define P9_RATTACH   105
#define P9_TFLUSH    108
#define P9_RFLUSH    109
#define P9_TWALK     110
#define P9_RWALK     111

#define P9_QID_DIR  0x80
#define P9_NOTAG    0xFFFF

#define P9_PROTO    "9P2000.L"
#define V9P_TAG     "hostshare"
#define V9P_MAX_MSG (256 * 1024)

/* Split virtqueue descriptor flags */
#define VRING_DESC_F_NEXT  1
#define VRING_DESC_F_WRITE 2

/* 9P fixed header: size[4] type[1] tag[2]; TWRITE adds fid[4] offset[8] count[4] */
#define P9_HDR_SIZE   7
#define P9_TWRITE_HDR (P9_HDR_SIZE + 4 + 8 + 4)

typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} vring_desc_t;

/* 9P open file (fid) */
typedef struct {
    uint32_t fid;
    char*    path;   /* Host absolute path */
    int      fd;     /* -1 when closed */
    bool     is_dir;
    bool     used;
} v9p_fid_t;

typedef struct {
    rvvm_machine_t* machine;
    rvvm_reg_dev_t* reg;
    rvvm_irq_dev_t* irq_dev;
    rvvm_irq_t      irq;

    char*    root;    /* Host share root directory */
    uint8_t  status;
    uint8_t  feat_sel;
    uint8_t  drv_sel;
    uint32_t queue_sel;
    uint32_t irq_status;
    uint64_t desc_addr, avail_addr, used_addr;
    uint32_t queue_num;
    bool     queue_ready;

    uint8_t* resp_buf;  /* 9P response scratch */
    uint8_t* req_buf;   /* 9P request scratch */
    uint8_t* walk_buf;

    v9p_fid_t* fids;
    size_t     fid_count;

    uint16_t last_used_idx;
} v9p_dev_t;

/* ---------- little-endian buffer ops ---------- */

static void v9p_put8(uint8_t** p, uint8_t v)
{
    *(*p)++ = v;
}

static void v9p_put16(uint8_t** p, uint16_t v)
{
    write_uint16_le(*p, v);
    *p += 2;
}

static void v9p_put32(uint8_t** p, uint32_t v)
{
    write_uint32_le(*p, v);
    *p += 4;
}

static void v9p_put64(uint8_t** p, uint64_t v)
{
    write_uint64_le(*p, v);
    *p += 8;
}

static uint8_t v9p_get8(const uint8_t** p)
{
    return *(*p)++;
}

static uint16_t v9p_get16(const uint8_t** p)
{
    uint16_t v = read_uint16_le(*p);
    *p += 2;
    return v;
}

static uint32_t v9p_get32(const uint8_t** p)
{
    uint32_t v = read_uint32_le(*p);
    *p += 4;
    return v;
}

static uint64_t v9p_get64(const uint8_t** p)
{
    uint64_t v = read_uint64_le(*p);
    *p += 8;
    return v;
}

/* ---------- qid & fid management ---------- */

static void v9p_qid_from_stat(uint8_t* qid, const struct stat* st)
{
    uint8_t type = S_ISDIR(st->st_mode) ? P9_QID_DIR : 0;
    write_uint8(qid, type);
    write_uint32_le(qid + 1, (uint32_t)st->st_mtime);
    write_uint64_le(qid + 5, (uint64_t)st->st_ino);
}

static v9p_fid_t* v9p_fid_alloc(v9p_dev_t* p9p, uint32_t fid, char* path, bool is_dir)
{
    for (size_t i = 0; i < p9p->fid_count; ++i) {
        if (!p9p->fids[i].used) {
            p9p->fids[i].used   = true;
            p9p->fids[i].fid    = fid;
            p9p->fids[i].path   = path;
            p9p->fids[i].fd     = -1;
            p9p->fids[i].is_dir = is_dir;
            return &p9p->fids[i];
        }
    }
    /* Grow the table (rare path) */
    size_t old = p9p->fid_count;
    size_t cnt = old ? old * 2 : 16;
    v9p_fid_t* grow = realloc(p9p->fids, cnt * sizeof(v9p_fid_t));
    if (!grow) return NULL;
    memset(grow + old, 0, (cnt - old) * sizeof(v9p_fid_t));
    p9p->fids      = grow;
    p9p->fid_count = cnt;
    p9p->fids[old] = (v9p_fid_t){ .fid = fid, .path = path, .fd = -1, .is_dir = is_dir, .used = true };
    return &p9p->fids[old];
}

static v9p_fid_t* v9p_fid_lookup(v9p_dev_t* p9p, uint32_t fid)
{
    for (size_t i = 0; i < p9p->fid_count; ++i) {
        if (p9p->fids[i].used && p9p->fids[i].fid == fid) return &p9p->fids[i];
    }
    return NULL;
}

static void v9p_fid_close_fd(v9p_fid_t* f)
{
    if (f && f->fd >= 0) {
        close(f->fd);
        f->fd = -1;
    }
}

static void v9p_fid_free(v9p_fid_t* f)
{
    if (!f) return;
    v9p_fid_close_fd(f);
    free(f->path);
    memset(f, 0, sizeof(*f));
}

/* Resolve a path under root, refusing traversal outside of it */
static char* v9p_join_path(v9p_dev_t* p9p, const char* base, const char* comp)
{
    size_t bl = strlen(base);
    size_t cl = comp ? strlen(comp) : 0;
    size_t sep = (bl && base[bl - 1] != '/') ? 1 : 0;
    char*  path = malloc(bl + sep + cl + 1);
    if (!path) return NULL;
    memcpy(path, base, bl);
    if (sep) path[bl++] = '/';
    memcpy(path + bl, comp, cl + 1);
    /* Refuse escaping the share root */
    size_t rl = strlen(p9p->root);
    if (strncmp(path, p9p->root, rl) != 0 || (path[rl] != '/' && path[rl] != '\0')) {
        free(path);
        return NULL;
    }
    return path;
}

/* ---------- 9P response helpers ---------- */

typedef struct {
    uint8_t* out;    /* Response write cursor (after size/type/tag) */
    uint8_t* hdr;    /* Response start */
    uint16_t tag;    /* Request tag to echo */
    size_t   in_len; /* Guest in-buffer capacity */
} v9p_resp_t;

static void v9p_resp_begin(v9p_resp_t* r, uint8_t type)
{
    r->hdr = r->out;
    v9p_put32(&r->out, 0);
    v9p_put8(&r->out, type);
    v9p_put16(&r->out, r->tag);
}

static void v9p_resp_send(v9p_resp_t* r)
{
    size_t written = (size_t)(r->out - r->hdr);
    rvvm_info("v9p: send written=%zu type=%02x", written, r->hdr[4]);
    size_t total   = written; /* 9P size field INCLUDES itself */
    if (total > r->in_len) {
        total = r->in_len;
    }
    write_uint32_le(r->hdr, (uint32_t)total);
}

static void v9p_rlerror(v9p_resp_t* r, uint32_t ecode)
{
    rvvm_info("v9p: Rlerror ecode=%u tag=%u", ecode, r->tag);
    v9p_resp_begin(r, P9_RLERROR);
    v9p_put32(&r->out, ecode);
    v9p_resp_send(r);
}

/* ---------- 9P handlers ---------- */

static void v9p_handle_version(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    UNUSED(p9p);
    uint32_t msize = v9p_get32(in);
    uint16_t slen  = v9p_get16(in);
    const uint8_t* ver = *in;
    *in += slen;
    rvvm_info("v9p: Tversion msize=%u ver='%.*s'", msize, slen, ver);
    if (msize > V9P_MAX_MSG) msize = V9P_MAX_MSG;
    v9p_resp_begin(r, P9_RVERSION); /* Rversion echoes NOTAG */
    r->tag = P9_NOTAG;
    v9p_put32(&r->out, msize);
    v9p_put16(&r->out, strlen(P9_PROTO));
    memcpy(r->out, P9_PROTO, strlen(P9_PROTO));
    r->out += strlen(P9_PROTO);
    v9p_resp_send(r);
}

static void v9p_handle_attach(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid = v9p_get32(in);
    v9p_get32(in); /* afid */
    uint16_t ulen = v9p_get16(in);
    *in += ulen; /* uname */
    uint16_t alen = v9p_get16(in);
    *in += alen; /* anames */
    char* root = malloc(strlen(p9p->root) + 1);
    if (!root) {
        v9p_rlerror(r, ENOMEM);
        return;
    }
    strcpy(root, p9p->root);
    struct stat st;
    if (stat(root, &st) != 0) {
        rvvm_info("v9p: attach stat failed root='%s' errno=%d", root ? root : "(null)", errno);
        free(root);
        v9p_rlerror(r, ENOENT);
        return;
    }
    v9p_fid_t* f = v9p_fid_alloc(p9p, fid, root, S_ISDIR(st.st_mode));
    if (!f) {
        rvvm_info("v9p: attach fid_alloc failed");
        free(root);
        v9p_rlerror(r, ENOMEM);
        return;
    }
    rvvm_info("v9p: attach ok fid=%u root='%s'", fid, root);
    uint8_t qid[13];
    v9p_qid_from_stat(qid, &st);
    v9p_resp_begin(r, P9_RATTACH);
    memcpy(r->out, qid, 13);
    r->out += 13;
    v9p_resp_send(r);
}

static void v9p_handle_walk(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid    = v9p_get32(in);
    uint32_t newfid = v9p_get32(in);
    uint16_t nwname = v9p_get16(in);
    v9p_fid_t* base = v9p_fid_lookup(p9p, fid);
    if (!base) {
        v9p_rlerror(r, EBADF);
        return;
    }
    char* cur = malloc(strlen(base->path) + 1);
    if (!cur) return;
    strcpy(cur, base->path);
    uint8_t* qids = p9p->walk_buf;
    size_t   qcnt = 0;
    for (uint16_t i = 0; i < nwname; ++i) {
        uint16_t clen = v9p_get16(in);
        const uint8_t* name = *in;
        *in += clen;
        char comp[256];
        if (clen >= sizeof(comp)) break;
        memcpy(comp, name, clen);
        comp[clen] = '\0';
        char* next = v9p_join_path(p9p, cur, comp);
        if (!next) break;
        struct stat st;
        if (stat(next, &st) != 0) {
            free(next);
            break;
        }
        v9p_qid_from_stat(qids + qcnt * 13, &st);
        qcnt++;
        free(cur);
        cur = next;
    }
    if (qcnt > 0 || nwname == 0) {
        /* Register newfid at the walked path (clone when nwname == 0) */
        char* path = malloc(strlen(cur) + 1);
        if (path) {
            strcpy(path, cur);
            struct stat st;
            bool is_dir = stat(path, &st) == 0 && S_ISDIR(st.st_mode);
            v9p_fid_t* nf = v9p_fid_alloc(p9p, newfid, path, is_dir);
            if (!nf) free(path);
        }
    }
    v9p_resp_begin(r, P9_RWALK);
    v9p_put16(&r->out, (uint16_t)qcnt);
    memcpy(r->out, qids, qcnt * 13);
    r->out += qcnt * 13;
    v9p_resp_send(r);
    free(cur);
}

static void v9p_handle_lopen(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid   = v9p_get32(in);
    uint32_t flags = v9p_get32(in);
    v9p_get32(in); /* mode */
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    if (!f) {
        v9p_rlerror(r, EBADF);
        return;
    }
    if (f->is_dir) {
        v9p_rlerror(r, EISDIR);
        return;
    }
    int fl = flags & 3;
    if (fl == 1) fl = O_WRONLY;
    else if (fl == 2) fl = O_RDWR;
    else fl = O_RDONLY;
    if (flags & 0x10) fl |= O_TRUNC;
    if (flags & 0x40) fl |= O_APPEND;
    v9p_fid_close_fd(f);
    f->fd = open(f->path, fl | O_CLOEXEC, 0644);
    if (f->fd < 0) {
        rvvm_info("v9p: lopen failed path='%s' flags=%o errno=%d", f->path, fl, errno);
        v9p_rlerror(r, errno);
        return;
    }
    struct stat st;
    fstat(f->fd, &st);
    uint8_t qid[13];
    v9p_qid_from_stat(qid, &st);
    v9p_resp_begin(r, P9_RLOPEN);
    memcpy(r->out, qid, 13);
    r->out += 13;
    v9p_put32(&r->out, 4096); /* iounit */
    v9p_resp_send(r);
}

static void v9p_handle_lcreate(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid    = v9p_get32(in);
    uint16_t clen   = v9p_get16(in);
    const uint8_t* name = *in;
    *in += clen;
    v9p_get32(in); /* flags */
    v9p_get32(in); /* mode */
    v9p_get32(in); /* gid */
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    if (!f) {
        v9p_rlerror(r, EBADF);
        return;
    }
    if (!f->is_dir) {
        v9p_rlerror(r, ENOTDIR);
        return;
    }
    char comp[256];
    if (clen >= sizeof(comp)) {
        v9p_rlerror(r, ENAMETOOLONG);
        return;
    }
    memcpy(comp, name, clen);
    comp[clen] = '\0';
    char* path = v9p_join_path(p9p, f->path, comp);
    if (!path) {
        v9p_rlerror(r, EACCES);
        return;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        free(path);
        v9p_rlerror(r, errno);
        return;
    }
    /* The fid is reused for the created file */
    v9p_fid_close_fd(f);
    free(f->path);
    f->path   = path;
    f->fd     = fd;
    f->is_dir = false;
    struct stat st;
    fstat(fd, &st);
    uint8_t qid[13];
    v9p_qid_from_stat(qid, &st);
    v9p_resp_begin(r, P9_RLCREATE);
    memcpy(r->out, qid, 13);
    r->out += 13;
    v9p_put32(&r->out, 4096);
    v9p_resp_send(r);
}

static void v9p_handle_getattr(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid  = v9p_get32(in);
    uint64_t mask = v9p_get64(in);
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    struct stat st;
    if (!f) {
        rvvm_info("v9p: getattr fid=%u not found", fid);
        v9p_rlerror(r, EBADF);
        return;
    }
    if (lstat(f->path, &st) != 0) {
        rvvm_info("v9p: getattr lstat failed path='%s' errno=%d", f->path, errno);
        v9p_rlerror(r, errno);
        return;
    }
    uint8_t qid[13];
    v9p_qid_from_stat(qid, &st);
    uint64_t valid = mask & 0x3FF;
    rvvm_info("v9p: getattr ok fid=%u path=%s size=%lu", fid, f->path, (unsigned long)st.st_size);
    v9p_resp_begin(r, P9_RGETATTR);
    v9p_put64(&r->out, valid);
    memcpy(r->out, qid, 13);
    r->out += 13;
    v9p_put32(&r->out, (uint32_t)st.st_mode);
    v9p_put32(&r->out, (uint32_t)st.st_uid);
    v9p_put32(&r->out, (uint32_t)st.st_gid);
    v9p_put64(&r->out, (uint64_t)st.st_nlink);
    v9p_put64(&r->out, (uint64_t)st.st_rdev);
    v9p_put64(&r->out, (uint64_t)st.st_size);
    v9p_put64(&r->out, 4096); /* blksize */
    v9p_put64(&r->out, (uint64_t)st.st_blocks);
    v9p_put64(&r->out, (uint64_t)st.st_atime);
    v9p_put64(&r->out, (uint64_t)st.st_mtime);
    v9p_put64(&r->out, (uint64_t)st.st_ctime);
    v9p_put64(&r->out, 0); /* btime_sec */
    v9p_put64(&r->out, 0); /* atime_nsec */
    v9p_put64(&r->out, 0); /* mtime_nsec */
    v9p_put64(&r->out, 0); /* ctime_nsec */
    v9p_put64(&r->out, 0); /* btime_nsec */
    v9p_put64(&r->out, 0); /* gen */
    v9p_put64(&r->out, 0); /* data_version */
    v9p_resp_send(r);
}

static void v9p_handle_setattr(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid   = v9p_get32(in);
    uint32_t valid = v9p_get32(in);
    v9p_get32(in); /* mode */
    v9p_get32(in); /* uid */
    v9p_get32(in); /* gid */
    uint64_t size  = v9p_get64(in);
    v9p_get64(in); /* atime */
    v9p_get64(in); /* mtime */
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    if (!f) {
        v9p_rlerror(r, EBADF);
        return;
    }
    if ((valid & 0x80) && truncate(f->path, (off_t)size) != 0) { /* ATTR_SIZE */
        v9p_rlerror(r, errno);
        return;
    }
    v9p_resp_begin(r, P9_RSETATTR);
    v9p_resp_send(r);
}

static void v9p_handle_readdir(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid    = v9p_get32(in);
    uint64_t offset = v9p_get64(in);
    uint32_t count  = v9p_get32(in);
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    if (!f) {
        v9p_rlerror(r, EBADF);
        return;
    }
    if (!f->is_dir) {
        v9p_rlerror(r, ENOTDIR);
        return;
    }
    if (count > V9P_MAX_MSG / 2) count = V9P_MAX_MSG / 2;
    uint8_t* dents = malloc(count ? count : 1);
    if (!dents) return;
    DIR* dir = opendir(f->path);
    if (!dir) {
        free(dents);
        v9p_rlerror(r, errno);
        return;
    }
    uint8_t* cur = dents;
    uint64_t off = 0;
    struct dirent* de;
    while ((de = readdir(dir)) != NULL) {
        if (off < offset) {
            off++;
            continue;
        }
        char* full = v9p_join_path(p9p, f->path, de->d_name);
        if (!full) break;
        struct stat st;
        if (stat(full, &st) != 0) {
            free(full);
            off++;
            continue;
        }
        free(full);
        size_t nlen = strlen(de->d_name);
        size_t need = 13 + 8 + 1 + 2 + nlen;
        if ((size_t)(cur - dents) + need > count) break;
        uint8_t qid[13];
        v9p_qid_from_stat(qid, &st);
        memcpy(cur, qid, 13);
        cur += 13;
        v9p_put64(&cur, off + 1);
        v9p_put8(&cur, S_ISDIR(st.st_mode) ? P9_QID_DIR : 0);
        v9p_put16(&cur, (uint16_t)nlen);
        memcpy(cur, de->d_name, nlen);
        cur += nlen;
        off++;
    }
    closedir(dir);
    v9p_resp_begin(r, P9_RREADDIR);
    v9p_put32(&r->out, (uint32_t)(cur - dents));
    memcpy(r->out, dents, cur - dents);
    r->out += cur - dents;
    v9p_resp_send(r);
    free(dents);
}

static void v9p_handle_read(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    uint32_t fid    = v9p_get32(in);
    uint64_t offset = v9p_get64(in);
    uint32_t count  = v9p_get32(in);
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    if (!f || f->fd < 0) {
        v9p_rlerror(r, EBADF);
        return;
    }
    if (count > r->in_len - 64) count = r->in_len - 64;
    v9p_resp_begin(r, P9_RREAD);
    v9p_put32(&r->out, 0); /* placeholder for count */
    ssize_t rd = pread(f->fd, r->out, count, (off_t)offset);
    rvvm_info("v9p: read fd=%d count=%u offset=%lu rd=%ld", f->fd, count, (unsigned long)offset, (long)rd);
    if (rd < 0) {
        rd = 0;
    }
    /* Patch the count in place */
    write_uint32_le(r->hdr + 7, (uint32_t)rd);
    r->out += rd;
    v9p_resp_send(r);
}

static void v9p_handle_write(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in,
                             const uint8_t* data, uint32_t dcount)
{
    uint32_t fid    = v9p_get32(in);
    uint64_t offset = v9p_get64(in);
    uint32_t count  = v9p_get32(in);
    v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
    if (!f || f->fd < 0) {
        v9p_rlerror(r, EBADF);
        return;
    }
    if (count > dcount) count = dcount;
    ssize_t wr = pwrite(f->fd, data, count, (off_t)offset);
    if (wr < 0) {
        v9p_rlerror(r, errno);
        return;
    }
    v9p_resp_begin(r, P9_RWRITE);
    v9p_put32(&r->out, (uint32_t)wr);
    v9p_resp_send(r);
}

static void v9p_handle_statfs(v9p_dev_t* p9p, v9p_resp_t* r, const uint8_t** in)
{
    UNUSED(in);
    struct statvfs fs;
    if (statvfs(p9p->root, &fs) != 0) {
        v9p_rlerror(r, errno);
        return;
    }
    v9p_resp_begin(r, P9_RSTATFS);
    v9p_put32(&r->out, 0x0102); /* V9FS_MAGIC */
    v9p_put32(&r->out, (uint32_t)fs.f_bsize);
    v9p_put64(&r->out, (uint64_t)fs.f_blocks);
    v9p_put64(&r->out, (uint64_t)fs.f_bfree);
    v9p_put64(&r->out, (uint64_t)fs.f_bavail);
    v9p_put64(&r->out, (uint64_t)fs.f_files);
    v9p_put64(&r->out, (uint64_t)fs.f_ffree);
    v9p_put64(&r->out, 0); /* fsid */
    v9p_put32(&r->out, (uint32_t)fs.f_namemax);
    v9p_resp_send(r);
}

/* ---------- virtqueue processing ---------- */

static bool v9p_desc_read(v9p_dev_t* p9p, uint16_t idx, vring_desc_t* desc)
{
    return rvvm_read_ram(p9p->machine, desc, p9p->desc_addr + idx * sizeof(vring_desc_t), sizeof(vring_desc_t));
}

static void v9p_queue_notify(v9p_dev_t* p9p)
{
    if (!p9p->queue_ready || p9p->queue_num == 0) return;

    while (true) {
        uint16_t avail_idx = 0;
        if (!rvvm_read_ram(p9p->machine, &avail_idx, p9p->avail_addr + 2, 2)) return;
        if (avail_idx == p9p->last_used_idx) break;

        uint16_t entry_idx = 0;
        if (!rvvm_read_ram(p9p->machine, &entry_idx, p9p->avail_addr + 4 + (p9p->last_used_idx % p9p->queue_num) * 2, 2)) break;

        /* Walk the descriptor chain: leading out buffers + trailing in buffer */
        uint8_t* out_buf = malloc(V9P_MAX_MSG);
        uint8_t* resp_buf = malloc(V9P_MAX_MSG);
        if (!out_buf || !resp_buf) {
            free(out_buf);
            free(resp_buf);
            break;
        }
        size_t   out_len = 0;
        size_t   in_cap  = 0;
        uint64_t in_addr = 0;
        uint16_t head    = entry_idx;
        uint16_t d       = head;
        vring_desc_t vd;
        bool ok = true;
        for (uint32_t guard = 0; guard < VMM_QUEUE_MAX_NUM; ++guard) {
            if (!v9p_desc_read(p9p, d, &vd)) {
                ok = false;
                break;
            }
            rvvm_info("v9p: desc[%u] addr=%llx len=%u flags=%x next=%u", d, (unsigned long long)vd.addr, vd.len, vd.flags, vd.next);
            if (vd.flags & VRING_DESC_F_WRITE) {
                /* First write descriptor: guest response buffer */
                in_addr = vd.addr;
                in_cap  = vd.len;
                break;
            }
            if (out_len + vd.len > V9P_MAX_MSG) {
                ok = false;
                break;
            }
            if (!rvvm_read_ram(p9p->machine, out_buf + out_len, vd.addr, vd.len)) {
                ok = false;
                break;
            }
            out_len += vd.len;
            if (vd.flags & VRING_DESC_F_NEXT) {
                d = vd.next;
            } else {
                break; /* Out-only chain: no room for a response, treat as error */
            }
        }
        if (!ok || in_cap < 11) { /* Minimum response: size+type+tag+small payload */
            free(out_buf);
            free(resp_buf);
            break;
        }

        /* Parse the 9P request: size[4] type[1] tag[2] */
        const uint8_t* in    = out_buf;
        v9p_get32(&in); /* msize/size field */
        uint8_t        type  = v9p_get8(&in);
        uint16_t       tag   = v9p_get16(&in);
        v9p_resp_t     r     = { .out = resp_buf, .tag = tag, .in_len = in_cap };
        const uint8_t* ddata = NULL;
        uint32_t       dcount = 0;
        if (type == P9_TWRITE && out_len >= P9_TWRITE_HDR) {
            ddata  = out_buf + P9_TWRITE_HDR;
            dcount = out_len - P9_TWRITE_HDR;
        }
        switch (type) {
            case P9_TVERSION:
                v9p_handle_version(p9p, &r, &in);
                break;
            case P9_TATTACH:
                v9p_handle_attach(p9p, &r, &in);
                break;
            case P9_TWALK:
                v9p_handle_walk(p9p, &r, &in);
                break;
            case P9_TLOPEN:
                v9p_handle_lopen(p9p, &r, &in);
                break;
            case P9_TLCREATE:
                v9p_handle_lcreate(p9p, &r, &in);
                break;
            case P9_TGETATTR:
                v9p_handle_getattr(p9p, &r, &in);
                break;
            case P9_TSETATTR:
                v9p_handle_setattr(p9p, &r, &in);
                break;
            case P9_TREADDIR:
                v9p_handle_readdir(p9p, &r, &in);
                break;
            case P9_TREAD:
                v9p_handle_read(p9p, &r, &in);
                break;
            case P9_TWRITE:
                v9p_handle_write(p9p, &r, &in, ddata, dcount);
                break;
            case P9_TSTATFS:
                v9p_handle_statfs(p9p, &r, &in);
                break;
            case P9_TCLUNK: {
                uint32_t fid = v9p_get32(&in);
                rvvm_info("v9p: Tclunk fid=%u", fid);
                v9p_fid_t* f = v9p_fid_lookup(p9p, fid);
                if (f) v9p_fid_free(f);
                rvvm_info("v9p: Tclunk freed");
                v9p_resp_begin(&r, P9_RCLUNK);
                v9p_resp_send(&r);
                rvvm_info("v9p: Tclunk resp sent");
                break;
            }
            case P9_TFLUSH:
                v9p_resp_begin(&r, P9_RFLUSH);
                v9p_resp_send(&r);
                break;
            default:
                v9p_rlerror(&r, ENOSYS);
                break;
        }

        /* Copy the response into the guest in buffer, then write the used ring */
        size_t resp_len = read_uint32_le(resp_buf); /* size field includes itself */
        if (resp_len > in_cap) resp_len = in_cap;
        rvvm_info("v9p: resp len=%zu bytes=%ph", resp_len, (const void*)resp_buf);
        rvvm_write_ram(p9p->machine, in_addr, resp_buf, resp_len);

        uint64_t used_entry = p9p->used_addr + 4 + (p9p->last_used_idx % p9p->queue_num) * 8;
        uint8_t  ue[8];
        write_uint32_le(ue, head);
        write_uint32_le(ue + 4, (uint32_t)resp_len);
        bool w_ok = rvvm_write_ram(p9p->machine, used_entry, ue, 8);
        rvvm_info("v9p: resp hex %02x %02x %02x %02x %02x %02x %02x %02x | used ok=%d idx=%u head=%u len=%u",
                  resp_buf[0], resp_buf[1], resp_buf[2], resp_buf[3], resp_buf[4], resp_buf[5], resp_buf[6], resp_buf[7],
                  (int)w_ok, p9p->last_used_idx, head, (uint32_t)resp_len);
        p9p->last_used_idx++;
        uint16_t ui = p9p->last_used_idx;
        rvvm_write_ram(p9p->machine, p9p->used_addr + 2, &ui, 2);

        /* Raise the interrupt (guest ACK clears it) */
        {
            uint8_t echo[16], ue2[16];
            memset(echo, 0xEE, sizeof(echo));
            memset(ue2, 0xDD, sizeof(ue2));
            rvvm_read_ram(p9p->machine, echo, in_addr, 12);
            rvvm_read_ram(p9p->machine, ue2, p9p->used_addr, 8);
            rvvm_info("v9p: guest echo %x %x %x %x %x %x %x %x %x %x %x %x",
                      echo[0], echo[1], echo[2], echo[3], echo[4], echo[5], echo[6], echo[7],
                      echo[8], echo[9], echo[10], echo[11]);
            rvvm_info("v9p: used ring %x %x %x %x %x %x %x %x",
                      ue2[0], ue2[1], ue2[2], ue2[3], ue2[4], ue2[5], ue2[6], ue2[7]);
        }
        p9p->irq_status |= VIRTIO_IRQ_USED_RING;
        rvvm_irq_raise(p9p->irq_dev, p9p->irq);

        free(out_buf);
        free(resp_buf);
    }
}

/* ---------- virtio-mmio register callbacks ---------- */

static uint32_t v9p_mmio_read_reg(v9p_dev_t* p9p, size_t off)
{
    switch (off) {
        case VMM_MAGIC:         return VMM_MAGIC_VAL;
        case VMM_VERSION:       return VMM_VERSION_VAL;
        case VMM_DEVID:         return V9P_DEVID;
        case VMM_VENDOR:        return VMM_VENDOR_VAL;
        case VMM_DEVFEAT:       return p9p->feat_sel == 1 ? 1 : 0x1; /* low: VIRTIO_9P_MOUNT_TAG(0); high: VERSION_1 */
        case VMM_QUEUE_NUM_MAX: return VMM_QUEUE_MAX_NUM;
        case VMM_QUEUE_READY:   return p9p->queue_ready ? 1 : 0;
        case VMM_IRQ_STATUS:    return p9p->irq_status;
        case VMM_STATUS:        rvvm_info("v9p: status read 0x%x (size handled by caller)", p9p->status); return p9p->status;
        case VMM_CFG_GEN:       return 0;
        default:                return 0;
    }
}

static void v9p_mmio_write_reg(v9p_dev_t* p9p, size_t off, uint32_t val)
{
    switch (off) {
        case VMM_DEVFEAT_SEL: p9p->feat_sel = (uint8_t)val; break;
        case VMM_DRVFEAT_SEL: p9p->drv_sel = (uint8_t)val; break;
        case VMM_QUEUE_SEL:   p9p->queue_sel = val; break;
        case VMM_QUEUE_NUM:   p9p->queue_num = val; break;
        case VMM_QUEUE_READY:
            p9p->queue_ready = (val == 1);
            if (!p9p->queue_ready) p9p->last_used_idx = 0;
            break;
        case VMM_QUEUE_DESC_LOW:   p9p->desc_addr = (p9p->desc_addr & ~0xFFFFFFFFULL) | val; break;
        case VMM_QUEUE_DESC_HIGH:  p9p->desc_addr = (p9p->desc_addr & 0xFFFFFFFFULL) | ((uint64_t)val << 32); break;
        case VMM_QUEUE_AVAIL_LOW:  p9p->avail_addr = (p9p->avail_addr & ~0xFFFFFFFFULL) | val; break;
        case VMM_QUEUE_AVAIL_HIGH: p9p->avail_addr = (p9p->avail_addr & 0xFFFFFFFFULL) | ((uint64_t)val << 32); break;
        case VMM_QUEUE_USED_LOW:   p9p->used_addr = (p9p->used_addr & ~0xFFFFFFFFULL) | val; break;
        case VMM_QUEUE_USED_HIGH:  p9p->used_addr = (p9p->used_addr & 0xFFFFFFFFULL) | ((uint64_t)val << 32); break;
        case VMM_QUEUE_NOTIFY:
            if (val == 0) v9p_queue_notify(p9p);
            break;
        case VMM_IRQ_ACK:
            p9p->irq_status &= ~val;
            if (!(p9p->irq_status & VIRTIO_IRQ_USED_RING)) rvvm_irq_lower(p9p->irq_dev, p9p->irq);
            break;
        case VMM_STATUS: p9p->status = (uint8_t)val; rvvm_info("v9p: status write 0x%x", val); break;
    }
}

static void v9p_mmio_read(rvvm_reg_dev_t* dev, void* data, size_t size, size_t off)
{
    v9p_dev_t* p9p = rvvm_region_data(dev);
    if (off >= VMM_CFG) {
        /* Device config: u16 tag length + tag string */
        uint8_t cfg[VMM_CFG_SIZE] = {0};
        write_uint16_le(cfg, strlen(V9P_TAG));
        memcpy(cfg + 2, V9P_TAG, strlen(V9P_TAG));
        if (off - VMM_CFG + size <= VMM_CFG_SIZE) {
            memcpy(data, cfg + off - VMM_CFG, size);
        }
        return;
    }
    uint32_t val = v9p_mmio_read_reg(p9p, off);
    for (size_t i = 0; i < size && i < 4; ++i) {
        write_uint8((uint8_t*)data + i, (val >> (8 * i)) & 0xFF);
    }
}

static void v9p_mmio_write(rvvm_reg_dev_t* dev, const void* data, size_t size, size_t off)
{
    v9p_dev_t* p9p = rvvm_region_data(dev);
    uint32_t val = 0;
    for (size_t i = 0; i < size && i < 4; ++i) {
        val |= ((uint32_t)read_uint8((const uint8_t*)data + i)) << (8 * i);
    }
    rvvm_info("v9p: write off=0x%x val=0x%x size=%u", (uint32_t)off, val, (uint32_t)size);
    if (off >= VMM_CFG) return; /* Config is read-only */
    v9p_mmio_write_reg(p9p, off, val);
}

static void v9p_mmio_reset(rvvm_reg_dev_t* dev)
{
    v9p_dev_t* p9p = rvvm_region_data(dev);
    p9p->status = 0;
    p9p->queue_ready = false;
    p9p->queue_num = 0;
    p9p->irq_status = 0;
    p9p->last_used_idx = 0;
    rvvm_irq_lower(p9p->irq_dev, p9p->irq);
}

static void v9p_mmio_cleanup(rvvm_reg_dev_t* dev)
{
    v9p_dev_t* p9p = rvvm_region_data(dev);
    for (size_t i = 0; i < p9p->fid_count; ++i) {
        if (p9p->fids[i].used) v9p_fid_free(&p9p->fids[i]);
    }
    free(p9p->fids);
    free(p9p->resp_buf);
    free(p9p->req_buf);
    free(p9p->walk_buf);
    free(p9p->root);
    free(p9p);
}

static const rvvm_reg_type_t v9p_mmio_type = {
    .name     = "virtio-9p",
    .read     = v9p_mmio_read,
    .write    = v9p_mmio_write,
    .reset    = v9p_mmio_reset,
    .cleanup  = v9p_mmio_cleanup,
    .min_size = 1,
    .max_size = 8,
};

/* ---------- Device init ---------- */

RVVM_PUBLIC rvvm_reg_dev_t* rvvm_virtio_9p_init(rvvm_machine_t* machine, const char* root_path, rvvm_addr_t addr)
{
    if (!root_path) return NULL;
    struct stat st;
    if (stat(root_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        rvvm_error("virtio-9p: share root \"%s\" is not a directory", root_path);
        return NULL;
    }
    v9p_dev_t* p9p = safe_new_obj(v9p_dev_t);
    p9p->machine = machine;
    p9p->root    = malloc(strlen(root_path) + 1);
    p9p->resp_buf = malloc(V9P_MAX_MSG);
    p9p->req_buf  = malloc(V9P_MAX_MSG);
    p9p->walk_buf = malloc(256 * 13);
    if (!p9p->root || !p9p->resp_buf || !p9p->req_buf || !p9p->walk_buf) {
        free(p9p->root);
        free(p9p->resp_buf);
        free(p9p->req_buf);
        free(p9p->walk_buf);
        free(p9p);
        return NULL;
    }
    strcpy(p9p->root, root_path);

    rvvm_reg_desc_t desc = {
        .addr = addr,
        .size = 0x1000,
        .data = p9p,
        .type = &v9p_mmio_type,
    };
    rvvm_reg_dev_t* dev = rvvm_region_init_auto(machine, &desc);
    if (!dev) {
        free(p9p->root);
        free(p9p->resp_buf);
        free(p9p->req_buf);
        free(p9p->walk_buf);
        free(p9p);
        return NULL;
    }

    p9p->irq_dev = rvvm_get_intc(machine);
    p9p->irq     = rvvm_irq_alloc(p9p->irq_dev, VMM_IRQ_BASE);
    rvvm_info("virtio-9p: irq line = %u", (uint32_t)p9p->irq);

    /* Device tree: virtio,mmio node */
    rvvm_fdt_node_t* soc = rvvm_get_fdt_soc(machine);
    if (soc) {
        rvvm_fdt_node_t* fdt = rvvm_fdt_init_reg("virtio_mmio", desc.addr);
        rvvm_fdt_prop_set_reg(fdt, "reg", desc.addr, desc.size);
        rvvm_fdt_prop_set_str(fdt, "compatible", "virtio,mmio");
        rvvm_fdt_prop_set_str(fdt, "status", "okay");
        rvvm_irq_fdt_describe(fdt, p9p->irq_dev, p9p->irq);
        rvvm_fdt_attach(soc, fdt);
    }

    rvvm_info("virtio-9p: sharing \"%s\" as tag \"%s\"", root_path, V9P_TAG);
    return dev;
}

POP_OPTIMIZATION_SIZE
