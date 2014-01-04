/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "uncall.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <link.h>

#define ELF_WORD 64
#define ELFT(t) _ELFT1(Elf,ELF_WORD,t)
#define _ELFT1(e,w,t) _ELFT(e,w,_##t)
#define _ELFT(e,w,t) e##w##t

typedef ELFT(Addr) addr_type;

#ifndef ASSERTION
#define ASSERTION(x, reason) if (!(x)) { abort(); }
#endif

#define UNC_DUP_BOOK_SIZE_START 256
#define UNC_DUP_BOOK_SIZE_MAX (256*256)
#define UNC_DUP_BOOK_BUCKET_SIZE 8

#define IO_BUF_SIZE 1024


static void
RC4_KSA(RC4_state_t *rc4, const unsigned char *key, int key_size) {
    int i, j;
    unsigned char *S = rc4->S;

    for (i = j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_size]) & 0xff;
        /* Swap S[i], S[j] */
        S[i] ^= S[j];
        S[j] ^= S[i];
        S[i] ^= S[j];
    }
}

static void
RC4_KSA_feed(RC4_state_t *rc4, const unsigned char *key, int key_size) {
    int i, j;
    int cnt;
    unsigned char *S = rc4->S;

    i = rc4->i;
    j = rc4->j;
    for (cnt = 0; cnt < key_size; cnt++) {
        j = (j + S[i] + key[i % key_size]) & 0xff;
        /* Swap S[i], S[j] */
        S[i] ^= S[j];
        S[j] ^= S[i];
        S[i] ^= S[j];

        i = (i + 1) & 0xff;
    }
    rc4->i = i;
    rc4->j = j;
}

static void
RC4_init(RC4_state_t *rc4, const unsigned char *key, int key_size) {
    int i;
    unsigned char *S = rc4->S;

    rc4->i = rc4->j = 0;
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }

    RC4_KSA(rc4, key, key_size);
}

static unsigned char
RC4_PRGA(RC4_state_t *rc4) {
    unsigned char *S = rc4->S;
    unsigned char K;

    rc4->i = (rc4->i + 1) & 0xff;
    rc4->j = (rc4->j + S[rc4->i]) & 0xff;

    /* Swap S[i], S[j] */
    S[rc4->i] ^= S[rc4->j];
    S[rc4->j] ^= S[rc4->i];
    S[rc4->i] ^= S[rc4->j];

    K = S[(S[rc4->i] + S[rc4->j]) & 0xff];

    return K;
}

static int bookmark_flow_code(uncall_context_t *ctx, uint32_t code);

static void
bookmark_grow(uncall_context_t *ctx) {
    uint32_t *old_book = ctx->dup_book;
    int old_book_size = ctx->dup_book_size;
    uint32_t *bucket;
    int i;

    ASSERTION(old_book_size < UNC_DUP_BOOK_SIZE_MAX,
              "too much collision!");

    ctx->dup_book_size = old_book_size << 2;
    ctx->dup_book = (uint32_t *)calloc(ctx->dup_book_size, sizeof(uint32_t));

    bucket = old_book;
    for (i = 0; i < old_book_size; i++, bucket++) {
        if (*bucket != 0)
            bookmark_flow_code(ctx, *bucket);
    }

    free(old_book);
}

/**
 * Check and remember if a flow is already previously existing.
 *
 * The flow code of a flow is the digest of the call flow.  It is used
 * to identify and detect if a call flow is duplicated.  The RC4
 * algorithm is used to generate the flow codes.
 *
 * \param code is the flow code of the flow.
 * \return 0 for a new flow, 1 for an existing flow.
 */
static int
bookmark_flow_code(uncall_context_t *ctx, uint32_t code) {
    uint32_t *book = ctx->dup_book;
    uint32_t *bucket = ctx->dup_book;
    int book_size = ctx->dup_book_size;
    uint32_t bucket_start = code & (book_size / UNC_DUP_BOOK_BUCKET_SIZE - 1);
    int i;

    bucket = book + bucket_start;
    for (i = 0; i < UNC_DUP_BOOK_BUCKET_SIZE; i++, bucket++) {
        if (*bucket != 0) {
            if (*bucket == code)
                return 1;
            continue;
        }
        *bucket = code;
        return 0;
    }
    /* the bucket is full */

    bookmark_grow(ctx);
    bookmark_flow_code(ctx, code);

    return 0;
}

/**
 * Write out a call flow to the log file.
 */
static void
log_flow(uncall_context_t *ctx, unw_word_t *flow, int size) {
    static const char flow_prefix[] = "FLOW: ";
    int buf_size;
    char *buf, *buf_free;
    int i, cp, data_sz;

    buf_size = size * 19 + 1;   // The max size of 0xXXXX is 18 bytes.
    buf_size += sizeof(flow_prefix) - 1;
    buf = (char*)malloc(buf_size);

    buf_free = buf;
    memcpy(buf_free, flow_prefix, sizeof(flow_prefix) - 1);
    buf_free += sizeof(flow_prefix) - 1;

    for (i = 0; i < size; i++) {
        sprintf(buf_free, "0x%lx ", flow[i]);
        cp = strlen(buf_free);
        buf_free += cp;
    }
    data_sz = buf_free - buf;

    if (data_sz > 0) {
        *(buf_free - 1) = '\n';
        write(ctx->logfd, buf, data_sz);
    }

    free(buf);
}

static int
find_so_phdr(const char *fname, ELFT(Phdr) **phdrs) {
    ELFT(Ehdr) elfhdr;
    ELFT(Phdr) *_phdrs;
    int progfd;
    int cp, offset;

    progfd = open(fname, O_RDONLY);
    if (progfd < 0) {
        return -1;
    }

    cp = read(progfd, &elfhdr, sizeof(elfhdr));
    ASSERTION(cp == sizeof(elfhdr), "IO error!");

    _phdrs = (ELFT(Phdr) *)malloc(sizeof(ELFT(Phdr)) * elfhdr.e_phnum);
    offset = lseek(progfd, elfhdr.e_phoff, SEEK_SET);
    ASSERTION(offset == elfhdr.e_phoff, "IO error!");
    cp = read(progfd, _phdrs, sizeof(ELFT(Phdr)) * elfhdr.e_phnum);
    ASSERTION(cp == sizeof(ELFT(Phdr)) * elfhdr.e_phnum, "IO error!");

    close(progfd);

    *phdrs = _phdrs;

    return elfhdr.e_phnum;;
}

static ELFT(Dyn) *
find_executable_dynamic_section() {
    extern char *program_invocation_name;
    ELFT(Phdr) *phdrs = NULL;
    ELFT(Dyn) *dyn = NULL;
    int phnum;
    int i;

    phnum = find_so_phdr(program_invocation_name, &phdrs);
    ASSERTION(phnum >= 0, "fail to load the program headers!");

    for (i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn = (ELFT(Dyn) *)phdrs[i].p_vaddr;
            break;
        }
    }

    free(phdrs);

    return dyn;
}

static struct r_debug *
find_r_debug() {
    struct r_debug *r_debug = NULL;
    ELFT(Dyn) *dyn;

    dyn = find_executable_dynamic_section();
    ASSERTION(dyn != NULL, "dlsym() error!");
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_DEBUG) {
            r_debug = (struct r_debug *)dyn->d_un.d_ptr;
            break;
        }
    }
    return r_debug;
}

/**
 * Write out memory map of the current process to the log file.
 */
static void
write_out_maps(uncall_context_t *ctx) {
    extern char *program_invocation_name;
    struct r_debug *r_debug;
    struct link_map *map;
    ELFT(Addr) addr;
    char *filename;
    int addr_buf_sz = 64;
    int addr_buf_sz_wanted;
    char *addr_buf = (char*)malloc(addr_buf_sz);
    int cp;

    r_debug = find_r_debug();
    ASSERTION(r_debug != NULL, "Can not find r_debug!");

    map = r_debug->r_map;
    while(map != NULL) {
        addr = map->l_addr;
        if (addr) {
            filename = map->l_name;
        } else {
            filename = program_invocation_name;
        }

        addr_buf_sz_wanted = (ELF_WORD / 4) + 8 + strlen(filename);
        if (addr_buf_sz < addr_buf_sz_wanted) {
            free(addr_buf);
            while (addr_buf_sz < addr_buf_sz_wanted)
                addr_buf_sz <<= 1;
            addr_buf = (char *)malloc(addr_buf_sz);
        }
#if ELF_WORD == 32
        sprintf(addr_buf, "MAP: %08x %s\n", addr, filename);
#elif ELF_WORD == 64
        sprintf(addr_buf, "MAP: %016x %s\n", addr, filename);
#else
#error "Unknown ELF_WORD size!"
#endif
        cp = write(ctx->logfd, addr_buf, addr_buf_sz_wanted - 1);
        ASSERTION(cp == (addr_buf_sz_wanted - 1),
                  "IO Error!");

        map = map->l_next;
    }

    free(addr_buf);
}

/**
 * Initialize the uncall context.
 *
 * \param max_depth is the maximum number of the frames being recoreded.
 * \param logfd is the file descriptor of the log file.
 */
void
uncall_context_init(uncall_context_t *ctx, int max_depth, int logfd) {
    static const unsigned char key[] = "libuncall";

    bzero(ctx, sizeof(uncall_context_t));

    ctx->max_depth = max_depth;
    ctx->flow_buf = (unw_word_t*)malloc(sizeof(unw_word_t) * max_depth);

    ctx->dup_book_size = UNC_DUP_BOOK_SIZE_START;
    ctx->dup_book = (uint32_t*)calloc(ctx->dup_book_size, sizeof(uint32_t));

    RC4_init(&ctx->rc4_init, key, sizeof(key));

    ctx->logfd = logfd;

    write_out_maps(ctx);
}

/**
 * Destroy the content of the uncall context.
 */
void
uncall_context_destroy(uncall_context_t *ctx) {
    free(ctx->flow_buf);
    free(ctx->dup_book);
}

/**
 * Make flow data on ctx->flow_buf and return the size.
 */
static int
construct_flow_data(uncall_context_t *ctx) {
    unw_context_t uctx;
    unw_cursor_t cursor;
    int remain_frames;
    unw_word_t ip;
    unw_word_t *flow;
    int next_flow_idx = 0;

    flow = ctx->flow_buf;

    unw_getcontext(&uctx);
    unw_init_local(&cursor, &uctx);
    remain_frames = unw_step(&cursor); /* skip current frame */
    ASSERTION(remain_frames > 0, "unwinding error!");
    remain_frames = unw_step(&cursor); /* skip uncall frame */
    ASSERTION(remain_frames >= 0, "unwinding error!");

    do {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        flow[next_flow_idx++] = ip;
        if (next_flow_idx >= ctx->max_depth)
            break;
    } while(unw_step(&cursor) > 0);

    return next_flow_idx;
}

/**
 * Log the call flow of the current thread.
 *
 * Eliminate duplications of flows, every call path would be written
 * out exactly one time.
 */
void
uncall(uncall_context_t *ctx) {
    unw_word_t *flow;
    int flow_size;
    int flow_bytes;
    RC4_state_t *rc4;
    uint32_t flow_code;
    int existing;

    flow = ctx->flow_buf;
    flow_size = construct_flow_data(ctx);

    rc4 = &ctx->rc4;
    memcpy(rc4, &ctx->rc4_init, sizeof(RC4_state_t));

    flow_bytes = sizeof(unw_word_t) * flow_size;
    RC4_KSA_feed(rc4, (const unsigned char *)flow, flow_bytes);

    /* 24bits only - considering the size of the bookmark. */
    flow_code =
        (RC4_PRGA(rc4) << 16) |
        (RC4_PRGA(rc4) << 8) |
        RC4_PRGA(rc4);
    ASSERTION(flow_code > 0,
              "The flow code is assumed unlikely to be 0."
              "  You are really unlucky!");

    existing = bookmark_flow_code(ctx, flow_code);
    if (!existing) {
        /* new one */
        log_flow(ctx, flow, flow_size);
    }
}
