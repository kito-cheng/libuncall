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

#define FLOWS_DUP_START_SIZE 256
#define MAPS_DUP_START_SIZE 64

#define HASH_SIZE_MAX (256*256)
#define HASH_BUCKET_SIZE 8

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

static int hash_put(hash_t *hash, uint32_t code);

static void
hash_grow(hash_t *hash) {
    int old_size = hash->size;
    uint32_t *old_codes = hash->codes;
    uint32_t *bucket;
    int i;

    ASSERTION(old_size < HASH_SIZE_MAX, "The hash has too much collision!");

    hash->size = old_size << 2;
    hash->codes = (uint32_t *)calloc(hash->size, sizeof(uint32_t));

    bucket = old_codes;
    for (i = 0; i < old_size; i++, bucket++) {
        if (*bucket != 0) {
            hash_put(hash, *bucket);
        }
    }

    free(old_codes);
}

static int
hash_put(hash_t *hash, uint32_t code) {
    int bucket_i = code & (hash->size / HASH_BUCKET_SIZE - 1);
    uint32_t *bucket = hash->codes + (bucket_i * HASH_BUCKET_SIZE);
    int i;

    for (i = 0; i < HASH_BUCKET_SIZE; i++, bucket++) {
        if (*bucket == 0) {
            *bucket = code;
            return 0;
        } else if (*bucket == code) {
            return 1;
        }
    }
    /* The bucket is full. */
    hash_grow(hash);
    hash_put(hash, code);
    return 0;
}

static void
hash_init(hash_t *hash, int start_size) {
    hash->size = start_size;
    hash->codes = (uint32_t *)calloc(hash->size, sizeof(uint32_t));
}

static void
hash_deinit(hash_t *hash) {
    free(hash->codes);
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
    ASSERTION(dyn != NULL, "fail to get dynamic section!");
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_DEBUG) {
            r_debug = (struct r_debug *)dyn->d_un.d_ptr;
            break;
        }
    }
    return r_debug;
}

/**
 * Compute digest code for a link map.
 *
 * It may be not good, but it is fast and the number of link_map is
 * small.  I don't go to fix it until someday and someone's crying.
 * Let's bless no confliction.
 */
static uint32_t
link_map_digest_code(struct link_map *map) {
    addr_type addr = map->l_addr;
    uint32_t code;

    code = addr ^ (addr >> 8) ^ 0xdadbeef;
    code = code ^ (addr >> 16);
#if ELF_WORD == 64
    code = code ^ (addr >> 32);
#endif
    ASSERTION(code != 0, "bad link map digest!");

    return code;
}

/**
 * Write out memory map of the current process to the log file.
 * Write out only new link maps of the process.
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
    uint32_t code;
    int existing;
    int cp;

    r_debug = ctx->r_debug;
    ASSERTION(r_debug != NULL, "Can not find r_debug!");

    map = r_debug->r_map;
    while(map != NULL) {
        addr = map->l_addr;
        if (addr) {
            filename = map->l_name;
        } else {
            filename = program_invocation_name;
        }

        code = link_map_digest_code(map);
        existing = hash_put(&ctx->maps_dup, code);
        if (existing) {
            map = map->l_next;
            continue;
        }

        addr_buf_sz_wanted = (ELF_WORD / 4) + 8 + strlen(filename);
        if (addr_buf_sz < addr_buf_sz_wanted) {
            free(addr_buf);
            while (addr_buf_sz < addr_buf_sz_wanted)
                addr_buf_sz <<= 1;
            addr_buf = (char *)malloc(addr_buf_sz);
        }
#if ELF_WORD == 32
        sprintf(addr_buf, "MAP: %08lx %s\n", addr, filename);
#elif ELF_WORD == 64
        sprintf(addr_buf, "MAP: %016llx %s\n", addr, filename);
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

    ctx->r_debug = find_r_debug();

    ctx->max_depth = max_depth;
    ctx->flow_buf = (unw_word_t*)malloc(sizeof(unw_word_t) * max_depth);

    hash_init(&ctx->flows_dup, FLOWS_DUP_START_SIZE);
    hash_init(&ctx->maps_dup, MAPS_DUP_START_SIZE);

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
    hash_deinit(&ctx->flows_dup);
    hash_deinit(&ctx->maps_dup);
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
    uint32_t flow_code;         /* the digest of the call flow */
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

    /* Make sure this call flow is not ths same as any exisiting one. */
    existing = hash_put(&ctx->flows_dup, flow_code);
    if (!existing) {
        /*
         * Write out new link maps if there is.  A better solution is
         * to check link maps once any new shared object is loaded or
         * unloaded.  We could hook-up the function of r_debug::r_brk,
         * but it should leverage breakpoints and signal handlers that
         * is laborious.  Let's left it to someday future.
         */
        write_out_maps(ctx);

        /* new one */
        log_flow(ctx, flow, flow_size);
    }
}
