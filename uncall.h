/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __UNCALL_H_
#define __UNCALL_H_

#include <stdint.h>
#include <libunwind.h>


struct RC4_state {
    int i, j;
    unsigned char S[256];
};

typedef struct RC4_state RC4_state_t;

struct hash {
    int size;
    uint32_t *codes;
};
typedef struct hash hash_t;


struct r_debug;

struct uncall_context {
    struct r_debug *r_debug;

    int max_depth;
    unw_word_t *flow_buf;

    hash_t flows_dup;
    hash_t maps_dup;

    RC4_state_t rc4_init;    /* initial state of rc4 */
    RC4_state_t rc4;         /* copied from rc4_init for every flow */

    int logfd;
};

typedef struct uncall_context uncall_context_t;

void uncall_context_init(uncall_context_t *ctx, int max_depth, int logfd);
void uncall_context_destroy(uncall_context_t *ctx);
void uncall(uncall_context_t *ctx);

#endif /* __UNCALL_H_ */
