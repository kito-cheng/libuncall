/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../uncall.h"

uncall_context_t ctx;

void target() {
    uncall(&ctx);
}

void path1() {
    target();
}

void path2() {
    target();
}

int
main(int argc, const char *argv[]) {
    int i;
    int logfd;

    logfd = open("basic_flow.log", O_RDWR | O_CREAT | O_TRUNC, 0666);
    uncall_context_init(&ctx, 16, logfd);

    for (i = 0; i < 20; i++) {
        path1();
        path2();
        path1();
    }
}
