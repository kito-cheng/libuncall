/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "../uncallutils.h"

void target() {
    UNCALL();
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

    UNCALL_INIT();

    for (i = 0; i < 10000; i++) {
        path1();
        path2();
        path1();
    }

    UNCALL_DEINIT();
    return 0;
}
