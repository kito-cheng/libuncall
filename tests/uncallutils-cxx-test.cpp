/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "../uncallutils-cxx.h"

class target {
    UNCALL_VARW<int> data1;
    UNCALL_VARW<unsigned int> data2;
public:
    void run() {
	data1 = 3;
	data2 = 4;
    }
};

void path1() {
    target a;
    a.run();
}

void path2() {
    target a;
    a.run();
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
