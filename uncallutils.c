/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "uncall.h"
#include "uncallutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define LOG_FILE "uncallutils.log"

int _uncallutils_existing = 0;

uncall_context_t *_uncallutils_context = NULL;
static int logfd;

void
_uncallutils_init() {
    static uncall_context_t context;

    if (_uncallutils_context)
        return;

    logfd = open(LOG_FILE, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (logfd < 0) {
        abort();                /* Could not open the log file. */
    }

    _uncallutils_context = &context;
    uncall_context_init(_uncallutils_context, 16, logfd);
}

void
_uncallutils_deinit() {
    if (!_uncallutils_context)
        return;

    uncall_context_destroy(_uncallutils_context);
}
