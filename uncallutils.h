/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __UNCALLUTILS_H_
#define __UNCALLUTILS_H_

void _uncall(void *) __attribute__((weak, alias("uncall")));
void *_uncallutils_context __attribute__((weak));

#define UNCALL() \
    if (_uncallutils_context) { _uncall(_uncallutils_context); }


void _uncallutils_init() __attribute__((weak));
void _uncallutils_deinit() __attribute__((weak));

#define UNCALL_INIT() \
    if (_uncallutils_init) { _uncallutils_init(); }
#define UNCALL_DEINIT() \
    if (_uncallutils_deinit) { _uncallutils_deinit(); }


#endif /* __UNCALLUTILS_H_ */
