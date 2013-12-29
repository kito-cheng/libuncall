/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __UNCALLUTILS_H_
#define __UNCALLUTILS_H_

typedef struct uncall_context uncall_context_t;

extern void uncall(uncall_context_t *);
extern uncall_context_t *_uncallutils_context;
extern int _uncallutils_existing;

#define UNCALL()                      \
    if (_uncallutils_existing) {      \
        uncall(_uncallutils_context); \
    }


extern void _uncallutils_init();
extern void _uncallutils_deinit();

#define UNCALL_INIT() \
    if (_uncallutils_existing) { _uncallutils_init(); }
#define UNCALL_DEINIT() \
    if (_uncallutils_existing) { _uncallutils_deinit(); }


#endif /* __UNCALLUTILS_H_ */
