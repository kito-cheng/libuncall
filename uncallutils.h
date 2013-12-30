/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __UNCALLUTILS_H_
#define __UNCALLUTILS_H_

#ifndef UNC_EXPORT
#define UNC_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uncall_context uncall_context_t;

extern void uncall(uncall_context_t *) UNC_EXPORT;
extern uncall_context_t * _uncallutils_context UNC_EXPORT;
extern int _uncallutils_existing UNC_EXPORT;

extern void _uncallutils_init() UNC_EXPORT;
extern void _uncallutils_deinit() UNC_EXPORT;

#ifdef __cplusplus
}
#endif

#define UNCALL()                        \
    if (_uncallutils_existing) {        \
        uncall(_uncallutils_context); \
    }


#define UNCALL_INIT() \
    if (_uncallutils_existing) { _uncallutils_init(); }
#define UNCALL_DEINIT() \
    if (_uncallutils_existing) { _uncallutils_deinit(); }


#endif /* __UNCALLUTILS_H_ */
