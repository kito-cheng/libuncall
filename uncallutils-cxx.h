/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __UNCALLUTILS_CXX_H_
#define __UNCALLUTILS_CXX_H_

#include "uncallutils.h"

/**
 * To collect call flows of assigning to the variable.
 *
 * Example:
 *   UNCALL_VARW<int> foo;
 *
 * Any assignments to foo would be collected of call flows.
 */
template <class T>
class UNCALL_VARW {
    T mValue;
public:
    UNCALL_VARW() {}
    UNCALL_VARW(T &aValue) {
        mValue = aValue;
    }

    UNCALL_VARW &operator =(const T &aValue) {
        UNCALL();
        mValue = aValue;
    }

    UNCALL_VARW &operator =(UNCALL_VARW &aOther) {
        UNCALL();
        mValue = aOther.mValue;
    }

    T operator ->() {
        return mValue;
    }

    operator T() const {
        return mValue;
    }
};

/**
 * To collect call flows of reading value to the variable.
 *
 * Example:
 *   UNCALL_VARW<int> foo;
 *
 * Any reading of foo would be collected of call flows.
 */
template <class T>
class UNCALL_VARR {
    T mValue;
public:
    UNCALL_VARR() {}
    UNCALL_VARR(T &aValue) {
        mValue = aValue;
    }

    UNCALL_VARR &operator =(const T &aValue) {
        mValue = aValue;
    }

    UNCALL_VARR &operator =(UNCALL_VARR &aOther) {
        mValue = aOther.mValue;
    }

    T operator ->() {
        UNCALL();
        return mValue;
    }

    operator T() const {
        UNCALL();
        return mValue;
    }
};

/**
 * To collect call flows of reading and writing value to the variable.
 */
template <class T>
class UNCALL_VARRW {
    T mValue;
public:
    UNCALL_VARRW() {}
    UNCALL_VARRW(T &aValue) {
        mValue = aValue;
    }

    UNCALL_VARRW &operator =(const T &aValue) {
        UNCALL();
        mValue = aValue;
    }

    UNCALL_VARRW &operator =(UNCALL_VARRW &aOther) {
        UNCALL();
        mValue = aOther.mValue;
    }

    T operator ->() {
        UNCALL();
        return mValue;
    }

    operator T() const {
        UNCALL();
        return mValue;
    }
};

#endif /* __UNCALLUTILS_CXX_H_ */

