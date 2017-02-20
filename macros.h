#ifndef MACROS_H
#define MACROS_H

#include <stdio.h>
#include <stdlib.h>

#ifdef DEBUG
#define DBG(...) printf (__VA_ARGS__)
#else
#define DBG(...)
#endif

#define DIE(errcode, ...) fprintf(stderr, __VA_ARGS__); exit(errcode)

#endif
