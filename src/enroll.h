#pragma once

#include <inttypes.h>

typedef uint8_t * __attribute__((__may_alias__)) u8_a;

long get_cpus(void);

void *brute_force(void *arg);
