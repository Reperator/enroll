#pragma once

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <arpa/inet.h>

#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "log.h"
#include "protocol.h"

#define HOST "fulcrum.net.in.tum.de"
#define PORT 34151

#define TIME(x) (1000000 * (uint64_t) (x).tv_sec) + ((uint64_t) (x).tv_nsec / 1000)

#define USAGE \
    "Usage: enroll "\
    "-f firstname "\
    "-l lastname "\
    "-e email "\
    "-p [DHT|RPS|NSE|Onion] "\
    "[-d] "\
    "[-t team] "\
    "[-T num_threads] "\
    "[-c challenge]"\

typedef uint8_t * __attribute__((__may_alias__)) u8_a;

long get_cpus(void);

void *brute_force(void *arg);
