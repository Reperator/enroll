#pragma once

#define ENROLL_INIT 680
#define ENROLL_REGISTER 681
#define ENROLL_SUCCESS 682
#define ENROLL_FAILURE 683

#define DHT 4963
#define RPS 15882
#define NSE 7071
#define Onion 39943

typedef struct __attribute__((__packed__)) {
    uint16_t size;
    uint16_t type;
} enroll_header;

typedef struct __attribute__((__packed__)) {
    uint64_t challenge;
} enroll_init;

typedef struct __attribute__((__packed__)) {
    uint64_t challenge;
    uint16_t team;
    uint16_t project;
    uint64_t nonce;
} enroll_register;

typedef struct __attribute__((__packed__)) {
    uint16_t reserved;
    uint16_t team;
} enroll_success;

typedef struct __attribute__((__packed__)) {
    uint16_t reserved;
    uint16_t error;
} enroll_failure;
