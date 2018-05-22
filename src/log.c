#include "log.h"

void print_hash(uint8_t *md, uint32_t md_len) {
    char md_str[2 * md_len + 1];
    for (int i = 0; i < md_len; i++)
        sprintf(&md_str[2 * i], "%02X", md[i]);
    printf(COLOR_GREEN "%s\n" COLOR_RESET, md_str);
}
