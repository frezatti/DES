#ifndef DES_BYTES_H
#define DES_BYTES_H

#include <stdint.h>

/* Big-endian 64-bit load/store */
static inline uint64_t load_be64(const uint8_t b[8])
{
    return ((uint64_t) b[0] << 56) | ((uint64_t) b[1] << 48) | ((uint64_t) b[2] << 40) |
           ((uint64_t) b[3] << 32) | ((uint64_t) b[4] << 24) | ((uint64_t) b[5] << 16) |
           ((uint64_t) b[6] << 8) | (uint64_t) b[7];
}

static inline void store_be64(uint64_t x, uint8_t b[8])
{
    b[0] = (uint8_t) (x >> 56);
    b[1] = (uint8_t) (x >> 48);
    b[2] = (uint8_t) (x >> 40);
    b[3] = (uint8_t) (x >> 32);
    b[4] = (uint8_t) (x >> 24);
    b[5] = (uint8_t) (x >> 16);
    b[6] = (uint8_t) (x >> 8);
    b[7] = (uint8_t) (x);
}

/* Optional 32-bit versions */
static inline uint32_t load_be32(const uint8_t b[4])
{
    return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8) |
           (uint32_t) b[3];
}

static inline void store_be32(uint32_t x, uint8_t b[4])
{
    b[0] = (uint8_t) (x >> 24);
    b[1] = (uint8_t) (x >> 16);
    b[2] = (uint8_t) (x >> 8);
    b[3] = (uint8_t) (x);
}

#endif /* DES_BYTES_H */
