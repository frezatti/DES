#include "des.h"
#include "des_tables.h"
#include <limits.h>

_Static_assert(sizeof(uint64_t) * 8 == 64, "Requires 64-bit uint64_t");

static inline uint64_t des_permute64(uint64_t x, const uint8_t tbl[64])
{
    uint64_t y = 0;
    for (int i = 0; i < 64; ++i) {
        uint64_t bit = (x >> (64 - tbl[i])) & 1ULL;
        y |= bit << (63 - i);
    }
    return y;
}

static inline uint64_t des_expand32_to_48(uint32_t r, const uint8_t tbl[48])
{
    uint64_t y = 0;
    for (int i = 0; i < 48; ++i) {
        uint64_t bit = (uint64_t) ((r >> (32 - tbl[i])) & 1U);
        y |= bit << (47 - i);
    }
    return y;
}

static inline uint32_t des_permute32(uint32_t x, const uint8_t tbl[32])
{
    uint32_t y = 0;
    for (int i = 0; i < 32; ++i) {
        uint32_t bit = (x >> (32 - tbl[i])) & 1U;
        y |= bit << (31 - i);
    }
    return y;
}

static inline uint32_t des_sboxes(uint64_t x48)
{
    uint32_t out = 0;
    for (int i = 0; i < 8; ++i) {
        int shift        = 42 - 6 * i;
        uint8_t six      = (uint8_t) ((x48 >> shift) & DES_MASK_6);
        uint8_t row      = (uint8_t) (((six & 0x20) >> 4) | (six & 0x01));
        uint8_t col      = (uint8_t) ((six >> 1) & 0x0F);
        const uint8_t* S = (i == 0)   ? DES_S1
                           : (i == 1) ? DES_S2
                           : (i == 2) ? DES_S3
                           : (i == 3) ? DES_S4
                           : (i == 4) ? DES_S5
                           : (i == 5) ? DES_S6
                           : (i == 6) ? DES_S7
                                      : DES_S8;
        uint8_t val      = S[(row << 4) | col];
        out              = (out << 4) | (uint32_t) val;
    }
    return out;
}

static inline uint32_t des_f(uint32_t r, uint64_t k48)
{
    uint64_t e = des_expand32_to_48(r, DES_E);
    uint64_t x = e ^ (k48 & DES_MASK_48);
    uint32_t s = des_sboxes(x);
    return des_permute32(s, DES_P);
}

uint64_t des_encrypt_block(uint64_t block, const uint64_t subkeys[16])
{
    uint64_t ip = des_permute64(block, DES_IP);
    uint32_t L  = (uint32_t) (ip >> 32);
    uint32_t R  = (uint32_t) (ip);

    for (int i = 0; i < 16; ++i) {
        uint32_t L_next = R;
        uint32_t R_next = L ^ des_f(R, subkeys[i]);
        L               = L_next;
        R               = R_next;
    }

    uint64_t preout = ((uint64_t) R << 32) | (uint64_t) L;
    return des_permute64(preout, DES_IP_INV);
}

uint64_t des_decrypt_block(uint64_t block, const uint64_t subkeys[16])
{
    uint64_t ip = des_permute64(block, DES_IP);
    uint32_t L  = (uint32_t) (ip >> 32);
    uint32_t R  = (uint32_t) (ip);

    for (int i = 15; i >= 0; --i) {
        uint32_t L_next = R;
        uint32_t R_next = L ^ des_f(R, subkeys[i]);
        L               = L_next;
        R               = R_next;
    }

    uint64_t preout = ((uint64_t) R << 32) | (uint64_t) L;
    return des_permute64(preout, DES_IP_INV);
}

static inline uint64_t des_permute64_to_56(uint64_t x, const uint8_t tbl[56])
{
    uint64_t y = 0;
    for (int i = 0; i < 56; ++i) {
        uint64_t bit = (x >> (64 - tbl[i])) & 1ULL;
        y |= bit << (55 - i); /* pack into low 56 bits */
    }
    return y;
}

static inline uint64_t des_permute56_to_48(uint64_t x56, const uint8_t tbl[48])
{
    uint64_t y = 0;
    for (int i = 0; i < 48; ++i) {
        uint64_t bit = (x56 >> (56 - tbl[i])) & 1ULL;
        y |= bit << (47 - i); /* pack into low 48 bits */
    }
    return y;
}

static inline uint32_t rotl28(uint32_t x, int r)
{
    x &= 0x0FFFFFFFU;
    return ((x << r) | (x >> (28 - r))) & 0x0FFFFFFFU;
}

void des_key_schedule(uint64_t key64, uint64_t subkeys[16])
{
    /* Drop parity and permute with PC-1: 64 -> 56 bits */
    uint64_t k56 = des_permute64_to_56(key64, DES_PC1);
    uint32_t C   = (uint32_t) (k56 >> 28) & 0x0FFFFFFFU; /* top 28 */
    uint32_t D   = (uint32_t) (k56) & 0x0FFFFFFFU;       /* low 28 */

    for (int i = 0; i < 16; ++i) {
        int r       = DES_ROTATIONS[i];
        C           = rotl28(C, r);
        D           = rotl28(D, r);
        uint64_t cd = ((uint64_t) C << 28) | (uint64_t) D; /* 56-bit */
        subkeys[i]  = des_permute56_to_48(cd, DES_PC2);    /* low 48 bits */
    }
}
