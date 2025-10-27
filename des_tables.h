#ifndef DES_TABLES_H
#define DES_TABLES_H

#include <stdint.h>

extern const uint64_t DES_MASK_48;
extern const uint8_t DES_MASK_6;

extern const uint8_t DES_IP[64];
extern const uint8_t DES_IP_INV[64];
extern const uint8_t DES_E[48];
extern const uint8_t DES_P[32];

extern const uint8_t DES_S1[64];
extern const uint8_t DES_S2[64];
extern const uint8_t DES_S3[64];
extern const uint8_t DES_S4[64];
extern const uint8_t DES_S5[64];
extern const uint8_t DES_S6[64];
extern const uint8_t DES_S7[64];
extern const uint8_t DES_S8[64];

extern const uint8_t DES_PC1[56];
extern const uint8_t DES_PC2[48];
extern const uint8_t DES_ROTATIONS[16];

#endif /* DES_TABLES_H */
