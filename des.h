#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stddef.h>

uint64_t des_encrypt_block(uint64_t block, const uint64_t subkeys[16]);
uint64_t des_decrypt_block(uint64_t block, const uint64_t subkeys[16]);
void des_key_schedule(uint64_t key64, uint64_t subkeys[16]);

int des_encrypt_buffer_zeropad(
    const uint8_t* in, size_t in_len, const uint64_t subkeys[16], uint8_t** out, size_t* out_len);

int des_decrypt_buffer_nopad(
    const uint8_t* in, size_t in_len, const uint64_t subkeys[16], uint8_t** out, size_t* out_len);

#endif /* DES_H */
