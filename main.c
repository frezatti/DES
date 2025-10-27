#include "des.h"
#include "des_tables.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int parse_hex_u64(const char* s, uint64_t* out)
{
    if (!s || !out)
        return 0;
    while (isspace((unsigned char) *s))
        s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;

    errno                = 0;
    char* end            = NULL;
    unsigned long long v = strtoull(s, &end, 16);
    if (errno != 0)
        return 0;
    while (end && isspace((unsigned char) *end))
        end++;
    if (end && *end != '\0' && *end != '\n')
        return 0;
    *out = (uint64_t) v;
    return 1;
}

static uint64_t random_u64(void)
{
    uint64_t x = 0;
    srand((unsigned) time(NULL));
    x = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
    x ^= ((uint64_t) rand() << 48);
    return x;
}

int main(void)
{
    uint64_t key64 = 0;
    uint64_t subkeys[16];

    char line[128];
    printf("Enter 64-bit key as 16 hex digits (or 'r' for random): ");
    if (!fgets(line, sizeof line, stdin)) {
        fprintf(stderr, "input error\n");
        return 1;
    }

    if (line[0] == 'r' || line[0] == 'R') {
        key64 = random_u64();
        printf("Random key = %016llX\n", (unsigned long long) key64);
    } else {
        if (!parse_hex_u64(line, &key64)) {
            fprintf(stderr, "Invalid hex key.\n");
            return 1;
        }
    }

    des_key_schedule(key64, subkeys);

    uint64_t plaintext = 0x0123456789ABCDEFULL;
    printf("Enter plaintext (16 hex digits) or press Enter for "
           "0123456789ABCDEF: ");
    if (fgets(line, sizeof line, stdin)) {
        const char* p = line;
        while (isspace((unsigned char) *p))
            p++;
        if (*p != '\0' && *p != '\n') {
            if (!parse_hex_u64(line, &plaintext)) {
                fprintf(stderr, "Invalid hex plaintext.\n");
                return 1;
            }
        }
    }

    uint64_t ciphertext = des_encrypt_block(plaintext, subkeys);
    uint64_t decrypted  = des_decrypt_block(ciphertext, subkeys);

    printf("key        = %016llX\n", (unsigned long long) key64);
    printf("plaintext  = %016llX\n", (unsigned long long) plaintext);
    printf("ciphertext = %016llX\n", (unsigned long long) ciphertext);
    printf("decrypted  = %016llX\n", (unsigned long long) decrypted);
    printf("round-trip %s\n", (decrypted == plaintext) ? "OK" : "FAIL");

    return 0;
}
