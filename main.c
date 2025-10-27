#include "des.h"
#include "des_bytes.h"
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

static const char B64_TBL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t* in, size_t in_len, char** out, size_t* out_len)
{
    if (!out || !out_len)
        return 1;
    size_t olen = 4 * ((in_len + 2) / 3);
    char* buf   = (char*) malloc(olen + 1);
    if (!buf)
        return 2;
    size_t i = 0, j = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i + 1] << 8) | (uint32_t) in[i + 2];
        buf[j++]   = B64_TBL[(v >> 18) & 0x3F];
        buf[j++]   = B64_TBL[(v >> 12) & 0x3F];
        buf[j++]   = B64_TBL[(v >> 6) & 0x3F];
        buf[j++]   = B64_TBL[v & 0x3F];
        i += 3;
    }
    if (i < in_len) {
        uint32_t v = (uint32_t) in[i] << 16;
        int rem    = (int) (in_len - i);
        if (rem == 2)
            v |= (uint32_t) in[i + 1] << 8;
        buf[j++] = B64_TBL[(v >> 18) & 0x3F];
        buf[j++] = B64_TBL[(v >> 12) & 0x3F];
        if (rem == 2) {
            buf[j++] = B64_TBL[(v >> 6) & 0x3F];
            buf[j++] = '=';
        } else {
            buf[j++] = '=';
            buf[j++] = '=';
        }
    }
    buf[j]   = '\0';
    *out     = buf;
    *out_len = j;
    return 0;
}

static void build_b64_dec_lut(int8_t lut[256])
{
    for (int i = 0; i < 256; ++i)
        lut[i] = -1;
    for (int i = 0; i < 64; ++i)
        lut[(unsigned char) B64_TBL[i]] = (int8_t) i;
    lut[(unsigned char) '='] = -2;
}

static int base64_decode(const char* in, uint8_t** out, size_t* out_len)
{
    if (!out || !out_len || !in)
        return 1;
    int8_t lut[256];
    build_b64_dec_lut(lut);

    size_t cap   = (strlen(in) / 4 + 1) * 3;
    uint8_t* buf = (uint8_t*) malloc(cap ? cap : 1);
    if (!buf)
        return 2;

    size_t j = 0;
    int vals[4];
    int vcount = 0;

    for (const unsigned char* p = (const unsigned char*) in; *p; ++p) {
        if (isspace(*p))
            continue;
        int8_t v = lut[*p];
        if (v == -1) {
            free(buf);
            return 3;
        }
        vals[vcount++] = v;
        if (vcount == 4) {
            int pad = 0;
            if (vals[2] == -2 && vals[3] == -2)
                pad = 2;
            else if (vals[3] == -2)
                pad = 1;

            uint32_t n = 0;
            n |= (uint32_t) ((vals[0] < 0 ? 0 : vals[0]) & 0x3F) << 18;
            n |= (uint32_t) ((vals[1] < 0 ? 0 : vals[1]) & 0x3F) << 12;
            if (vals[2] >= 0)
                n |= (uint32_t) (vals[2] & 0x3F) << 6;
            if (vals[3] >= 0)
                n |= (uint32_t) (vals[3] & 0x3F);

            if (pad == 2) {
                buf[j++] = (uint8_t) ((n >> 16) & 0xFF);
            } else if (pad == 1) {
                buf[j++] = (uint8_t) ((n >> 16) & 0xFF);
                buf[j++] = (uint8_t) ((n >> 8) & 0xFF);
            } else {
                buf[j++] = (uint8_t) ((n >> 16) & 0xFF);
                buf[j++] = (uint8_t) ((n >> 8) & 0xFF);
                buf[j++] = (uint8_t) (n & 0xFF);
            }
            vcount = 0;
        }
    }
    if (vcount != 0) {
        free(buf);
        return 5;
    }
    *out     = buf;
    *out_len = j;
    return 0;
}

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
    int fd     = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, &x, 8);
        close(fd);
        if (r == 8)
            return x;
    }
    srand((unsigned) time(NULL));
    x = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
    x ^= ((uint64_t) rand() << 48);
    return x;
}

static uint64_t key_from_ascii_8(const char* s)
{
    uint8_t b[8] = {0};
    size_t n     = s ? strlen(s) : 0;
    if (n > 8)
        n = 8;
    memcpy(b, s, n);
    return ((uint64_t) b[0] << 56) | ((uint64_t) b[1] << 48) | ((uint64_t) b[2] << 40) |
           ((uint64_t) b[3] << 32) | ((uint64_t) b[4] << 24) | ((uint64_t) b[5] << 16) |
           ((uint64_t) b[6] << 8) | (uint64_t) b[7];
}

static void strip_newline(char* s)
{
    if (!s)
        return;
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

int main(void)
{
    uint64_t key64 = 0;
    uint64_t subkeys[16];
    char line[8192];

    printf("Choose action: [e]ncrypt, [d]ecrypt, [b]oth: ");
    if (!fgets(line, sizeof line, stdin)) {
        fprintf(stderr, "input error\n");
        return 1;
    }
    char mode = 0;
    for (char* p = line; *p; ++p)
        if (isalpha((unsigned char) *p)) {
            mode = (char) tolower(*p);
            break;
        }
    if (mode != 'e' && mode != 'd' && mode != 'b') {
        fprintf(stderr, "invalid mode\n");
        return 1;
    }

    printf("Key input: [r]andom  [h]ex (16 hex digits)  [s]tring (<=8 chars): ");
    if (!fgets(line, sizeof line, stdin)) {
        fprintf(stderr, "input error\n");
        return 1;
    }
    char kmode = 0;
    for (char* p = line; *p; ++p)
        if (isalpha((unsigned char) *p)) {
            kmode = (char) tolower(*p);
            break;
        }

    if (kmode == 'r') {
        key64 = random_u64();
        printf("Random key = %016llX\n", (unsigned long long) key64);
    } else if (kmode == 'h') {
        printf("Enter 16 hex digits: ");
        if (!fgets(line, sizeof line, stdin)) {
            fprintf(stderr, "input error\n");
            return 1;
        }
        if (!parse_hex_u64(line, &key64)) {
            fprintf(stderr, "Invalid hex key.\n");
            return 1;
        }
    } else if (kmode == 's') {
        printf("Enter key string (<= 8 chars): ");
        if (!fgets(line, sizeof line, stdin)) {
            fprintf(stderr, "input error\n");
            return 1;
        }
        strip_newline(line);
        key64 = key_from_ascii_8(line);
        printf("Key (from string) = %016llX\n", (unsigned long long) key64);
    } else {
        fprintf(stderr, "Invalid key mode.\n");
        return 1;
    }

    des_key_schedule(key64, subkeys);

    if (mode == 'e' || mode == 'b') {
        printf("Enter plaintext (a line of text): ");
        if (!fgets(line, sizeof line, stdin)) {
            fprintf(stderr, "input error\n");
            return 1;
        }
        strip_newline(line);
        const uint8_t* pt = (const uint8_t*) line;
        size_t pt_len     = strlen(line);

        uint8_t* ct       = NULL;
        size_t ct_len     = 0;
        int rc            = des_encrypt_buffer_zeropad(pt, pt_len, subkeys, &ct, &ct_len);
        if (rc) {
            fprintf(stderr, "encrypt error (%d)\n", rc);
            return 1;
        }

        char* b64      = NULL;
        size_t b64_len = 0;
        rc             = base64_encode(ct, ct_len, &b64, &b64_len);
        if (rc) {
            free(ct);
            fprintf(stderr, "base64 encode error\n");
            return 1;
        }

        printf("Ciphertext (Base64): %s\n", b64);
        free(ct);
        free(b64);
    }

    if (mode == 'd' || mode == 'b') {
        printf("Enter ciphertext in Base64: ");
        if (!fgets(line, sizeof line, stdin)) {
            fprintf(stderr, "input error\n");
            return 1;
        }
        strip_newline(line);
        uint8_t* ct2   = NULL;
        size_t ct2_len = 0;
        int rc         = base64_decode(line, &ct2, &ct2_len);
        if (rc) {
            fprintf(stderr, "base64 decode error (%d)\n", rc);
            return 1;
        }

        if ((ct2_len % 8) != 0) {
            fprintf(stderr, "ciphertext length (%zu) is not a multiple of 8 bytes\n", ct2_len);
            free(ct2);
            return 1;
        }

        uint8_t* pt2   = NULL;
        size_t pt2_len = 0;
        rc             = des_decrypt_buffer_nopad(ct2, ct2_len, subkeys, &pt2, &pt2_len);
        free(ct2);
        if (rc) {
            fprintf(stderr, "decrypt error (%d)\n", rc);
            return 1;
        }

        /* Print raw bytes; trailing zeros may exist due to zero-padding */
        printf("Decrypted (%zu bytes): ", pt2_len);
        fwrite(pt2, 1, pt2_len, stdout);
        putchar('\n');
        free(pt2);
    }

    return 0;
}
