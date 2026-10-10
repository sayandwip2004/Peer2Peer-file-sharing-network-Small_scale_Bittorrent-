#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   blen;
} Sha256;

void sha256_init(Sha256 *c);
void sha256_update(Sha256 *c, const void *data, size_t len);
void sha256_final(Sha256 *c, uint8_t out[SHA256_LEN]);


void sha256_buf(const void *data, size_t len, uint8_t out[SHA256_LEN]);
int  sha256_file(const char *path, uint8_t out[SHA256_LEN]);   

void hex_encode(const uint8_t *in, size_t n, char *out);
int  hex_decode(const char *hex, uint8_t *out, size_t n);      

#endif
