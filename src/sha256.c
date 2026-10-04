/* Self-contained SHA-256 (FIPS 180-4), so the project has no OpenSSL dependency. */
#include "sha256.h"

#include <stdio.h>
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void transform(uint32_t st[8], const uint8_t blk[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = st[0]; b = st[1]; c = st[2]; d = st[3];
    e = st[4]; f = st[5]; g = st[6]; h = st[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1  = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        uint32_t ch  = (e & f) ^ (~e & g);
        uint32_t t1  = h + S1 + ch + K[i] + w[i];
        uint32_t S0  = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2  = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

void sha256_init(Sha256 *c)
{
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->blen  = 0;
}

void sha256_update(Sha256 *c, const void *data, size_t len)
{
    const uint8_t *p = data;
    c->total += len;

    if (c->blen > 0) {
        size_t need = 64 - c->blen;
        size_t take = len < need ? len : need;
        memcpy(c->buf + c->blen, p, take);
        c->blen += take; p += take; len -= take;
        if (c->blen == 64) {
            transform(c->h, c->buf);
            c->blen = 0;
        }
    }
    while (len >= 64) {
        transform(c->h, p);
        p += 64; len -= 64;
    }
    if (len > 0) {
        memcpy(c->buf, p, len);
        c->blen = len;
    }
}

void sha256_final(Sha256 *c, uint8_t out[SHA256_LEN])
{
    uint64_t bits = c->total * 8;
    uint8_t pad[72];
    size_t padlen = (c->blen < 56) ? (56 - c->blen) : (120 - c->blen);

    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    for (int i = 0; i < 8; i++)
        pad[padlen + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, pad, padlen + 8);

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

void sha256_buf(const void *data, size_t len, uint8_t out[SHA256_LEN])
{
    Sha256 c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

int sha256_file(const char *path, uint8_t out[SHA256_LEN])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    Sha256 c;
    uint8_t buf[65536];
    size_t n;
    sha256_init(&c);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        sha256_update(&c, buf, n);
    int err = ferror(f);
    fclose(f);
    if (err)
        return -1;
    sha256_final(&c, out);
    return 0;
}

void hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != n * 2)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
