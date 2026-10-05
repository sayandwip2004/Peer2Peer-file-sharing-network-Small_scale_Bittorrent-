/*
 * metadata.c - create / load the small-scale ".torrent" metadata file.
 *
 * File format (plain text, one item per line):
 *
 *     SHA256-TORRENT 1
 *     name <file name>
 *     size <bytes>
 *     piece_size <bytes>
 *     pieces <count>
 *     <64 hex chars>          <- one line per piece, in order
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "metadata.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAGIC          "SHA256-TORRENT 1"
#define MAX_PIECES     (16u * 1024u * 1024u)
#define MIN_PIECE_SIZE 1u
#define MAX_PIECE_SIZE (64u * 1024u * 1024u)

uint32_t torrent_piece_len(const Torrent *t, uint32_t idx)
{
    if (!t || idx >= t->num_pieces) return 0;
    if (idx + 1 < t->num_pieces) return t->piece_size;
    return (uint32_t)(t->size - (uint64_t)(t->num_pieces - 1) * t->piece_size);
}

void torrent_free(Torrent *t)
{
    if (!t) return;
    free(t->hashes);
    memset(t, 0, sizeof *t);
}

static const char *base_name(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

int torrent_create(const char *src, uint32_t piece_size, const char *out)
{
    if (!src || !out) return -1;
    if (piece_size < MIN_PIECE_SIZE || piece_size > MAX_PIECE_SIZE) {
        fprintf(stderr, "metadata: piece size must be between %u and %u\n", MIN_PIECE_SIZE, MAX_PIECE_SIZE);
        return -1;
    }

    struct stat st;
    if (stat(src, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "metadata: %s: not a readable regular file\n", src);
        return -1;
    }
    if (st.st_size == 0) {
        fprintf(stderr, "metadata: %s is empty\n", src);
        return -1;
    }

    const char *name = base_name(src);
    if (*name == '\0' || strlen(name) >= TORRENT_NAME_MAX || strchr(name, '\n')) {
        fprintf(stderr, "metadata: unusable file name\n");
        return -1;
    }

    uint64_t size = (uint64_t)st.st_size;
    uint64_t np64 = (size + piece_size - 1) / piece_size;
    if (np64 > MAX_PIECES) {
        fprintf(stderr, "metadata: too many pieces (%" PRIu64 "), use a larger piece size\n", np64);
        return -1;
    }
    uint32_t np = (uint32_t)np64;

    FILE *in = fopen(src, "rb");
    if (!in) { fprintf(stderr, "metadata: %s: %s\n", src, strerror(errno)); return -1; }

    uint8_t *buf = malloc(piece_size);
    uint8_t (*hashes)[SHA256_LEN] = malloc((size_t)np * SHA256_LEN);
    if (!buf || !hashes) { fclose(in); free(buf); free(hashes); return -1; }

    int rc = -1;
    for (uint32_t i = 0; i < np; i++) {
        uint64_t left = size - (uint64_t)i * piece_size;
        size_t   want = left < piece_size ? (size_t)left : piece_size;
        if (fread(buf, 1, want, in) != want) {
            fprintf(stderr, "metadata: read error at piece %u (file changed while reading?)\n", i);
            goto done;
        }
        sha256_buf(buf, want, hashes[i]);
    }

    FILE *f = fopen(out, "w");
    if (!f) { fprintf(stderr, "metadata: %s: %s\n", out, strerror(errno)); goto done; }

    fprintf(f, "%s\nname %s\nsize %" PRIu64 "\npiece_size %u\npieces %u\n", MAGIC, name, size, piece_size, np);
    char hex[SHA256_LEN * 2 + 1];
    for (uint32_t i = 0; i < np; i++) {
        hex_encode(hashes[i], SHA256_LEN, hex);
        fprintf(f, "%s\n", hex);
    }
    if (fflush(f) != 0 || ferror(f)) { fclose(f); fprintf(stderr, "metadata: write error on %s\n", out); goto done; }
    if (fclose(f) != 0) goto done;
    rc = 0;

done:
    fclose(in);
    free(buf);
    free(hashes);
    return rc;
}

/* Read one line, strip the newline. Returns 0 on success, -1 on EOF/too long. */
static int read_line(FILE *f, char *line, size_t cap)
{
    if (!fgets(line, (int)cap, f)) return -1;
    size_t n = strlen(line);
    if (n && line[n - 1] == '\n') line[--n] = '\0';
    else if (n == cap - 1) return -1;                  /* line did not fit */
    if (n && line[n - 1] == '\r') line[--n] = '\0';
    return 0;
}

int torrent_load(Torrent *t, const char *path)
{
    if (!t || !path) return -1;
    memset(t, 0, sizeof *t);

    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "metadata: %s: %s\n", path, strerror(errno)); return -1; }

    char line[512];
    unsigned long long size = 0;
    unsigned piece_size = 0, np = 0;

    if (read_line(f, line, sizeof line) != 0 || strcmp(line, MAGIC) != 0) goto bad;

    if (read_line(f, line, sizeof line) != 0 || strncmp(line, "name ", 5) != 0) goto bad;
    const char *nm = line + 5;
    if (*nm == '\0' || strlen(nm) >= TORRENT_NAME_MAX ||
        strchr(nm, '/') || !strcmp(nm, ".") || !strcmp(nm, ".."))        /* no path traversal */
        goto bad;
    strcpy(t->name, nm);

    if (read_line(f, line, sizeof line) != 0 || sscanf(line, "size %llu", &size) != 1) goto bad;
    if (read_line(f, line, sizeof line) != 0 || sscanf(line, "piece_size %u", &piece_size) != 1) goto bad;
    if (read_line(f, line, sizeof line) != 0 || sscanf(line, "pieces %u", &np) != 1) goto bad;

    if (size == 0 || piece_size < MIN_PIECE_SIZE || piece_size > MAX_PIECE_SIZE) goto bad;
    if (np == 0 || np > MAX_PIECES) goto bad;
    if (((uint64_t)size + piece_size - 1) / piece_size != np) goto bad;     /* counts must agree */

    t->size       = size;
    t->piece_size = piece_size;
    t->num_pieces = np;
    t->hashes     = malloc((size_t)np * SHA256_LEN);
    if (!t->hashes) goto bad;

    for (uint32_t i = 0; i < np; i++) {
        if (read_line(f, line, sizeof line) != 0 || strlen(line) != SHA256_LEN * 2 ||
            hex_decode(line, t->hashes[i], SHA256_LEN) != 0)
            goto bad;
    }
    fclose(f);
    return 0;

bad:
    fprintf(stderr, "metadata: %s is not a valid torrent file\n", path);
    fclose(f);
    torrent_free(t);
    return -1;
}

void torrent_info_hash(const Torrent *t, uint8_t out[SHA256_LEN])
{
    Sha256 c;
    char head[TORRENT_NAME_MAX + 64];
    int n = snprintf(head, sizeof head, "%s\n%" PRIu64 "\n%u\n", t->name, t->size, t->piece_size);

    sha256_init(&c);
    sha256_update(&c, head, (size_t)n);
    for (uint32_t i = 0; i < t->num_pieces; i++)
        sha256_update(&c, t->hashes[i], SHA256_LEN);
    sha256_final(&c, out);
}
