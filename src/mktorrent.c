/*
 * mktorrent - build a torrent metadata file from a source file.
 *
 *   usage: mktorrent [-p piece_size_bytes] [-o out.torrent] <file>
 *
 * The file is split into fixed-size pieces and every piece is hashed with SHA-256.
 */
#define _GNU_SOURCE
#include "metadata.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [-p piece_size_bytes] [-o out.torrent] <file>\n"
            "  -p  piece size in bytes (default %u)\n"
            "  -o  output path (default <file>.torrent)\n",
            prog, TORRENT_DEFAULT_PIECE);
}

int main(int argc, char **argv)
{
    uint32_t    piece_size = TORRENT_DEFAULT_PIECE;
    const char *out = NULL;
    const char *src = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) {
            char *end;
            errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno || *end || v == 0 || v > UINT32_MAX) {
                fprintf(stderr, "mktorrent: bad piece size '%s'\n", argv[i]);
                return 2;
            }
            piece_size = (uint32_t)v;
        } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            out = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            usage(argv[0]);
            return 2;
        } else if (!src) {
            src = argv[i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!src) { usage(argv[0]); return 2; }

    char outbuf[PATH_MAX];
    if (!out) {
        if (snprintf(outbuf, sizeof outbuf, "%s.torrent", src) >= (int)sizeof outbuf) {
            fprintf(stderr, "mktorrent: path too long\n");
            return 1;
        }
        out = outbuf;
    }

    if (torrent_create(src, piece_size, out) != 0) return 1;

    Torrent t;
    if (torrent_load(&t, out) != 0) return 1;      /* read back to prove the file is valid */

    uint8_t ih[SHA256_LEN];
    char hex[SHA256_LEN * 2 + 1];
    torrent_info_hash(&t, ih);
    hex_encode(ih, SHA256_LEN, hex);

    printf("created   : %s\n", out);
    printf("file      : %s (%llu bytes)\n", t.name, (unsigned long long)t.size);
    printf("piece size: %u bytes\n", t.piece_size);
    printf("pieces    : %u (last piece %u bytes)\n", t.num_pieces, torrent_piece_len(&t, t.num_pieces - 1));
    printf("info hash : %s\n", hex);

    torrent_free(&t);
    return 0;
}
