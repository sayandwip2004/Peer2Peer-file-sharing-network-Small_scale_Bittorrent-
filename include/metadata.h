#ifndef METADATA_H
#define METADATA_H

#include <stdint.h>
#include "sha256.h"

#define TORRENT_NAME_MAX      256
#define TORRENT_DEFAULT_PIECE 262144u        /* 256 KiB */

/*
 * In-memory view of a .torrent file.
 * hashes[i] is the SHA-256 of piece i (the last piece may be shorter).
 */
typedef struct {
    char      name[TORRENT_NAME_MAX];   /* file name only, never contains '/' */
    uint64_t  size;                     /* total file size in bytes */
    uint32_t  piece_size;               /* bytes per piece */
    uint32_t  num_pieces;
    uint8_t (*hashes)[SHA256_LEN];
} Torrent;

/* Split `src` into pieces, hash each one and write the metadata file `out`. 0 ok, -1 error. */
int      torrent_create(const char *src, uint32_t piece_size, const char *out);

/* Parse a metadata file written by torrent_create. 0 ok, -1 error. Call torrent_free afterwards. */
int      torrent_load(Torrent *t, const char *path);
void     torrent_free(Torrent *t);

/* Length in bytes of piece idx (0 if idx is out of range). */
uint32_t torrent_piece_len(const Torrent *t, uint32_t idx);

/* Identifier of the swarm: SHA-256 over name, size, piece size and all piece hashes.
 * Peers use its hex form when talking to the tracker. */
void     torrent_info_hash(const Torrent *t, uint8_t out[SHA256_LEN]);

#endif
