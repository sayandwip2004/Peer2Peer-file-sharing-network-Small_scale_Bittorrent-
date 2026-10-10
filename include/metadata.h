#ifndef METADATA_H
#define METADATA_H

#include <stdint.h>
#include "sha256.h"

#define TORRENT_NAME_MAX      256
#define TORRENT_DEFAULT_PIECE 262144u        


typedef struct {
    char      name[TORRENT_NAME_MAX];   
    uint64_t  size;                     
    uint32_t  piece_size;               
    uint32_t  num_pieces;
    uint8_t (*hashes)[SHA256_LEN];
} Torrent;

int      torrent_create(const char *src, uint32_t piece_size, const char *out);


int      torrent_load(Torrent *t, const char *path);
void     torrent_free(Torrent *t);

uint32_t torrent_piece_len(const Torrent *t, uint32_t idx);


void     torrent_info_hash(const Torrent *t, uint8_t out[SHA256_LEN]);

#endif
