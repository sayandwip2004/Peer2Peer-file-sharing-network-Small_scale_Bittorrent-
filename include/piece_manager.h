#ifndef PIECE_MANAGER_H
#define PIECE_MANAGER_H

#include <pthread.h>
#include <stdint.h>
#include "metadata.h"

#define REQUEST_TIMEOUT_S 8.0     /* an unanswered request is handed to another peer after this */

enum { PS_MISSING = 0, PS_REQUESTED = 1, PS_HAVE = 2 };

typedef struct {
    const Torrent  *t;
    int             fd;           /* output file, pre-sized to t->size */
    char            path[600];
    pthread_mutex_t lock;
    uint8_t        *have;         /* bitfield of verified pieces (sent to peers) */
    uint8_t        *state;        /* PS_* per piece */
    uint32_t       *owner;        /* connection id a piece was requested from */
    double         *req_time;     /* when it was requested */
    uint32_t       *avail;        /* how many connected peers have each piece */
    uint32_t        have_count;
    unsigned        seed;         /* for rand_r */
} PieceManager;

static inline int bf_get(const uint8_t *bf, uint32_t i) { return (bf[i >> 3] >> (7 - (i & 7))) & 1; }
static inline void bf_set(uint8_t *bf, uint32_t i)      { bf[i >> 3] |= (uint8_t)(0x80u >> (i & 7)); }
static inline uint32_t bf_bytes(uint32_t n)             { return (n + 7) / 8; }

/*
 * Open/create <dir>/<name>. Existing data is verified piece by piece (so a seed or a
 * resumed download is recognised). If only_lo/only_hi >= 0, only pieces in that range
 * are claimed - handy to simulate peers that start with different parts of the file.
 */
int      pm_open(PieceManager *pm, const Torrent *t, const char *dir, int only_lo, int only_hi);
void     pm_close(PieceManager *pm);

int      pm_complete(PieceManager *pm);
uint32_t pm_count(PieceManager *pm);
int      pm_has(PieceManager *pm, uint32_t idx);
void     pm_snapshot(PieceManager *pm, uint8_t *out_bitfield);

/* Check data against the torrent hash. 1 = ok, 0 = wrong length or hash mismatch. */
int      pm_verify(const Torrent *t, uint32_t idx, const uint8_t *data, uint32_t len);

/* Verify + write at the right offset. 1 = stored, 0 = duplicate, -1 = hash mismatch, -2 = I/O error */
int      pm_store(PieceManager *pm, uint32_t idx, const uint8_t *data, uint32_t len);

/* Read a piece we have into buf (needs torrent_piece_len bytes). 0 ok, -1 not available. */
int      pm_read(PieceManager *pm, uint32_t idx, uint8_t *buf);

/* Piece selection: rarest-first among pieces the remote has (random for the very first piece).
 * `bad` (may be NULL) marks pieces this peer already sent corrupted. Returns -1 if none. */
int      pm_pick(PieceManager *pm, const uint8_t *remote_bf, const uint8_t *bad, uint32_t cid, double now);
int      pm_inflight(PieceManager *pm, uint32_t cid);
int      pm_release_owner(PieceManager *pm, uint32_t cid);   /* returns number of pieces requeued */
void     pm_release_piece(PieceManager *pm, uint32_t idx);

/* Availability bookkeeping (how many peers have each piece). delta = +1 / -1. */
void     pm_avail_bitfield(PieceManager *pm, const uint8_t *bf, int delta);
void     pm_avail_inc(PieceManager *pm, uint32_t idx);

#endif
