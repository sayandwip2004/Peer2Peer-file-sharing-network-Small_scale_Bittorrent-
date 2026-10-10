#ifndef PIECE_MANAGER_H
#define PIECE_MANAGER_H

#include <pthread.h>
#include <stdint.h>
#include "metadata.h"

#define REQUEST_TIMEOUT_S 8.0     

enum { PS_MISSING = 0, PS_REQUESTED = 1, PS_HAVE = 2 };

typedef struct {
    const Torrent  *t;
    int             fd;           
    char            path[600];
    pthread_mutex_t lock;
    uint8_t        *have;         
    uint8_t        *state;        
    uint32_t       *owner;       
    double         *req_time;     
    uint32_t       *avail;        
    uint32_t        have_count;
    unsigned        seed;         
} PieceManager;

static inline int bf_get(const uint8_t *bf, uint32_t i) { return (bf[i >> 3] >> (7 - (i & 7))) & 1; }
static inline void bf_set(uint8_t *bf, uint32_t i)      { bf[i >> 3] |= (uint8_t)(0x80u >> (i & 7)); }
static inline uint32_t bf_bytes(uint32_t n)             { return (n + 7) / 8; }


int      pm_open(PieceManager *pm, const Torrent *t, const char *dir, int only_lo, int only_hi);
void     pm_close(PieceManager *pm);

int      pm_complete(PieceManager *pm);
uint32_t pm_count(PieceManager *pm);
int      pm_has(PieceManager *pm, uint32_t idx);
void     pm_snapshot(PieceManager *pm, uint8_t *out_bitfield);


int      pm_verify(const Torrent *t, uint32_t idx, const uint8_t *data, uint32_t len);


int      pm_store(PieceManager *pm, uint32_t idx, const uint8_t *data, uint32_t len);


int      pm_read(PieceManager *pm, uint32_t idx, uint8_t *buf);


int      pm_pick(PieceManager *pm, const uint8_t *remote_bf, const uint8_t *bad, uint32_t cid, double now);
int      pm_inflight(PieceManager *pm, uint32_t cid);
int      pm_release_owner(PieceManager *pm, uint32_t cid);  
void     pm_release_piece(PieceManager *pm, uint32_t idx);


void     pm_avail_bitfield(PieceManager *pm, const uint8_t *bf, int delta);
void     pm_avail_inc(PieceManager *pm, uint32_t idx);

#endif
