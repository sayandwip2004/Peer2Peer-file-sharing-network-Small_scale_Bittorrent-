#ifndef PEER_H
#define PEER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "choker.h"
#include "protocol.h"

#define PEER_PIPELINE      5     /* max outstanding block requests per peer */
#define PEER_KEEPALIVE_SEC 60
#define PEER_TIMEOUT_SEC   120

/*
 * Callbacks into the piece manager (Vedabetta's module). Keeping them as
 * function pointers means peer.c does not depend on piece_manager.h's exact
 * API; main/glue code fills this struct in. Any callback marked optional
 * may be NULL.
 */
typedef struct peer_ops {
    void *ctx;

    /* 1 if we already hold (and verified) the whole piece. */
    int (*have_piece)(void *ctx, uint32_t index);

    /* Write our bitfield (MSB-first, bit 7 of byte 0 = piece 0) into out;
     * return the number of bytes written. */
    size_t (*get_bitfield)(void *ctx, uint8_t *out, size_t cap);

    /* Copy a block we own into out. Return 0 on success. */
    int (*read_block)(void *ctx, uint32_t index, uint32_t begin,
                      uint32_t length, uint8_t *out);

    /* Store a received block. Return 0 on success. */
    int (*write_block)(void *ctx, uint32_t index, uint32_t begin,
                       const uint8_t *data, uint32_t length);

    /* Pick the next block to ask this peer for, given the pieces it has.
     * Return 1 and fill the outputs, or 0 if nothing is wanted right now. */
    int (*next_request)(void *ctx, int peer_id, const uint8_t *peer_bitfield,
                        size_t bf_len, uint32_t *index, uint32_t *begin,
                        uint32_t *length);

    /* (optional) Peer choked us or disconnected: its in-flight requests are
     * void, so the manager can hand those blocks to someone else. */
    void (*release_requests)(void *ctx, int peer_id);
} peer_ops;

typedef struct peer {
    int      fd;
    int      id;
    char     addr[64];
    uint32_t num_pieces;

    uint8_t  info_hash[INFO_HASH_LEN];
    uint8_t  my_id[PEER_ID_LEN];
    uint8_t  remote_id[PEER_ID_LEN];
    int      handshake_done;

    /* choke / interest flags, from the BitTorrent state machine */
    int am_choking, am_interested, peer_choking, peer_interested;

    uint8_t *bitfield;       /* what the remote peer has */
    size_t   bf_len;

    uint8_t *in;  size_t in_len,  in_cap;
    uint8_t *out; size_t out_len, out_cap;

    int      pending;        /* our outstanding REQUESTs to this peer */

    uint64_t down_total, up_total;
    uint64_t down_window, up_window;
    double   down_rate, up_rate;   /* smoothed bytes/sec */
    time_t   last_recv, last_send, last_rate;

    const peer_ops *ops;
    int      dead;           /* set on error/close; caller frees it */
} peer_t;

/* Takes ownership of fd (made non-blocking) and queues our handshake. */
peer_t *peer_new(int fd, int id, const char *addr, uint32_t num_pieces,
                 const uint8_t info_hash[INFO_HASH_LEN],
                 const uint8_t my_id[PEER_ID_LEN], const peer_ops *ops);

/* Outgoing TCP connection with a 5 s timeout; NULL on failure. */
peer_t *peer_connect(const char *ip, uint16_t port, int id,
                     uint32_t num_pieces,
                     const uint8_t info_hash[INFO_HASH_LEN],
                     const uint8_t my_id[PEER_ID_LEN], const peer_ops *ops);

void peer_free(peer_t *p);

/* Queue / apply state changes. */
void peer_set_choke(peer_t *p, int choke);
void peer_announce_have(peer_t *p, uint32_t index);
void peer_refresh_interest(peer_t *p);   /* call after we complete a piece */

/* Drive I/O for a set of peers: poll(), read, parse, flush, keep-alives,
 * timeouts, rate updates. Peers that fail get p->dead = 1. Returns the number
 * of peers that had activity, or -1 on poll() failure. */
int peer_poll(peer_t **peers, size_t n, int timeout_ms, time_t now);

/* Run one choker round across the swarm and apply the result. */
void peer_apply_choker(peer_t **peers, size_t n, choker_state *cs,
                       int seeding, time_t now);

#endif /* PEER_H */
