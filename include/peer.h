#ifndef PEER_H
#define PEER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "choker.h"
#include "protocol.h"

#define PEER_PIPELINE      5     
#define PEER_KEEPALIVE_SEC 60
#define PEER_TIMEOUT_SEC   120


typedef struct peer_ops {
    void *ctx;

   
    int (*have_piece)(void *ctx, uint32_t index);

  
    size_t (*get_bitfield)(void *ctx, uint8_t *out, size_t cap);

    
    int (*read_block)(void *ctx, uint32_t index, uint32_t begin,
                      uint32_t length, uint8_t *out);

    int (*write_block)(void *ctx, uint32_t index, uint32_t begin,
                       const uint8_t *data, uint32_t length);

   
    int (*next_request)(void *ctx, int peer_id, const uint8_t *peer_bitfield,
                        size_t bf_len, uint32_t *index, uint32_t *begin,
                        uint32_t *length);

    
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

    
    int am_choking, am_interested, peer_choking, peer_interested;

    uint8_t *bitfield;       
    size_t   bf_len;

    uint8_t *in;  size_t in_len,  in_cap;
    uint8_t *out; size_t out_len, out_cap;

    int      pending;        

    uint64_t down_total, up_total;
    uint64_t down_window, up_window;
    double   down_rate, up_rate;   
    time_t   last_recv, last_send, last_rate;

    const peer_ops *ops;
    int      dead;           
} peer_t;


peer_t *peer_new(int fd, int id, const char *addr, uint32_t num_pieces,
                 const uint8_t info_hash[INFO_HASH_LEN],
                 const uint8_t my_id[PEER_ID_LEN], const peer_ops *ops);


peer_t *peer_connect(const char *ip, uint16_t port, int id,
                     uint32_t num_pieces,
                     const uint8_t info_hash[INFO_HASH_LEN],
                     const uint8_t my_id[PEER_ID_LEN], const peer_ops *ops);

void peer_free(peer_t *p);


void peer_set_choke(peer_t *p, int choke);
void peer_announce_have(peer_t *p, uint32_t index);
void peer_refresh_interest(peer_t *p);   


int peer_poll(peer_t **peers, size_t n, int timeout_ms, time_t now);


void peer_apply_choker(peer_t **peers, size_t n, choker_state *cs,
                       int seeding, time_t now);

#endif 
