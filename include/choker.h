#ifndef CHOKER_H
#define CHOKER_H

#include <stddef.h>
#include <time.h>


#define CHOKER_SLOTS            4
#define CHOKE_INTERVAL_SEC      10
#define OPTIMISTIC_INTERVAL_SEC 30

typedef struct {
    int    id;            
    int    interested;    
    double rate;          
    int    unchoked;      
    int    want_unchoke;  
} choker_peer;

typedef struct {
    time_t last_round;
    time_t last_optimistic;
    int    optimistic_id; 
} choker_state;

void choker_init(choker_state *cs);


int choker_run(choker_state *cs, choker_peer *peers, size_t n, time_t now);

#endif
