#ifndef CHOKER_H
#define CHOKER_H

#include <stddef.h>
#include <time.h>

/*
 * Tit-for-tat choking (BitTorrent style):
 *   - every CHOKE_INTERVAL_SEC seconds, unchoke the CHOKER_SLOTS interested
 *     peers with the highest transfer rate;
 *   - every OPTIMISTIC_INTERVAL_SEC seconds, additionally unchoke one random
 *     interested peer outside that set, so new peers get a chance to prove
 *     themselves.
 * While downloading, "rate" is the rate we download from the peer; while
 * seeding it is the rate we upload to it (the caller chooses).
 */
#define CHOKER_SLOTS            4
#define CHOKE_INTERVAL_SEC      10
#define OPTIMISTIC_INTERVAL_SEC 30

typedef struct {
    int    id;            /* stable identifier chosen by the caller      */
    int    interested;    /* peer is interested in us                    */
    double rate;          /* bytes/sec, see note above                   */
    int    unchoked;      /* current state: 1 if we are not choking it   */
    int    want_unchoke;  /* OUTPUT: desired state after this round      */
} choker_peer;

typedef struct {
    time_t last_round;
    time_t last_optimistic;
    int    optimistic_id;  /* -1 if none */
} choker_state;

void choker_init(choker_state *cs);

/*
 * Runs one decision round if CHOKE_INTERVAL_SEC has elapsed since the last
 * one. Fills peers[i].want_unchoke and returns the number of peers whose
 * state must change, or -1 if it is not time yet (want_unchoke untouched).
 */
int choker_run(choker_state *cs, choker_peer *peers, size_t n, time_t now);

#endif /* CHOKER_H */
