#include "choker.h"

#include <stdlib.h>

void choker_init(choker_state *cs)
{
    cs->last_round = 0;        /* first round runs immediately */
    cs->last_optimistic = 0;
    cs->optimistic_id = -1;
}

int choker_run(choker_state *cs, choker_peer *peers, size_t n, time_t now)
{
    if (cs->last_round != 0 && now - cs->last_round < CHOKE_INTERVAL_SEC)
        return -1;
    cs->last_round = now;

    for (size_t i = 0; i < n; i++)
        peers[i].want_unchoke = 0;
    if (n == 0) {
        cs->optimistic_id = -1;
        return 0;
    }

    /* Indices of interested peers, sorted by rate (insertion sort; n is small). */
    size_t *order = malloc(n * sizeof(*order));
    if (!order)
        return -1;
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        if (!peers[i].interested)
            continue;
        size_t j = m++;
        while (j > 0 && peers[order[j - 1]].rate < peers[i].rate) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = i;
    }

    size_t top = m < CHOKER_SLOTS ? m : CHOKER_SLOTS;
    for (size_t k = 0; k < top; k++)
        peers[order[k]].want_unchoke = 1;

    /* Optimistic slot: keep the current one while it is still eligible. */
    int keep = 0;
    if (cs->optimistic_id >= 0 &&
        cs->last_optimistic != 0 &&
        now - cs->last_optimistic < OPTIMISTIC_INTERVAL_SEC) {
        for (size_t i = 0; i < n; i++) {
            if (peers[i].id == cs->optimistic_id) {
                keep = peers[i].interested && !peers[i].want_unchoke;
                if (keep)
                    peers[i].want_unchoke = 1;
                break;
            }
        }
    }

    if (!keep) {
        size_t count = 0;
        for (size_t i = 0; i < n; i++)
            if (peers[i].interested && !peers[i].want_unchoke)
                count++;
        cs->optimistic_id = -1;
        if (count > 0) {
            size_t pick = (size_t)rand() % count;
            for (size_t i = 0; i < n; i++) {
                if (peers[i].interested && !peers[i].want_unchoke) {
                    if (pick-- == 0) {
                        peers[i].want_unchoke = 1;
                        cs->optimistic_id = peers[i].id;
                        break;
                    }
                }
            }
        }
        cs->last_optimistic = now;
    }

    free(order);

    int changes = 0;
    for (size_t i = 0; i < n; i++)
        if (peers[i].want_unchoke != peers[i].unchoked)
            changes++;
    return changes;
}
