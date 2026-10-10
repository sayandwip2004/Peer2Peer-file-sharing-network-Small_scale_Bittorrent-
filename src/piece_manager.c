#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "piece_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static ssize_t pread_full(int fd, void *buf, size_t n, off_t off)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = pread(fd, (uint8_t *)buf + done, n - done, off + (off_t)done);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        done += (size_t)r;
    }
    return (ssize_t)done;
}

static ssize_t pwrite_full(int fd, const void *buf, size_t n, off_t off)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = pwrite(fd, (const uint8_t *)buf + done, n - done, off + (off_t)done);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        done += (size_t)r;
    }
    return (ssize_t)done;
}

int pm_verify(const Torrent *t, uint32_t idx, const uint8_t *data, uint32_t len)
{
    if (idx >= t->num_pieces || len != torrent_piece_len(t, idx))
        return 0;
    uint8_t h[SHA256_LEN];
    sha256_buf(data, len, h);
    return memcmp(h, t->hashes[idx], SHA256_LEN) == 0;
}

int pm_open(PieceManager *pm, const Torrent *t, const char *dir, int only_lo, int only_hi)
{
    memset(pm, 0, sizeof *pm);
    pm->t = t;
    pm->fd = -1;
    pm->seed = (unsigned)time(NULL) ^ (unsigned)getpid();
    pthread_mutex_init(&pm->lock, NULL);

    uint32_t n = t->num_pieces;
    pm->have     = calloc(bf_bytes(n), 1);
    pm->state    = calloc(n, 1);
    pm->owner    = calloc(n, sizeof *pm->owner);
    pm->req_time = calloc(n, sizeof *pm->req_time);
    pm->avail    = calloc(n, sizeof *pm->avail);
    if (!pm->have || !pm->state || !pm->owner || !pm->req_time || !pm->avail) {
        pm_close(pm);
        return -1;
    }

    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        perror(dir);
        pm_close(pm);
        return -1;
    }
    snprintf(pm->path, sizeof pm->path, "%s/%s", dir, t->name);

    pm->fd = open(pm->path, O_RDWR | O_CREAT, 0644);
    if (pm->fd < 0) { perror(pm->path); pm_close(pm); return -1; }

    struct stat st;
    if (fstat(pm->fd, &st) != 0) { perror("fstat"); pm_close(pm); return -1; }
    if ((uint64_t)st.st_size != t->size && ftruncate(pm->fd, (off_t)t->size) != 0) {
        perror("ftruncate");
        pm_close(pm);
        return -1;
    }

    
    int lo = only_lo >= 0 ? only_lo : 0;
    int hi = only_hi >= 0 ? only_hi : (int)n - 1;
    uint8_t *buf = malloc(t->piece_size);
    if (!buf) { pm_close(pm); return -1; }

    for (int i = lo; i <= hi && i < (int)n; i++) {
        uint32_t len = torrent_piece_len(t, (uint32_t)i);
        if (pread_full(pm->fd, buf, len, (off_t)i * t->piece_size) < 0)
            continue;
        if (pm_verify(t, (uint32_t)i, buf, len)) {
            bf_set(pm->have, (uint32_t)i);
            pm->state[i] = PS_HAVE;
            pm->have_count++;
        }
    }
    free(buf);
    return 0;
}

void pm_close(PieceManager *pm)
{
    if (pm->fd >= 0) close(pm->fd);
    pm->fd = -1;
    free(pm->have); free(pm->state); free(pm->owner); free(pm->req_time); free(pm->avail);
    pm->have = NULL; pm->state = NULL; pm->owner = NULL; pm->req_time = NULL; pm->avail = NULL;
    pthread_mutex_destroy(&pm->lock);
}

int pm_complete(PieceManager *pm)
{
    pthread_mutex_lock(&pm->lock);
    int c = pm->have_count == pm->t->num_pieces;
    pthread_mutex_unlock(&pm->lock);
    return c;
}

uint32_t pm_count(PieceManager *pm)
{
    pthread_mutex_lock(&pm->lock);
    uint32_t c = pm->have_count;
    pthread_mutex_unlock(&pm->lock);
    return c;
}

int pm_has(PieceManager *pm, uint32_t idx)
{
    if (idx >= pm->t->num_pieces) return 0;
    pthread_mutex_lock(&pm->lock);
    int h = pm->state[idx] == PS_HAVE;
    pthread_mutex_unlock(&pm->lock);
    return h;
}

void pm_snapshot(PieceManager *pm, uint8_t *out)
{
    pthread_mutex_lock(&pm->lock);
    memcpy(out, pm->have, bf_bytes(pm->t->num_pieces));
    pthread_mutex_unlock(&pm->lock);
}

int pm_store(PieceManager *pm, uint32_t idx, const uint8_t *data, uint32_t len)
{
    const Torrent *t = pm->t;

    
    if (!pm_verify(t, idx, data, len))
        return -1;

    pthread_mutex_lock(&pm->lock);
    if (pm->state[idx] == PS_HAVE) {
        pthread_mutex_unlock(&pm->lock);
        return 0;                                   
    }
    if (pwrite_full(pm->fd, data, len, (off_t)idx * t->piece_size) < 0) {
        pthread_mutex_unlock(&pm->lock);
        return -2;
    }
    bf_set(pm->have, idx);
    pm->state[idx] = PS_HAVE;
    pm->have_count++;
    pthread_mutex_unlock(&pm->lock);
    return 1;
}

int pm_read(PieceManager *pm, uint32_t idx, uint8_t *buf)
{
    if (!pm_has(pm, idx))
        return -1;
    uint32_t len = torrent_piece_len(pm->t, idx);
    return pread_full(pm->fd, buf, len, (off_t)idx * pm->t->piece_size) < 0 ? -1 : 0;
}

int pm_pick(PieceManager *pm, const uint8_t *remote_bf, const uint8_t *bad, uint32_t cid, double now)
{
    const Torrent *t = pm->t;
    int best = -1, ties = 0;
    uint32_t best_avail = UINT_MAX;

    pthread_mutex_lock(&pm->lock);
    int first_piece = (pm->have_count == 0);

    for (uint32_t i = 0; i < t->num_pieces; i++) {
        if (pm->state[i] == PS_HAVE) continue;
        if (pm->state[i] == PS_REQUESTED && now - pm->req_time[i] < REQUEST_TIMEOUT_S) continue;
        if (!bf_get(remote_bf, i)) continue;
        if (bad && bf_get(bad, i)) continue;

        uint32_t a = first_piece ? 0 : pm->avail[i];    
        if (a < best_avail) {
            best = (int)i; best_avail = a; ties = 1;
        } else if (a == best_avail) {
            ties++;
            if (rand_r(&pm->seed) % (unsigned)ties == 0)  
                best = (int)i;
        }
    }

    if (best >= 0) {
        pm->state[best]    = PS_REQUESTED;
        pm->owner[best]    = cid;
        pm->req_time[best] = now;
    }
    pthread_mutex_unlock(&pm->lock);
    return best;
}

int pm_inflight(PieceManager *pm, uint32_t cid)
{
    int c = 0;
    pthread_mutex_lock(&pm->lock);
    for (uint32_t i = 0; i < pm->t->num_pieces; i++)
        if (pm->state[i] == PS_REQUESTED && pm->owner[i] == cid)
            c++;
    pthread_mutex_unlock(&pm->lock);
    return c;
}

int pm_release_owner(PieceManager *pm, uint32_t cid)
{
    int c = 0;
    pthread_mutex_lock(&pm->lock);
    for (uint32_t i = 0; i < pm->t->num_pieces; i++)
        if (pm->state[i] == PS_REQUESTED && pm->owner[i] == cid) {
            pm->state[i] = PS_MISSING;
            c++;
        }
    pthread_mutex_unlock(&pm->lock);
    return c;
}

void pm_release_piece(PieceManager *pm, uint32_t idx)
{
    pthread_mutex_lock(&pm->lock);
    if (idx < pm->t->num_pieces && pm->state[idx] == PS_REQUESTED)
        pm->state[idx] = PS_MISSING;
    pthread_mutex_unlock(&pm->lock);
}

void pm_avail_bitfield(PieceManager *pm, const uint8_t *bf, int delta)
{
    pthread_mutex_lock(&pm->lock);
    for (uint32_t i = 0; i < pm->t->num_pieces; i++) {
        if (!bf_get(bf, i)) continue;
        if (delta > 0) pm->avail[i]++;
        else if (pm->avail[i] > 0) pm->avail[i]--;
    }
    pthread_mutex_unlock(&pm->lock);
}

void pm_avail_inc(PieceManager *pm, uint32_t idx)
{
    pthread_mutex_lock(&pm->lock);
    if (idx < pm->t->num_pieces) pm->avail[idx]++;
    pthread_mutex_unlock(&pm->lock);
}
