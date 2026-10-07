#define _GNU_SOURCE
#include "peer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- small helpers ----------------------------------------------------- */

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int bit_get(const uint8_t *bf, uint32_t i)
{
    return (bf[i >> 3] >> (7 - (i & 7))) & 1;
}

static void bit_set(uint8_t *bf, uint32_t i)
{
    bf[i >> 3] |= (uint8_t)(0x80 >> (i & 7));
}

static int ensure(uint8_t **buf, size_t *cap, size_t need)
{
    if (need <= *cap)
        return 0;
    size_t ncap = *cap ? *cap : 4096;
    while (ncap < need)
        ncap *= 2;
    uint8_t *nb = realloc(*buf, ncap);
    if (!nb)
        return -1;
    *buf = nb;
    *cap = ncap;
    return 0;
}

static void mark_dead(peer_t *p)
{
    if (p->dead)
        return;
    p->dead = 1;
    if (p->ops && p->ops->release_requests)
        p->ops->release_requests(p->ops->ctx, p->id);
    p->pending = 0;
}

static int queue_bytes(peer_t *p, const uint8_t *data, size_t len)
{
    if (ensure(&p->out, &p->out_cap, p->out_len + len) < 0) {
        mark_dead(p);
        return -1;
    }
    memcpy(p->out + p->out_len, data, len);
    p->out_len += len;
    return 0;
}

static int queue_msg(peer_t *p, const proto_msg *m)
{
    size_t need = 4 + 1 + 8 + (m->data_len ? m->data_len : 0) + 16;
    if (ensure(&p->out, &p->out_cap, p->out_len + need) < 0) {
        mark_dead(p);
        return -1;
    }
    ssize_t n = proto_encode(m, p->out + p->out_len, p->out_cap - p->out_len);
    if (n < 0) {
        mark_dead(p);
        return -1;
    }
    p->out_len += (size_t)n;
    return 0;
}

static void send_simple(peer_t *p, msg_type t)
{
    proto_msg m = { .type = t };
    queue_msg(p, &m);
}

/* ---- lifecycle --------------------------------------------------------- */

peer_t *peer_new(int fd, int id, const char *addr, uint32_t num_pieces,
                 const uint8_t info_hash[INFO_HASH_LEN],
                 const uint8_t my_id[PEER_ID_LEN], const peer_ops *ops)
{
    peer_t *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    if (set_nonblock(fd) < 0) {
        free(p);
        return NULL;
    }
    p->fd = fd;
    p->id = id;
    snprintf(p->addr, sizeof(p->addr), "%s", addr ? addr : "?");
    p->num_pieces = num_pieces;
    memcpy(p->info_hash, info_hash, INFO_HASH_LEN);
    memcpy(p->my_id, my_id, PEER_ID_LEN);
    p->ops = ops;
    p->am_choking = 1;
    p->peer_choking = 1;
    p->bf_len = (num_pieces + 7) / 8;
    p->bitfield = calloc(p->bf_len ? p->bf_len : 1, 1);
    p->last_recv = p->last_send = p->last_rate = time(NULL);
    if (!p->bitfield) {
        free(p);
        return NULL;
    }

    uint8_t hs[HANDSHAKE_LEN];
    proto_encode_handshake(hs, info_hash, my_id);
    queue_bytes(p, hs, sizeof(hs));
    return p;
}

peer_t *peer_connect(const char *ip, uint16_t port, int id,
                     uint32_t num_pieces,
                     const uint8_t info_hash[INFO_HASH_LEN],
                     const uint8_t my_id[PEER_ID_LEN], const peer_ops *ops)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
        return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || set_nonblock(fd) < 0) {
        if (fd >= 0)
            close(fd);
        return NULL;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return NULL;
        }
        struct pollfd pf = { .fd = fd, .events = POLLOUT };
        int err = 0;
        socklen_t el = sizeof(err);
        if (poll(&pf, 1, 5000) <= 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
            close(fd);
            return NULL;
        }
    }

    char addr[64];
    snprintf(addr, sizeof(addr), "%s:%u", ip, port);
    peer_t *p = peer_new(fd, id, addr, num_pieces, info_hash, my_id, ops);
    if (!p)
        close(fd);
    return p;
}

void peer_free(peer_t *p)
{
    if (!p)
        return;
    if (p->fd >= 0)
        close(p->fd);
    free(p->bitfield);
    free(p->in);
    free(p->out);
    free(p);
}

/* ---- state machine ----------------------------------------------------- */

void peer_set_choke(peer_t *p, int choke)
{
    choke = choke ? 1 : 0;
    if (p->am_choking == choke || p->dead)
        return;
    p->am_choking = choke;
    send_simple(p, choke ? MSG_CHOKE : MSG_UNCHOKE);
}

void peer_announce_have(peer_t *p, uint32_t index)
{
    if (p->dead || !p->handshake_done)
        return;
    proto_msg m = { .type = MSG_HAVE, .index = index };
    queue_msg(p, &m);
}

static void fill_requests(peer_t *p)
{
    if (!p->ops || !p->ops->next_request)
        return;
    while (!p->dead && p->am_interested && !p->peer_choking &&
           p->pending < PEER_PIPELINE) {
        proto_msg m = { .type = MSG_REQUEST };
        if (!p->ops->next_request(p->ops->ctx, p->id, p->bitfield, p->bf_len,
                                  &m.index, &m.begin, &m.length))
            break;
        if (queue_msg(p, &m) < 0)
            break;
        p->pending++;
    }
}

void peer_refresh_interest(peer_t *p)
{
    if (p->dead || !p->handshake_done || !p->ops || !p->ops->have_piece)
        return;
    int want = 0;
    for (uint32_t i = 0; i < p->num_pieces && !want; i++)
        if (bit_get(p->bitfield, i) && !p->ops->have_piece(p->ops->ctx, i))
            want = 1;
    if (want != p->am_interested) {
        p->am_interested = want;
        send_simple(p, want ? MSG_INTERESTED : MSG_NOT_INTERESTED);
    }
    fill_requests(p);
}

static void handle_request(peer_t *p, const proto_msg *m)
{
    if (p->am_choking)
        return;                       /* ignore requests while choked */
    if (m->length == 0 || m->length > BLOCK_SIZE || m->index >= p->num_pieces) {
        mark_dead(p);
        return;
    }
    if (!p->ops || !p->ops->have_piece ||
        !p->ops->have_piece(p->ops->ctx, m->index) || !p->ops->read_block)
        return;                       /* we do not have it; just ignore */

    uint8_t *blk = malloc(m->length);
    if (!blk) {
        mark_dead(p);
        return;
    }
    if (p->ops->read_block(p->ops->ctx, m->index, m->begin, m->length, blk) == 0) {
        proto_msg r = { .type = MSG_PIECE, .index = m->index, .begin = m->begin,
                        .data = blk, .data_len = m->length };
        if (queue_msg(p, &r) == 0) {
            p->up_total += m->length;
            p->up_window += m->length;
        }
    }
    free(blk);
}

static void handle_msg(peer_t *p, const proto_msg *m)
{
    switch (m->type) {
    case MSG_KEEPALIVE:
        break;
    case MSG_CHOKE:
        p->peer_choking = 1;
        p->pending = 0;
        if (p->ops && p->ops->release_requests)
            p->ops->release_requests(p->ops->ctx, p->id);
        break;
    case MSG_UNCHOKE:
        p->peer_choking = 0;
        fill_requests(p);
        break;
    case MSG_INTERESTED:
        p->peer_interested = 1;
        break;
    case MSG_NOT_INTERESTED:
        p->peer_interested = 0;
        break;
    case MSG_HAVE:
        if (m->index >= p->num_pieces) {
            mark_dead(p);
            break;
        }
        bit_set(p->bitfield, m->index);
        peer_refresh_interest(p);
        break;
    case MSG_BITFIELD:
        if (m->data_len != p->bf_len) {
            mark_dead(p);
            break;
        }
        memcpy(p->bitfield, m->data, p->bf_len);
        peer_refresh_interest(p);
        break;
    case MSG_REQUEST:
        handle_request(p, m);
        break;
    case MSG_PIECE:
        if (p->pending > 0)
            p->pending--;
        p->down_total += m->data_len;
        p->down_window += m->data_len;
        if (m->index >= p->num_pieces) {
            mark_dead(p);
            break;
        }
        if (p->ops && p->ops->write_block)
            p->ops->write_block(p->ops->ctx, m->index, m->begin, m->data,
                                (uint32_t)m->data_len);
        fill_requests(p);
        break;
    case MSG_CANCEL:
        break;                        /* requests are served immediately */
    }
}

/* ---- I/O --------------------------------------------------------------- */

static void process_input(peer_t *p)
{
    size_t off = 0;

    if (!p->handshake_done) {
        if (p->in_len < HANDSHAKE_LEN)
            return;
        uint8_t ih[INFO_HASH_LEN];
        if (proto_decode_handshake(p->in, ih, p->remote_id) < 0 ||
            memcmp(ih, p->info_hash, INFO_HASH_LEN) != 0) {
            mark_dead(p);
            return;
        }
        p->handshake_done = 1;
        off = HANDSHAKE_LEN;

        if (p->ops && p->ops->get_bitfield) {
            size_t cap = p->bf_len ? p->bf_len : 1;
            uint8_t *bf = calloc(cap, 1);
            if (bf) {
                size_t n = p->ops->get_bitfield(p->ops->ctx, bf, cap);
                if (n > 0) {
                    proto_msg m = { .type = MSG_BITFIELD, .data = bf, .data_len = n };
                    queue_msg(p, &m);
                }
                free(bf);
            }
        }
    }

    while (!p->dead && off < p->in_len) {
        proto_msg m;
        ssize_t n = proto_decode(p->in + off, p->in_len - off, &m);
        if (n < 0) {
            mark_dead(p);
            return;
        }
        if (n == 0)
            break;
        handle_msg(p, &m);
        off += (size_t)n;
    }

    if (off > 0) {
        memmove(p->in, p->in + off, p->in_len - off);
        p->in_len -= off;
    }
}

static void on_readable(peer_t *p, time_t now)
{
    for (;;) {
        if (ensure(&p->in, &p->in_cap, p->in_len + 16384) < 0) {
            mark_dead(p);
            return;
        }
        ssize_t n = recv(p->fd, p->in + p->in_len, p->in_cap - p->in_len, 0);
        if (n > 0) {
            p->in_len += (size_t)n;
            p->last_recv = now;
            process_input(p);
            if (p->dead)
                return;
            if ((size_t)n < 16384)
                return;               /* drained for now */
            continue;
        }
        if (n == 0) {
            mark_dead(p);             /* orderly close by remote */
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        if (errno == EINTR)
            continue;
        mark_dead(p);
        return;
    }
}

static void flush_out(peer_t *p, time_t now)
{
    size_t sent = 0;
    while (sent < p->out_len) {
        ssize_t n = send(p->fd, p->out + sent, p->out_len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            p->last_send = now;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        mark_dead(p);
        return;
    }
    if (sent > 0) {
        memmove(p->out, p->out + sent, p->out_len - sent);
        p->out_len -= sent;
    }
}

static void update_rates(peer_t *p, time_t now)
{
    time_t dt = now - p->last_rate;
    if (dt < 1)
        return;
    p->down_rate = 0.5 * p->down_rate + 0.5 * ((double)p->down_window / dt);
    p->up_rate   = 0.5 * p->up_rate   + 0.5 * ((double)p->up_window / dt);
    p->down_window = p->up_window = 0;
    p->last_rate = now;
}

int peer_poll(peer_t **peers, size_t n, int timeout_ms, time_t now)
{
    if (n == 0)
        return 0;
    struct pollfd *pfds = calloc(n, sizeof(*pfds));
    if (!pfds)
        return -1;

    for (size_t i = 0; i < n; i++) {
        pfds[i].fd = peers[i]->dead ? -1 : peers[i]->fd;
        pfds[i].events = POLLIN | (peers[i]->out_len ? POLLOUT : 0);
    }

    int r = poll(pfds, (nfds_t)n, timeout_ms);
    if (r < 0 && errno != EINTR) {
        free(pfds);
        return -1;
    }

    int active = 0;
    for (size_t i = 0; i < n; i++) {
        peer_t *p = peers[i];
        if (p->dead)
            continue;
        if (r > 0 && pfds[i].revents) {
            active++;
            if (pfds[i].revents & POLLIN)
                on_readable(p, now);
            else if (pfds[i].revents & (POLLHUP | POLLERR | POLLNVAL))
                mark_dead(p);
        }
        if (!p->dead && p->handshake_done &&
            now - p->last_send >= PEER_KEEPALIVE_SEC && p->out_len == 0)
            send_simple(p, MSG_KEEPALIVE);
        if (!p->dead && now - p->last_recv >= PEER_TIMEOUT_SEC)
            mark_dead(p);
        if (!p->dead)
            flush_out(p, now);
        if (!p->dead)
            update_rates(p, now);
    }
    free(pfds);
    return active;
}

/* ---- choker glue ------------------------------------------------------- */

void peer_apply_choker(peer_t **peers, size_t n, choker_state *cs,
                       int seeding, time_t now)
{
    if (n == 0)
        return;
    choker_peer *cp = calloc(n, sizeof(*cp));
    if (!cp)
        return;
    for (size_t i = 0; i < n; i++) {
        cp[i].id = peers[i]->id;
        cp[i].interested = peers[i]->peer_interested && !peers[i]->dead;
        cp[i].rate = seeding ? peers[i]->up_rate : peers[i]->down_rate;
        cp[i].unchoked = !peers[i]->am_choking;
    }
    if (choker_run(cs, cp, n, now) >= 0) {
        for (size_t i = 0; i < n; i++)
            peer_set_choke(peers[i], !cp[i].want_unchoke);
    }
    free(cp);
}
