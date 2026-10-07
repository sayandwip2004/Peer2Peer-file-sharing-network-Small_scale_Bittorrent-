/* Tests for protocol.c, choker.c and peer.c (loopback over a socketpair). */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "choker.h"
#include "peer.h"
#include "protocol.h"

static int passed;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
#define OK(name) do { printf("  ok  %s\n", name); passed++; } while (0)

/* ---------------- protocol ---------------- */
static void test_protocol(void)
{
    uint8_t buf[BLOCK_SIZE + 64];
    uint8_t ih[INFO_HASH_LEN], pid[PEER_ID_LEN], ih2[INFO_HASH_LEN], pid2[PEER_ID_LEN];
    memset(ih, 0xAB, sizeof ih);
    memset(pid, 0xCD, sizeof pid);

    CHECK(proto_encode_handshake(buf, ih, pid) == HANDSHAKE_LEN);
    CHECK(proto_decode_handshake(buf, ih2, pid2) == 0);
    CHECK(!memcmp(ih, ih2, sizeof ih) && !memcmp(pid, pid2, sizeof pid));
    buf[0] ^= 1;
    CHECK(proto_decode_handshake(buf, ih2, pid2) < 0);
    OK("handshake roundtrip + bad magic");

    msg_type simple[] = { MSG_CHOKE, MSG_UNCHOKE, MSG_INTERESTED, MSG_NOT_INTERESTED, MSG_KEEPALIVE };
    for (size_t i = 0; i < sizeof simple / sizeof *simple; i++) {
        proto_msg m = { .type = simple[i] }, d;
        ssize_t n = proto_encode(&m, buf, sizeof buf);
        CHECK(n > 0);
        CHECK(proto_decode(buf, (size_t)n, &d) == n && d.type == simple[i]);
    }
    OK("simple messages + keepalive");

    proto_msg h = { .type = MSG_HAVE, .index = 0xDEADBEEF }, d;
    ssize_t n = proto_encode(&h, buf, sizeof buf);
    CHECK(proto_decode(buf, (size_t)n, &d) == n && d.index == 0xDEADBEEF);
    proto_msg r = { .type = MSG_REQUEST, .index = 7, .begin = 16384, .length = 16384 };
    n = proto_encode(&r, buf, sizeof buf);
    CHECK(proto_decode(buf, (size_t)n, &d) == n);
    CHECK(d.type == MSG_REQUEST && d.index == 7 && d.begin == 16384 && d.length == 16384);
    OK("have / request roundtrip");

    uint8_t blk[BLOCK_SIZE];
    for (size_t i = 0; i < sizeof blk; i++) blk[i] = (uint8_t)(i * 31);
    proto_msg pc = { .type = MSG_PIECE, .index = 3, .begin = 0, .data = blk, .data_len = sizeof blk };
    uint8_t big[BLOCK_SIZE + 64];
    n = proto_encode(&pc, big, sizeof big);
    CHECK(n == (ssize_t)(4 + 1 + 8 + BLOCK_SIZE));
    CHECK(proto_decode(big, (size_t)n, &d) == n);
    CHECK(d.type == MSG_PIECE && d.index == 3 && d.data_len == BLOCK_SIZE && !memcmp(d.data, blk, BLOCK_SIZE));
    OK("piece roundtrip (16 KiB block)");

    uint8_t bf[3] = { 0xF0, 0x0F, 0x80 };
    proto_msg b = { .type = MSG_BITFIELD, .data = bf, .data_len = 3 };
    n = proto_encode(&b, buf, sizeof buf);
    CHECK(proto_decode(buf, (size_t)n, &d) == n && d.data_len == 3 && !memcmp(d.data, bf, 3));
    OK("bitfield roundtrip");

    /* partial frames must report "need more", never consume */
    n = proto_encode(&r, buf, sizeof buf);
    for (ssize_t cut = 0; cut < n; cut++)
        CHECK(proto_decode(buf, (size_t)cut, &d) == 0);
    OK("partial frames return 0");

    /* malformed input */
    uint8_t bad1[] = { 0, 0, 0, 2, MSG_CHOKE, 0 };          /* choke with payload */
    uint8_t bad2[] = { 0, 0, 0, 1, 99 };                    /* unknown id */
    uint8_t bad3[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0 };         /* absurd length */
    CHECK(proto_decode(bad1, sizeof bad1, &d) < 0);
    CHECK(proto_decode(bad2, sizeof bad2, &d) < 0);
    CHECK(proto_decode(bad3, sizeof bad3, &d) < 0);
    CHECK(proto_encode(&pc, buf, 10) < 0);                  /* buffer too small */
    OK("malformed frames rejected");

    /* two frames back-to-back decode one at a time */
    proto_msg c1 = { .type = MSG_UNCHOKE }, c2 = { .type = MSG_HAVE, .index = 5 };
    ssize_t a = proto_encode(&c1, buf, sizeof buf);
    ssize_t bb = proto_encode(&c2, buf + a, sizeof buf - (size_t)a);
    CHECK(proto_decode(buf, (size_t)(a + bb), &d) == a && d.type == MSG_UNCHOKE);
    CHECK(proto_decode(buf + a, (size_t)bb, &d) == bb && d.index == 5);
    OK("concatenated frames");
}

/* ---------------- choker ---------------- */
static int count_unchoke(choker_peer *p, size_t n)
{
    int c = 0;
    for (size_t i = 0; i < n; i++) c += p[i].want_unchoke;
    return c;
}

static void test_choker(void)
{
    srand(1);
    choker_state cs;
    choker_init(&cs);
    choker_peer p[8];
    for (int i = 0; i < 8; i++)
        p[i] = (choker_peer){ .id = 100 + i, .interested = 1, .rate = 10.0 * (i + 1) };
    p[7].interested = 0;               /* fastest peer is not interested */

    time_t t = 1000;
    int ch = choker_run(&cs, p, 8, t);
    CHECK(ch >= 0);
    CHECK(count_unchoke(p, 8) == CHOKER_SLOTS + 1);
    CHECK(!p[7].want_unchoke);                          /* uninterested stays choked */
    CHECK(p[6].want_unchoke && p[5].want_unchoke && p[4].want_unchoke && p[3].want_unchoke);
    CHECK(p[0].want_unchoke + p[1].want_unchoke + p[2].want_unchoke == 1);   /* one optimistic */
    OK("top-4 by rate + 1 optimistic, uninterested choked");

    int opt = cs.optimistic_id;
    CHECK(opt >= 100 && opt <= 102);
    for (int i = 0; i < 8; i++) p[i].unchoked = p[i].want_unchoke;
    CHECK(choker_run(&cs, p, 8, t + 5) == -1);          /* too early */
    OK("rounds gated to 10 s");

    CHECK(choker_run(&cs, p, 8, t + 10) >= 0);
    CHECK(cs.optimistic_id == opt && p[opt - 100].want_unchoke);   /* kept < 30 s */
    OK("optimistic slot kept for 30 s");

    int moved = 0;
    for (int k = 0; k < 20 && !moved; k++) {
        t += 30;
        CHECK(choker_run(&cs, p, 8, t) >= 0);
        if (cs.optimistic_id != opt) moved = 1;
    }
    CHECK(moved);
    OK("optimistic slot rotates");

    choker_peer few[2] = { { .id = 1, .interested = 1, .rate = 5 }, { .id = 2, .interested = 1, .rate = 9 } };
    choker_init(&cs);
    CHECK(choker_run(&cs, few, 2, 5000) == 2);
    CHECK(few[0].want_unchoke && few[1].want_unchoke);
    CHECK(choker_run(&cs, few, 0, 6000) == 0);
    OK("fewer peers than slots / empty swarm");
}

/* ---------------- peer loopback ---------------- */
#define PIECE_SZ (2 * BLOCK_SIZE)
#define NPIECES  3
#define NBLOCKS  (NPIECES * 2)

typedef struct {
    uint8_t data[NPIECES * PIECE_SZ];
    uint8_t got[NBLOCKS], req[NBLOCKS];
} store_t;

static int s_have(void *c, uint32_t i)
{
    store_t *s = c;
    return s->got[2 * i] && s->got[2 * i + 1];
}
static size_t s_bitfield(void *c, uint8_t *out, size_t cap)
{
    store_t *s = c;
    size_t n = (NPIECES + 7) / 8;
    if (cap < n) return 0;
    memset(out, 0, n);
    for (uint32_t i = 0; i < NPIECES; i++)
        if (s_have(s, i)) out[i >> 3] |= (uint8_t)(0x80 >> (i & 7));
    return n;
}
static int s_read(void *c, uint32_t i, uint32_t b, uint32_t l, uint8_t *out)
{
    store_t *s = c;
    memcpy(out, s->data + (size_t)i * PIECE_SZ + b, l);
    return 0;
}
static int s_write(void *c, uint32_t i, uint32_t b, const uint8_t *d, uint32_t l)
{
    store_t *s = c;
    memcpy(s->data + (size_t)i * PIECE_SZ + b, d, l);
    s->got[2 * i + b / BLOCK_SIZE] = 1;
    return 0;
}
static int s_next(void *c, int pid, const uint8_t *bf, size_t bl, uint32_t *i, uint32_t *b, uint32_t *l)
{
    (void)pid; (void)bl;
    store_t *s = c;
    for (int k = 0; k < NBLOCKS; k++) {
        uint32_t pc = (uint32_t)k / 2;
        if (!s->got[k] && !s->req[k] && ((bf[pc >> 3] >> (7 - (pc & 7))) & 1)) {
            s->req[k] = 1;
            *i = pc; *b = (uint32_t)(k % 2) * BLOCK_SIZE; *l = BLOCK_SIZE;
            return 1;
        }
    }
    return 0;
}
static void s_release(void *c, int pid)
{
    (void)pid;
    store_t *s = c;
    for (int k = 0; k < NBLOCKS; k++) if (!s->got[k]) s->req[k] = 0;
}

static void test_peer_loopback(void)
{
    static store_t seed, leech;
    for (size_t i = 0; i < sizeof seed.data; i++) seed.data[i] = (uint8_t)(i * 7 + (i >> 9));
    memset(seed.got, 1, sizeof seed.got);

    peer_ops so = { &seed,  s_have, s_bitfield, s_read, s_write, s_next, s_release };
    peer_ops lo = { &leech, s_have, s_bitfield, s_read, s_write, s_next, s_release };

    uint8_t ih[INFO_HASH_LEN], ida[PEER_ID_LEN], idb[PEER_ID_LEN];
    memset(ih, 9, sizeof ih); memset(ida, 1, sizeof ida); memset(idb, 2, sizeof idb);

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    peer_t *a = peer_new(sv[0], 1, "seeder",  NPIECES, ih, ida, &so);   /* seeder's view of leecher */
    peer_t *b = peer_new(sv[1], 2, "leecher", NPIECES, ih, idb, &lo);   /* leecher's view of seeder */
    CHECK(a && b);
    peer_t *ps[2] = { a, b };

    time_t now = time(NULL);
    for (int it = 0; it < 500; it++) {
        peer_poll(ps, 2, 10, now + it / 50);
        CHECK(!a->dead && !b->dead);
        if (a->peer_interested && a->am_choking)
            peer_set_choke(a, 0);
        int done = 1;
        for (uint32_t i = 0; i < NPIECES; i++) done &= s_have(&leech, i);
        if (done) break;
    }
    for (uint32_t i = 0; i < NPIECES; i++) CHECK(s_have(&leech, i));
    CHECK(!memcmp(seed.data, leech.data, sizeof seed.data));
    CHECK(b->down_total == sizeof seed.data && a->up_total == sizeof seed.data);
    CHECK(b->pending == 0);
    OK("handshake, bitfield, interest, unchoke, pipelined transfer of 3 pieces");

    /* choke: leecher's outstanding requests are voided */
    peer_set_choke(a, 1);
    peer_poll(ps, 2, 20, now + 20);   /* a flushes CHOKE */
    peer_poll(ps, 2, 20, now + 20);   /* b reads it */
    CHECK(b->peer_choking);
    OK("choke propagates");

    /* have + interest refresh after seeder gets new piece */
    memset(leech.got, 0, sizeof leech.got); memset(leech.req, 0, sizeof leech.req);
    peer_refresh_interest(b);
    CHECK(b->am_interested);
    OK("interest recomputed from remote bitfield");

    /* protocol violation kills only that peer */
    uint8_t junk[] = { 0, 0, 0, 1, 99 };
    CHECK(send(sv[0], junk, sizeof junk, 0) == (ssize_t)sizeof junk);
    peer_poll(ps, 2, 50, now + 21);
    CHECK(b->dead);
    OK("unknown message id drops the peer");

    peer_free(a); peer_free(b);

    /* handshake with the wrong info_hash is refused */
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    uint8_t ih2[INFO_HASH_LEN]; memset(ih2, 8, sizeof ih2);
    a = peer_new(sv[0], 1, "x", NPIECES, ih,  ida, &so);
    b = peer_new(sv[1], 2, "y", NPIECES, ih2, idb, &lo);
    peer_t *qs[2] = { a, b };
    for (int it = 0; it < 5; it++) peer_poll(qs, 2, 10, now);
    CHECK(a->dead && b->dead);
    peer_free(a); peer_free(b);
    OK("info_hash mismatch rejected");
}

int main(void)
{
    puts("protocol"); test_protocol();
    puts("choker");   test_choker();
    puts("peer");     test_peer_loopback();
    printf("\nAll %d checks passed.\n", passed);
    return 0;
}
