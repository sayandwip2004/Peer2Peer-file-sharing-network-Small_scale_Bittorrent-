/* Unit tests: SHA-256, split/reassemble, tamper detection, resume, rarest-first, tit-for-tat. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "choker.h"
#include "metadata.h"
#include "piece_manager.h"

static int passes, fails;
#define CHECK(c) do { if (c) passes++; else { fails++; printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static char tmp[128];

static void test_sha256(void)
{
    puts("sha256");
    uint8_t h[32]; char hex[65];
    sha256_buf("abc", 3, h); hex_encode(h, 32, hex);
    CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    sha256_buf("", 0, h); hex_encode(h, 32, hex);
    CHECK(!strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";   /* crosses block boundary */
    sha256_buf(two, strlen(two), h); hex_encode(h, 32, hex);
    CHECK(!strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

static void make_source(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    srand(1234);
    for (size_t i = 0; i < size; i++) fputc(rand() & 0xFF, f);
    fclose(f);
}

static void test_pieces(void)
{
    puts("split / verify / reassemble");
    char src[200], tor[200], dst[200], dst_file[300];
    snprintf(src, sizeof src, "%s/data.bin", tmp);
    snprintf(tor, sizeof tor, "%s/data.torrent", tmp);
    snprintf(dst, sizeof dst, "%s/dst", tmp);
    snprintf(dst_file, sizeof dst_file, "%s/data.bin", dst);

    const size_t SIZE = 1000003;               /* deliberately not a multiple of the piece size */
    make_source(src, SIZE);
    CHECK(torrent_create(src, 4096, tor) == 0);

    Torrent t;
    CHECK(torrent_load(&t, tor) == 0);
    CHECK(t.size == SIZE && t.piece_size == 4096 && t.num_pieces == (SIZE + 4095) / 4096);
    CHECK(torrent_piece_len(&t, t.num_pieces - 1) == SIZE - (t.num_pieces - 1) * 4096);

    int sfd = open(src, O_RDONLY);
    uint8_t *buf = malloc(4096);

    PieceManager pm;
    CHECK(pm_open(&pm, &t, dst, -1, -1) == 0);
    CHECK(pm_count(&pm) == 0);

    /* store pieces in reverse order */
    int all_ok = 1;
    for (int i = (int)t.num_pieces - 1; i >= 0; i--) {
        uint32_t len = torrent_piece_len(&t, (uint32_t)i);
        if (pread(sfd, buf, len, (off_t)i * 4096) != (ssize_t)len) all_ok = 0;
        if (pm_store(&pm, (uint32_t)i, buf, len) != 1) all_ok = 0;
    }
    CHECK(all_ok);
    CHECK(pm_complete(&pm));

    uint8_t a[32], b[32];
    CHECK(sha256_file(src, a) == 0 && sha256_file(dst_file, b) == 0 && !memcmp(a, b, 32));

    /* duplicate piece is ignored */
    if (pread(sfd, buf, 4096, 0) != 4096) fails++;
    CHECK(pm_store(&pm, 0, buf, 4096) == 0);
    pm_close(&pm);

    puts("resume (existing file is recognised)");
    CHECK(pm_open(&pm, &t, dst, -1, -1) == 0);
    CHECK(pm_complete(&pm));
    pm_close(&pm);

    puts("partial peer (--only range)");
    CHECK(pm_open(&pm, &t, dst, 10, 19) == 0);
    CHECK(pm_count(&pm) == 10);
    CHECK(pm_has(&pm, 10) && pm_has(&pm, 19) && !pm_has(&pm, 9) && !pm_has(&pm, 20));
    pm_close(&pm);

    puts("tampered data is rejected");
    char dst2[200];
    snprintf(dst2, sizeof dst2, "%s/dst2", tmp);
    CHECK(pm_open(&pm, &t, dst2, -1, -1) == 0);
    if (pread(sfd, buf, 4096, 5 * 4096) != 4096) fails++;
    buf[100] ^= 0x01;                                   /* flip a single bit */
    CHECK(pm_store(&pm, 5, buf, 4096) == -1);
    CHECK(!pm_has(&pm, 5) && pm_count(&pm) == 0);
    buf[100] ^= 0x01;                                   /* restore */
    CHECK(pm_store(&pm, 5, buf, 4095) == -1);           /* wrong length */
    CHECK(pm_store(&pm, 5, buf, 4096) == 1);

    puts("rarest-first");
    uint32_t n = t.num_pieces;
    uint8_t *all = calloc(bf_bytes(n), 1), *not3 = calloc(bf_bytes(n), 1);
    for (uint32_t i = 0; i < n; i++) { bf_set(all, i); if (i != 3) bf_set(not3, i); }
    pm_avail_bitfield(&pm, all, +1);
    pm_avail_bitfield(&pm, not3, +1);                   /* piece 3 is held by 1 peer, others by 2 */
    CHECK(pm_pick(&pm, all, NULL, 1, 100.0) == 3);      /* we already hold piece 5, so not "first piece" */
    CHECK(pm_pick(&pm, all, NULL, 1, 101.0) != 3);      /* 3 is now in flight */
    CHECK(pm_inflight(&pm, 1) == 2);

    uint8_t *bad = calloc(bf_bytes(n), 1);
    bf_set(bad, 3);
    CHECK(pm_release_owner(&pm, 1) == 2);
    CHECK(pm_pick(&pm, all, bad, 2, 102.0) != 3);       /* piece marked bad for this peer is skipped */

    /* timed-out request is handed to someone else */
    pm_release_owner(&pm, 2);
    int p = pm_pick(&pm, all, NULL, 7, 200.0);
    CHECK(p >= 0);
    CHECK(pm_pick(&pm, all, NULL, 8, 200.1) != p);
    int stolen = 0;
    for (int k = 0; k < (int)n && !stolen; k++)
        if (pm_pick(&pm, all, NULL, 9, 200.0 + REQUEST_TIMEOUT_S + 1) == p) stolen = 1;
    CHECK(stolen);

    free(all); free(not3); free(bad); free(buf);
    pm_close(&pm);
    close(sfd);
    torrent_free(&t);
}

static void test_choker(void)
{
    puts("tit-for-tat choker");
    ChokerState s;
    choker_init(&s);

    ChokeCand c[5] = { {1, 10, 0}, {2, 500, 0}, {3, 300, 0}, {4, 0, 0}, {5, 20, 0} };
    choker_decide(&s, c, 5, 3);

    int unchoked = 0, top2 = 0;
    for (int i = 0; i < 5; i++) {
        unchoked += c[i].unchoke;
        if ((c[i].cid == 2 || c[i].cid == 3) && c[i].unchoke) top2++;
    }
    CHECK(unchoked == 3);       /* 2 regular + 1 optimistic */
    CHECK(top2 == 2);           /* the two best uploaders always get a slot */

    /* a free-rider (rate 0) only ever gets the optimistic slot, never a regular one */
    int freerider_regular = 0;
    for (int round = 0; round < 50; round++) {
        ChokeCand d[4] = { {1, 100, 0}, {2, 90, 0}, {3, 80, 0}, {4, 0, 0} };
        choker_decide(&s, d, 4, 3);                      /* 2 regular slots: peers 1 and 2 */
        for (int i = 0; i < 4; i++)
            if (d[i].cid == 3 || d[i].cid == 4) { /* optimistic candidates */ }
        for (int i = 0; i < 4; i++)
            if (d[i].cid == 4 && d[i].unchoke && d[i].rate > 0) freerider_regular++;
    }
    CHECK(freerider_regular == 0);

    ChokeCand one[1] = { {9, 0, 0} };
    choker_decide(&s, one, 1, 4);
    CHECK(one[0].unchoke == 1); /* spare slot: everybody gets served */
}

int main(void)
{
    snprintf(tmp, sizeof tmp, "/tmp/p2p_test_%d", (int)getpid());
    mkdir(tmp, 0755);

    test_sha256();
    test_pieces();
    test_choker();

    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf %s", tmp);
    if (system(cmd)) {}

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
