
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "metadata.h"
#include "peer.h"
#include "piece_manager.h"
#include "protocol.h"

#define MAX_PEERS       50
#define SLOTS           256         
#define TRACKER_EVERY   20           


typedef struct { int piece; uint32_t next_begin; } req_slot;

typedef struct {
    uint8_t *buf;                   
    uint8_t *got;                   
    uint32_t nblk, ngot;
} assembly;

static struct {
    Torrent       t;
    PieceManager  pm;
    char          hash_hex[SHA256_LEN * 2 + 1];
    uint8_t       info_hash[SHA256_LEN];
    uint8_t       my_id[PEER_ID_LEN];
    uint16_t      port;
    char          thost[256];
    char          tport[16];

    peer_t       *peers[MAX_PEERS];
    size_t        npeers;
    int           next_id;
    req_slot      slot[SLOTS];
    assembly     *asmb;              

    uint8_t      *cache;             
    int           cache_idx;

    int           bad_pieces;
    volatile sig_atomic_t quit;
} G;

static void on_signal(int s) { (void)s; G.quit = 1; }

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}



static int op_have_piece(void *ctx, uint32_t idx) { (void)ctx; return pm_has(&G.pm, idx); }

static size_t op_get_bitfield(void *ctx, uint8_t *out, size_t cap)
{
    (void)ctx;
    size_t n = bf_bytes(G.t.num_pieces);
    if (cap < n) return 0;
    pm_snapshot(&G.pm, out);
    return n;
}

static int op_read_block(void *ctx, uint32_t idx, uint32_t begin, uint32_t len, uint8_t *out)
{
    (void)ctx;
    uint32_t plen = torrent_piece_len(&G.t, idx);
    if (plen == 0 || begin >= plen || len > plen - begin) return -1;
    if (G.cache_idx != (int)idx) {
        if (pm_read(&G.pm, idx, G.cache) != 0) return -1;
        G.cache_idx = (int)idx;
    }
    memcpy(out, G.cache + begin, len);
    return 0;
}

static void drop_assembly(uint32_t idx)
{
    assembly *a = &G.asmb[idx];
    free(a->buf);
    free(a->got);
    memset(a, 0, sizeof *a);
}

static void piece_completed(uint32_t idx)
{
    for (size_t i = 0; i < G.npeers; i++) {
        peer_announce_have(G.peers[i], idx);
        peer_refresh_interest(G.peers[i]);
    }
    printf("[peer] piece %u verified (%u/%u)\n", idx, pm_count(&G.pm), G.t.num_pieces);
    fflush(stdout);
}

static int op_write_block(void *ctx, uint32_t idx, uint32_t begin, const uint8_t *data, uint32_t len)
{
    (void)ctx;
    uint32_t plen = torrent_piece_len(&G.t, idx);
    if (plen == 0 || len == 0 || len > BLOCK_SIZE || begin % BLOCK_SIZE != 0 ||
        begin >= plen || len > plen - begin)
        return -1;
    if (pm_has(&G.pm, idx)) return 0;                 

    assembly *a = &G.asmb[idx];
    if (!a->buf) {
        a->nblk = (plen + BLOCK_SIZE - 1) / BLOCK_SIZE;
        a->buf  = malloc(plen);
        a->got  = calloc(a->nblk, 1);
        if (!a->buf || !a->got) { drop_assembly(idx); return -1; }
    }
    uint32_t b = begin / BLOCK_SIZE;
    uint32_t want = (b + 1 == a->nblk) ? plen - b * BLOCK_SIZE : BLOCK_SIZE;
    if (len != want) return -1;
    memcpy(a->buf + begin, data, len);
    if (!a->got[b]) { a->got[b] = 1; a->ngot++; }
    if (a->ngot < a->nblk) return 0;

   
    int r = pm_store(&G.pm, idx, a->buf, plen);
    drop_assembly(idx);
    if (r == 1) {
        piece_completed(idx);
    } else if (r == -1) {
        G.bad_pieces++;
        fprintf(stderr, "[peer] piece %u failed SHA-256 check, will re-download\n", idx);
        pm_release_piece(&G.pm, idx);
    } else if (r < 0) {
        pm_release_piece(&G.pm, idx);
    }
    return 0;
}

static int op_next_request(void *ctx, int id, const uint8_t *bf, size_t bf_len,
                           uint32_t *index, uint32_t *begin, uint32_t *length)
{
    (void)ctx; (void)bf_len;
    req_slot *s = &G.slot[(unsigned)id % SLOTS];

    if (s->piece >= 0 && pm_has(&G.pm, (uint32_t)s->piece)) s->piece = -1;
    if (s->piece >= 0 && s->next_begin >= torrent_piece_len(&G.t, (uint32_t)s->piece))
        s->piece = -1;
    if (s->piece < 0) {
        int p = pm_pick(&G.pm, bf, NULL, (uint32_t)id, now_s());
        if (p < 0) return 0;
        s->piece = p;
        s->next_begin = 0;
    }
    uint32_t plen = torrent_piece_len(&G.t, (uint32_t)s->piece);
    uint32_t len = plen - s->next_begin;
    if (len > BLOCK_SIZE) len = BLOCK_SIZE;
    *index = (uint32_t)s->piece;
    *begin = s->next_begin;
    *length = len;
    s->next_begin += len;
    return 1;
}

static void op_release_requests(void *ctx, int id)
{
    (void)ctx;
    req_slot *s = &G.slot[(unsigned)id % SLOTS];
    s->piece = -1;
    s->next_begin = 0;
    int n = pm_release_owner(&G.pm, (uint32_t)id);   
    if (n > 0) {
        printf("[peer] connection %d lost/choked: %d piece(s) re-queued for other peers\n", id, n);
        fflush(stdout);
    }
}

static const peer_ops OPS = {
    .ctx = NULL,
    .have_piece = op_have_piece,
    .get_bitfield = op_get_bitfield,
    .read_block = op_read_block,
    .write_block = op_write_block,
    .next_request = op_next_request,
    .release_requests = op_release_requests,
};


static int tracker_connect(void)
{
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res;
    if (getaddrinfo(G.thost, G.tport, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd >= 0) {
        struct timeval tv = { .tv_sec = 3 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) { close(fd); fd = -1; }
    }
    freeaddrinfo(res);
    return fd;
}

static int already_connected(const char *ip, uint16_t port)
{
    char addr[64];
    snprintf(addr, sizeof addr, "%s:%u", ip, port);
    for (size_t i = 0; i < G.npeers; i++)
        if (!G.peers[i]->dead && !strcmp(G.peers[i]->addr, addr)) return 1;
    return 0;
}

static void connect_to(const char *ip, uint16_t port)
{
    if (G.npeers >= MAX_PEERS || already_connected(ip, port)) return;
    int id = G.next_id++;
    G.slot[(unsigned)id % SLOTS] = (req_slot){ -1, 0 };
    peer_t *p = peer_connect(ip, port, id, G.t.num_pieces, G.info_hash, G.my_id, &OPS);
    if (!p) { printf("[peer] could not connect to %s:%u\n", ip, port); fflush(stdout); return; }
    G.peers[G.npeers++] = p;
    printf("[peer] connected to %s:%u (connection %d)\n", ip, port, id);
    fflush(stdout);
}


static void tracker_sync(void)
{
    int fd = tracker_connect();
    if (fd < 0) {
        printf("[peer] tracker %s:%s unreachable\n", G.thost, G.tport);
        fflush(stdout);
        return;
    }
    FILE *io = fdopen(fd, "r+");
    if (!io) { close(fd); return; }
    setvbuf(io, NULL, _IOLBF, 0);

    char line[256];
    fprintf(io, "REGISTER %s %u\n", G.hash_hex, G.port);
    fflush(io);
    if (!fgets(line, sizeof line, io) || strncmp(line, "OK", 2) != 0)
        printf("[peer] tracker rejected REGISTER\n");

    fprintf(io, "PEERS %s %u\n", G.hash_hex, G.port);
    fflush(io);
    int n = 0;
    if (fgets(line, sizeof line, io) && sscanf(line, "PEERS %d", &n) == 1) {
        char ips[64][INET_ADDRSTRLEN];
        unsigned ports[64];
        int got = 0;
        for (int i = 0; i < n && i < 64; i++) {
            unsigned pt;
            char ip[INET_ADDRSTRLEN];
            if (!fgets(line, sizeof line, io)) break;
            if (sscanf(line, "%15s %u", ip, &pt) == 2 && pt > 0 && pt < 65536) {
                snprintf(ips[got], sizeof ips[got], "%s", ip);
                ports[got++] = pt;
            }
        }
        for (int i = 0; i < got; i++) connect_to(ips[i], (uint16_t)ports[i]);
    }
    fprintf(io, "QUIT\n");
    fflush(io);
    fclose(io);
}

static void tracker_leave(void)
{
    int fd = tracker_connect();
    if (fd < 0) return;
    char msg[160];
    int n = snprintf(msg, sizeof msg, "LEAVE %s %u\nQUIT\n", G.hash_hex, G.port);
    if (write(fd, msg, (size_t)n) < 0) { /* best effort */ }
    close(fd);
}



static void reap_dead_and_duplicates(void)
{
    
    for (size_t i = 0; i < G.npeers; i++) {
        peer_t *a = G.peers[i];
        if (a->dead || !a->handshake_done) continue;
        int dup = !memcmp(a->remote_id, G.my_id, PEER_ID_LEN);
        for (size_t j = 0; j < i && !dup; j++)
            if (!G.peers[j]->dead && G.peers[j]->handshake_done &&
                !memcmp(G.peers[j]->remote_id, a->remote_id, PEER_ID_LEN))
                dup = 1;
        if (dup) { a->dead = 1; op_release_requests(NULL, a->id); }
    }
    size_t k = 0;
    for (size_t i = 0; i < G.npeers; i++) {
        if (G.peers[i]->dead) {
            printf("[peer] connection %d (%s) closed\n", G.peers[i]->id, G.peers[i]->addr);
            fflush(stdout);
            peer_free(G.peers[i]);
        } else {
            G.peers[k++] = G.peers[i];
        }
    }
    G.npeers = k;
}


static void refresh_availability(void)
{
    pthread_mutex_lock(&G.pm.lock);
    memset(G.pm.avail, 0, G.t.num_pieces * sizeof *G.pm.avail);
    pthread_mutex_unlock(&G.pm.lock);
    for (size_t i = 0; i < G.npeers; i++)
        if (G.peers[i]->handshake_done) pm_avail_bitfield(&G.pm, G.peers[i]->bitfield, +1);
}

static void print_status(void)
{
    printf("[status] %s: %u/%u pieces (%.1f%%), %zu peer(s), %d corrupted piece(s) rejected\n",
           G.t.name, pm_count(&G.pm), G.t.num_pieces,
           100.0 * pm_count(&G.pm) / G.t.num_pieces, G.npeers, G.bad_pieces);
}

static void print_peers(void)
{
    if (!G.npeers) puts("[peers] none");
    for (size_t i = 0; i < G.npeers; i++) {
        peer_t *p = G.peers[i];
        printf("[peers] #%d %-21s down %7.0f B/s  up %7.0f B/s  %s %s\n", p->id, p->addr,
               p->down_rate, p->up_rate, p->am_choking ? "we-choke" : "we-serve",
               p->peer_choking ? "they-choke" : "they-serve");
    }
}

static void handle_command(char *line)
{
    char ip[64];
    unsigned port;
    if (!strncmp(line, "status", 6)) print_status();
    else if (!strncmp(line, "peers", 5)) print_peers();
    else if (sscanf(line, "connect %63s %u", ip, &port) == 2 && port > 0 && port < 65536)
        connect_to(ip, (uint16_t)port);
    else if (!strncmp(line, "quit", 4) || !strncmp(line, "exit", 4)) G.quit = 1;
    else if (line[0] != '\n' && line[0] != '\0')
        puts("commands: status | peers | connect <ip> <port> | quit");
    fflush(stdout);
}

static int listen_on(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port),
                              .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
}

static void accept_one(int lfd)
{
    struct sockaddr_in ra;
    socklen_t rl = sizeof ra;
    int cfd = accept(lfd, (struct sockaddr *)&ra, &rl);
    if (cfd < 0) return;
    char ip[INET_ADDRSTRLEN], full[96];
    inet_ntop(AF_INET, &ra.sin_addr, ip, sizeof ip);
    snprintf(full, sizeof full, "%s:%u", ip, ntohs(ra.sin_port));
    int id = G.next_id++;
    G.slot[(unsigned)id % SLOTS] = (req_slot){ -1, 0 };
    peer_t *p = G.npeers < MAX_PEERS
        ? peer_new(cfd, id, full, G.t.num_pieces, G.info_hash, G.my_id, &OPS) : NULL;
    if (!p) { close(cfd); return; }
    G.peers[G.npeers++] = p;
    printf("[peer] %s connected to us (connection %d)\n", full, id);
    fflush(stdout);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s -t file.torrent -d dir -p listen_port [-T host:port] [-r lo:hi] [-x]\n", prog);
}

int main(int argc, char **argv)
{
    const char *tfile = NULL, *dir = NULL;
    int port = 0, lo = -1, hi = -1, exit_when_done = 0;
    snprintf(G.thost, sizeof G.thost, "127.0.0.1");
    snprintf(G.tport, sizeof G.tport, "6969");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) tfile = argv[++i];
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-T") && i + 1 < argc) {
            char *c = strrchr(argv[++i], ':');
            if (!c) { usage(argv[0]); return 2; }
            *c = '\0';
            snprintf(G.thost, sizeof G.thost, "%s", argv[i]);
            snprintf(G.tport, sizeof G.tport, "%s", c + 1);
        } else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            if (sscanf(argv[++i], "%d:%d", &lo, &hi) != 2) { usage(argv[0]); return 2; }
        } else if (!strcmp(argv[i], "-x")) exit_when_done = 1;
        else { usage(argv[0]); return 2; }
    }
    if (!tfile || !dir || port <= 0 || port > 65535) { usage(argv[0]); return 2; }
    G.port = (uint16_t)port;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (torrent_load(&G.t, tfile) != 0) { fprintf(stderr, "cannot load %s\n", tfile); return 1; }
    torrent_info_hash(&G.t, G.info_hash);
    hex_encode(G.info_hash, SHA256_LEN, G.hash_hex);

    if (pm_open(&G.pm, &G.t, dir, lo, hi) != 0) return 1;
    G.asmb  = calloc(G.t.num_pieces, sizeof *G.asmb);
    G.cache = malloc(G.t.piece_size);
    G.cache_idx = -1;
    if (!G.asmb || !G.cache) return 1;
    for (int i = 0; i < SLOTS; i++) G.slot[i].piece = -1;

    memcpy(G.my_id, "-MT0001-", 8);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for (int i = 8; i < PEER_ID_LEN; i++) G.my_id[i] = (uint8_t)(rand() & 0xFF);

    int lfd = listen_on(G.port);
    if (lfd < 0) { perror("listen"); return 1; }

    printf("[peer] %s  info hash %.16s...  listening on port %u\n", G.t.name, G.hash_hex, G.port);
    print_status();
    puts("[peer] commands: status | peers | connect <ip> <port> | quit");
    fflush(stdout);

    int announced_done = pm_complete(&G.pm);
    int stdin_open = 1;
    time_t last_tracker = 0, last_avail = 0;
    choker_state cs;
    choker_init(&cs);

    while (!G.quit) {
        time_t now = time(NULL);

        if (now - last_tracker >= TRACKER_EVERY) { tracker_sync(); last_tracker = time(NULL); }
        if (now - last_avail >= 1) { refresh_availability(); last_avail = now; }

        
        struct pollfd pf[2] = { { .fd = lfd, .events = POLLIN },
                                { .fd = stdin_open ? STDIN_FILENO : -1, .events = POLLIN } };
        if (poll(pf, 2, 0) > 0) {
            if (pf[0].revents & POLLIN) accept_one(lfd);
            if (pf[1].revents & (POLLIN | POLLHUP)) {
                char cmd[128];
                if (!fgets(cmd, sizeof cmd, stdin)) stdin_open = 0;  
                else handle_command(cmd);
            }
        }

        if (G.npeers) peer_poll(G.peers, G.npeers, 100, time(NULL));
        else usleep(100000);

        reap_dead_and_duplicates();
        peer_apply_choker(G.peers, G.npeers, &cs, pm_complete(&G.pm), time(NULL));

        if (!announced_done && pm_complete(&G.pm)) {
            announced_done = 1;
            printf("[peer] DOWNLOAD COMPLETE: %s/%s (all %u pieces verified with SHA-256)\n",
                   dir, G.t.name, G.t.num_pieces);
            fflush(stdout);
            if (exit_when_done) break;
        }
    }

    puts("[peer] shutting down");
    tracker_leave();
    for (size_t i = 0; i < G.npeers; i++) peer_free(G.peers[i]);
    close(lfd);
    pm_close(&G.pm);
    torrent_free(&G.t);
    return 0;
}
