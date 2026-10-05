/*
 * tracker - lightweight peer-discovery server. It never sees file data.
 *
 *   usage: tracker [port]            (default 6969)
 *
 * Line-based text protocol over TCP. <hash> is the 64-hex-char info hash that
 * `mktorrent` prints. The peer's IP is taken from the connection itself.
 *
 *   REGISTER <hash> <port>   announce "I am listening on <port>" (repeat as heartbeat)
 *                            -> OK
 *   PEERS <hash> [port]      list peers in the swarm, omitting the caller's own <port>
 *                            -> PEERS <n>\n  followed by n lines "<ip> <port>"
 *   LEAVE <hash> <port>      remove this peer                      -> OK
 *   QUIT                     close the connection                  -> BYE
 *
 * Errors are answered with "ERR <reason>". Peers that have not re-registered for
 * PEER_TTL seconds are dropped.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT   6969
#define PEER_TTL       120      /* seconds without a REGISTER before a peer is forgotten */
#define IDLE_TIMEOUT   30       /* seconds a client may stay silent */
#define MAX_ENTRIES    4096
#define MAX_REPLY      50       /* peers returned per PEERS request */
#define HASH_HEX_LEN   64
#define MAX_LINE       256

typedef struct {
    int      used;
    char     hash[HASH_HEX_LEN + 1];
    uint32_t ip;                 /* network byte order */
    uint16_t port;               /* host byte order */
    time_t   last_seen;
} Entry;

static Entry           table[MAX_ENTRIES];
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- peer table (caller must hold table_lock) ---- */

static void expire_locked(time_t now)
{
    for (int i = 0; i < MAX_ENTRIES; i++)
        if (table[i].used && now - table[i].last_seen > PEER_TTL)
            table[i].used = 0;
}

static int register_peer(const char *hash, uint32_t ip, uint16_t port)
{
    time_t now = time(NULL);
    int rc = -1;
    pthread_mutex_lock(&table_lock);
    expire_locked(now);

    int freeslot = -1;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (!table[i].used) { if (freeslot < 0) freeslot = i; continue; }
        if (table[i].ip == ip && table[i].port == port && !strcmp(table[i].hash, hash)) {
            table[i].last_seen = now;                     /* heartbeat */
            rc = 0;
            goto out;
        }
    }
    if (freeslot >= 0) {
        Entry *e = &table[freeslot];
        e->used = 1;
        strcpy(e->hash, hash);
        e->ip = ip;
        e->port = port;
        e->last_seen = now;
        rc = 0;
    }
out:
    pthread_mutex_unlock(&table_lock);
    return rc;
}

static void remove_peer(const char *hash, uint32_t ip, uint16_t port)
{
    pthread_mutex_lock(&table_lock);
    for (int i = 0; i < MAX_ENTRIES; i++)
        if (table[i].used && table[i].ip == ip && table[i].port == port && !strcmp(table[i].hash, hash))
            table[i].used = 0;
    pthread_mutex_unlock(&table_lock);
}

/* Copy up to MAX_REPLY peers of this swarm (except self) into out; returns the count. */
static int list_peers(const char *hash, uint32_t self_ip, int self_port, Entry *out)
{
    int n = 0;
    pthread_mutex_lock(&table_lock);
    expire_locked(time(NULL));
    for (int i = 0; i < MAX_ENTRIES && n < MAX_REPLY; i++) {
        if (!table[i].used || strcmp(table[i].hash, hash)) continue;
        if (self_port >= 0 && table[i].ip == self_ip && table[i].port == self_port) continue;
        out[n++] = table[i];
    }
    pthread_mutex_unlock(&table_lock);
    return n;
}

/* ---- protocol helpers ---- */

static int valid_hash(const char *s)
{
    if (strlen(s) != HASH_HEX_LEN) return 0;
    for (; *s; s++)
        if (!isxdigit((unsigned char)*s)) return 0;
    return 1;
}

static void lower(char *s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }

static int parse_port(const char *s)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || v < 1 || v > 65535) return -1;
    return (int)v;
}

typedef struct {
    int                fd;
    struct sockaddr_in addr;
} Client;

static void *client_thread(void *arg)
{
    Client *c = arg;
    int fd = c->fd;
    uint32_t ip = c->addr.sin_addr.s_addr;
    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->addr.sin_addr, ipstr, sizeof ipstr);
    free(c);

    struct timeval tv = { .tv_sec = IDLE_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    FILE *in  = fdopen(fd, "r");
    FILE *out = fdopen(dup(fd), "w");
    if (!in || !out) { if (in) fclose(in); else close(fd); if (out) fclose(out); return NULL; }

    char line[MAX_LINE];
    while (fgets(line, sizeof line, in)) {
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') {      /* over-long line: give up */
            fprintf(out, "ERR line too long\n");
            break;
        }

        char *save = NULL;
        char *cmd = strtok_r(line, " \t\r\n", &save);
        if (!cmd) continue;
        char *a1 = strtok_r(NULL, " \t\r\n", &save);
        char *a2 = strtok_r(NULL, " \t\r\n", &save);

        if (!strcasecmp(cmd, "QUIT")) {
            fprintf(out, "BYE\n");
            fflush(out);
            break;
        } else if (!strcasecmp(cmd, "REGISTER") || !strcasecmp(cmd, "LEAVE")) {
            if (!a1 || !a2 || !valid_hash(a1) || parse_port(a2) < 0) {
                fprintf(out, "ERR usage: %s <hash> <port>\n", cmd);
            } else {
                lower(a1);
                uint16_t port = (uint16_t)parse_port(a2);
                if (!strcasecmp(cmd, "REGISTER")) {
                    if (register_peer(a1, ip, port) == 0) {
                        printf("[tracker] register %s:%u  swarm %.8s\n", ipstr, port, a1);
                        fprintf(out, "OK\n");
                    } else {
                        fprintf(out, "ERR tracker full\n");
                    }
                } else {
                    remove_peer(a1, ip, port);
                    printf("[tracker] leave    %s:%u  swarm %.8s\n", ipstr, port, a1);
                    fprintf(out, "OK\n");
                }
                fflush(stdout);
            }
        } else if (!strcasecmp(cmd, "PEERS")) {
            int self = a2 ? parse_port(a2) : -1;
            if (!a1 || !valid_hash(a1) || (a2 && self < 0)) {
                fprintf(out, "ERR usage: PEERS <hash> [port]\n");
            } else {
                lower(a1);
                Entry list[MAX_REPLY];
                int n = list_peers(a1, ip, self, list);
                fprintf(out, "PEERS %d\n", n);
                for (int i = 0; i < n; i++) {
                    struct in_addr ia = { .s_addr = list[i].ip };
                    char s[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ia, s, sizeof s);
                    fprintf(out, "%s %u\n", s, list[i].port);
                }
            }
        } else {
            fprintf(out, "ERR unknown command\n");
        }
        if (fflush(out) != 0) break;
    }

    fclose(out);
    fclose(in);
    return NULL;
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    if (argc > 2 || (argc == 2 && (port = parse_port(argv[1])) < 0)) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                              .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }
    if (listen(ls, 64) < 0) { perror("listen"); return 1; }

    printf("[tracker] listening on port %d\n", port);
    fflush(stdout);

    for (;;) {
        Client *c = malloc(sizeof *c);
        if (!c) { sleep(1); continue; }
        socklen_t al = sizeof c->addr;
        c->fd = accept(ls, (struct sockaddr *)&c->addr, &al);
        if (c->fd < 0) {
            free(c);
            if (errno != EINTR) perror("accept");
            continue;
        }
        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, c) != 0) {
            close(c->fd);
            free(c);
            continue;
        }
        pthread_detach(th);
    }
}
