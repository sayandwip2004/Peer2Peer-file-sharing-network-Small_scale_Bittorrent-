#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* ---- Wire constants ---------------------------------------------------- */
#define PROTO_MAGIC        "MINITRNT"   /* 8 bytes, identifies the protocol */
#define PROTO_MAGIC_LEN    8
#define INFO_HASH_LEN      32           /* SHA-256 (see sha256.h) */
#define PEER_ID_LEN        20
#define HANDSHAKE_LEN      (PROTO_MAGIC_LEN + INFO_HASH_LEN + PEER_ID_LEN) /* 60 */

#define BLOCK_SIZE         16384u       /* max payload of one PIECE message */
#define MAX_MSG_LEN        (1u << 20)   /* upper bound on <len> field */

/*
 * Framing: every message after the handshake is
 *     <len : uint32 big-endian> <id : 1 byte> <payload : len-1 bytes>
 * len == 0 is a keep-alive (no id, no payload).
 */
typedef enum {
    MSG_CHOKE          = 0,
    MSG_UNCHOKE        = 1,
    MSG_INTERESTED     = 2,
    MSG_NOT_INTERESTED = 3,
    MSG_HAVE           = 4,   /* payload: index                      */
    MSG_BITFIELD       = 5,   /* payload: bitfield bytes             */
    MSG_REQUEST        = 6,   /* payload: index, begin, length       */
    MSG_PIECE          = 7,   /* payload: index, begin, block data   */
    MSG_CANCEL         = 8,   /* payload: index, begin, length       */
    MSG_KEEPALIVE      = 255  /* pseudo id: zero-length frame        */
} msg_type;

typedef struct {
    msg_type       type;
    uint32_t       index;
    uint32_t       begin;
    uint32_t       length;     /* REQUEST/CANCEL length; PIECE: data_len */
    const uint8_t *data;       /* BITFIELD bytes or PIECE block (borrowed) */
    size_t         data_len;
} proto_msg;

/* Handshake: writes HANDSHAKE_LEN bytes into out, returns HANDSHAKE_LEN. */
size_t proto_encode_handshake(uint8_t *out,
                              const uint8_t info_hash[INFO_HASH_LEN],
                              const uint8_t peer_id[PEER_ID_LEN]);

/* Returns 0 on success, -1 if the magic string is wrong. in must hold
 * HANDSHAKE_LEN bytes. */
int proto_decode_handshake(const uint8_t *in,
                           uint8_t info_hash[INFO_HASH_LEN],
                           uint8_t peer_id[PEER_ID_LEN]);

/* Serialise a message. Returns bytes written, or -1 if cap is too small or
 * the message is invalid/too large. */
ssize_t proto_encode(const proto_msg *m, uint8_t *out, size_t cap);

/* Parse one message from the front of buf.
 *   > 0 : bytes consumed, *out filled (data points into buf)
 *   == 0: incomplete frame, need more bytes
 *   < 0 : protocol violation, caller must drop the connection */
ssize_t proto_decode(const uint8_t *buf, size_t len, proto_msg *out);

const char *proto_type_name(msg_type t);

#endif /* PROTOCOL_H */
