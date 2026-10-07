#include "protocol.h"

#include <string.h>

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

size_t proto_encode_handshake(uint8_t *out,
                              const uint8_t info_hash[INFO_HASH_LEN],
                              const uint8_t peer_id[PEER_ID_LEN])
{
    memcpy(out, PROTO_MAGIC, PROTO_MAGIC_LEN);
    memcpy(out + PROTO_MAGIC_LEN, info_hash, INFO_HASH_LEN);
    memcpy(out + PROTO_MAGIC_LEN + INFO_HASH_LEN, peer_id, PEER_ID_LEN);
    return HANDSHAKE_LEN;
}

int proto_decode_handshake(const uint8_t *in,
                           uint8_t info_hash[INFO_HASH_LEN],
                           uint8_t peer_id[PEER_ID_LEN])
{
    if (memcmp(in, PROTO_MAGIC, PROTO_MAGIC_LEN) != 0)
        return -1;
    memcpy(info_hash, in + PROTO_MAGIC_LEN, INFO_HASH_LEN);
    memcpy(peer_id, in + PROTO_MAGIC_LEN + INFO_HASH_LEN, PEER_ID_LEN);
    return 0;
}

ssize_t proto_encode(const proto_msg *m, uint8_t *out, size_t cap)
{
    size_t payload = 0; /* bytes after the id byte */

    switch (m->type) {
    case MSG_KEEPALIVE:
        if (cap < 4)
            return -1;
        put32(out, 0);
        return 4;
    case MSG_CHOKE:
    case MSG_UNCHOKE:
    case MSG_INTERESTED:
    case MSG_NOT_INTERESTED:
        payload = 0;
        break;
    case MSG_HAVE:
        payload = 4;
        break;
    case MSG_BITFIELD:
        payload = m->data_len;
        break;
    case MSG_REQUEST:
    case MSG_CANCEL:
        payload = 12;
        break;
    case MSG_PIECE:
        if (m->data_len > BLOCK_SIZE)
            return -1;
        payload = 8 + m->data_len;
        break;
    default:
        return -1;
    }

    size_t len = 1 + payload;
    if (len > MAX_MSG_LEN || cap < 4 + len)
        return -1;

    put32(out, (uint32_t)len);
    out[4] = (uint8_t)m->type;
    uint8_t *p = out + 5;

    switch (m->type) {
    case MSG_HAVE:
        put32(p, m->index);
        break;
    case MSG_BITFIELD:
        if (m->data_len)
            memcpy(p, m->data, m->data_len);
        break;
    case MSG_REQUEST:
    case MSG_CANCEL:
        put32(p, m->index);
        put32(p + 4, m->begin);
        put32(p + 8, m->length);
        break;
    case MSG_PIECE:
        put32(p, m->index);
        put32(p + 4, m->begin);
        if (m->data_len)
            memcpy(p + 8, m->data, m->data_len);
        break;
    default:
        break;
    }
    return (ssize_t)(4 + len);
}

ssize_t proto_decode(const uint8_t *buf, size_t len, proto_msg *out)
{
    if (len < 4)
        return 0;

    uint32_t flen = get32(buf);
    if (flen > MAX_MSG_LEN)
        return -1;
    if (len < 4 + (size_t)flen)
        return 0;

    memset(out, 0, sizeof(*out));
    if (flen == 0) {
        out->type = MSG_KEEPALIVE;
        return 4;
    }

    uint8_t id = buf[4];
    const uint8_t *p = buf + 5;
    size_t plen = flen - 1;

    switch (id) {
    case MSG_CHOKE:
    case MSG_UNCHOKE:
    case MSG_INTERESTED:
    case MSG_NOT_INTERESTED:
        if (plen != 0)
            return -1;
        break;
    case MSG_HAVE:
        if (plen != 4)
            return -1;
        out->index = get32(p);
        break;
    case MSG_BITFIELD:
        out->data = p;
        out->data_len = plen;
        break;
    case MSG_REQUEST:
    case MSG_CANCEL:
        if (plen != 12)
            return -1;
        out->index = get32(p);
        out->begin = get32(p + 4);
        out->length = get32(p + 8);
        break;
    case MSG_PIECE:
        if (plen < 8 || plen - 8 > BLOCK_SIZE)
            return -1;
        out->index = get32(p);
        out->begin = get32(p + 4);
        out->data = p + 8;
        out->data_len = plen - 8;
        out->length = (uint32_t)out->data_len;
        break;
    default:
        return -1; /* unknown message id */
    }
    out->type = (msg_type)id;
    return (ssize_t)(4 + flen);
}

const char *proto_type_name(msg_type t)
{
    switch (t) {
    case MSG_CHOKE:          return "choke";
    case MSG_UNCHOKE:        return "unchoke";
    case MSG_INTERESTED:     return "interested";
    case MSG_NOT_INTERESTED: return "not_interested";
    case MSG_HAVE:           return "have";
    case MSG_BITFIELD:       return "bitfield";
    case MSG_REQUEST:        return "request";
    case MSG_PIECE:          return "piece";
    case MSG_CANCEL:         return "cancel";
    case MSG_KEEPALIVE:      return "keepalive";
    }
    return "unknown";
}
