#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>


#define PROTO_MAGIC        "MINITRNT"   
#define PROTO_MAGIC_LEN    8
#define INFO_HASH_LEN      32           
#define PEER_ID_LEN        20
#define HANDSHAKE_LEN      (PROTO_MAGIC_LEN + INFO_HASH_LEN + PEER_ID_LEN) 

#define BLOCK_SIZE         16384u       
#define MAX_MSG_LEN        (1u << 20)   


typedef enum {
    MSG_CHOKE          = 0,
    MSG_UNCHOKE        = 1,
    MSG_INTERESTED     = 2,
    MSG_NOT_INTERESTED = 3,
    MSG_HAVE           = 4,   
    MSG_BITFIELD       = 5,   
    MSG_REQUEST        = 6, 
    MSG_PIECE          = 7,  
    MSG_CANCEL         = 8,  
    MSG_KEEPALIVE      = 255  
} msg_type;

typedef struct {
    msg_type       type;
    uint32_t       index;
    uint32_t       begin;
    uint32_t       length;     
    const uint8_t *data;       
    size_t         data_len;
} proto_msg;


size_t proto_encode_handshake(uint8_t *out,
                              const uint8_t info_hash[INFO_HASH_LEN],
                              const uint8_t peer_id[PEER_ID_LEN]);


int proto_decode_handshake(const uint8_t *in,
                           uint8_t info_hash[INFO_HASH_LEN],
                           uint8_t peer_id[PEER_ID_LEN]);


ssize_t proto_encode(const proto_msg *m, uint8_t *out, size_t cap);


ssize_t proto_decode(const uint8_t *buf, size_t len, proto_msg *out);

const char *proto_type_name(msg_type t);

#endif 
