#ifndef FLOW_STORE_H
#define FLOW_STORE_H

#include <stdint.h>
#include <stddef.h>

#include <lmdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nm_flow_state {
    uint64_t bytes_total;
    uint64_t packets_total;
    uint64_t first_seen_ts;
    uint64_t last_seen_ts;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto_id;
    uint8_t  ndpi_proto_id;
    uint8_t  risk_score;
    uint8_t  reserved;
} nm_flow_state_t;

typedef struct flow_store flow_store_t;

int flow_store_open(flow_store_t **out,
                    const char *path,
                    size_t mapsize_bytes,
                    unsigned int max_readers);

void flow_store_close(flow_store_t *st);

int flow_store_put(flow_store_t *st,
                   uint64_t flow_hash,
                   const nm_flow_state_t *state);

int flow_store_get(flow_store_t *st,
                   uint64_t flow_hash,
                   nm_flow_state_t *out_state);

int flow_store_del(flow_store_t *st,
                   uint64_t flow_hash);

int flow_store_iter(flow_store_t *st,
                    MDB_cursor **cursor,
                    uint64_t *out_hash,
                    nm_flow_state_t *out_state);

void flow_store_iter_end(MDB_cursor *cursor);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_STORE_H */
