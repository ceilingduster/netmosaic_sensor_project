#include "sensor.h"

static size_t next_power_of_two_local(size_t value) {
    size_t n = 1;
    while (n < value) {
        n <<= 1;
    }
    return n;
}

bool flow_table_init(flow_table_t *table, size_t capacity) {
    memset(table, 0, sizeof(*table));
    table->capacity = next_power_of_two_local(capacity);
    table->entries = (flow_entry_t *)calloc(table->capacity, sizeof(flow_entry_t));
    return table->entries != NULL;
}

void flow_table_free(flow_table_t *table) {
    if (!table || !table->entries) {
        return;
    }
    for (size_t i = 0; i < table->capacity; ++i) {
        flow_entry_t *entry = &table->entries[i];
        if (entry->in_use && entry->ndpi_flow) {
            ndpi_free_flow(entry->ndpi_flow);
            entry->ndpi_flow = NULL;
        }
    }
    free(table->entries);
    table->entries = NULL;
    table->capacity = 0;
}

void flow_table_release(flow_entry_t *entry) {
    if (!entry) {
        return;
    }
    if (entry->ndpi_flow) {
        ndpi_free_flow(entry->ndpi_flow);
        entry->ndpi_flow = NULL;
    }
    memset(entry, 0, sizeof(*entry));
}

flow_entry_t *flow_table_acquire(flow_table_t *table, const flow_key_t *key, uint64_t hash, bool *is_new) {
    if (table->capacity == 0) {
        return NULL;
    }
    size_t index = hash & (table->capacity - 1);
    for (size_t i = 0; i < table->capacity; ++i) {
        flow_entry_t *entry = &table->entries[index];
        if (!entry->in_use) {
            if (is_new) *is_new = true;
            entry->in_use = true;
            entry->hash = hash;
            entry->key = *key;
            entry->bytes = 0;
            entry->packets = 0;
            entry->bytes_inbound = 0;
            entry->bytes_outbound = 0;
            entry->packets_inbound = 0;
            entry->packets_outbound = 0;
            entry->first_seen = get_time_seconds();
            entry->last_seen = entry->first_seen;
            entry->risk = 0;
            entry->dropped_packets = 0;
            entry->reported = false;
            entry->payload_reported = false;
            entry->final_reported = false;
            entry->fin_seen_outbound = false;
            entry->fin_seen_inbound = false;
            entry->ndpi_finalized = false;
            entry->last_reported_master = NDPI_PROTOCOL_UNKNOWN;
            entry->last_reported_app = NDPI_PROTOCOL_UNKNOWN;
            entry->last_reported_risk = 0;
            entry->last_reported_drops = 0;
            entry->last_reported_bytes = 0;
            entry->last_reported_packets = 0;
            memset(&entry->detected, 0, sizeof(entry->detected));
            entry->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
            if (entry->ndpi_flow) {
                memset(entry->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
            }
            return entry;
        }
        if (entry->hash == hash && memcmp(&entry->key, key, sizeof(flow_key_t)) == 0) {
            if (is_new) *is_new = false;
            return entry;
        }
        index = (index + 1) & (table->capacity - 1);
    }
    return NULL;
}

void metadata_to_flow_key(const packet_metadata_t *meta, flow_key_t *key) {
    memset(key, 0, sizeof(*key));
    key->ipv6 = meta->ipv6;
    key->proto = meta->proto;
    const uint8_t *src_ip = meta->src_ip;
    const uint8_t *dst_ip = meta->dst_ip;
    uint16_t src_port = meta->src_port;
    uint16_t dst_port = meta->dst_port;
    size_t addr_len = meta->ipv6 ? 16u : 4u;

    bool preserve_order = true;
    int cmp = memcmp(src_ip, dst_ip, addr_len);
    if (cmp > 0) {
        preserve_order = false;
    } else if (cmp == 0 && src_port > dst_port) {
        preserve_order = false;
    }

    if (preserve_order) {
        key->src_port = src_port;
        key->dst_port = dst_port;
        memcpy(key->src_ip, src_ip, addr_len);
        memcpy(key->dst_ip, dst_ip, addr_len);
    } else {
        key->src_port = dst_port;
        key->dst_port = src_port;
        memcpy(key->src_ip, dst_ip, addr_len);
        memcpy(key->dst_ip, src_ip, addr_len);
    }
}

uint64_t flow_hash_from_key(const flow_key_t *key) {
    return fnv1a64(key, sizeof(*key));
}

static void format_ipv4(const uint8_t ip[4], char *buffer, size_t buffer_len) {
    snprintf(buffer, buffer_len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void format_ipv6(const uint8_t ip[16], char *buffer, size_t buffer_len) {
    inet_ntop(AF_INET6, ip, buffer, (socklen_t)buffer_len);
}

void format_ip_string(const packet_metadata_t *meta, bool source, char *buffer, size_t buffer_len) {
    if (meta->ipv6) {
        format_ipv6(source ? meta->src_ip : meta->dst_ip, buffer, buffer_len);
    } else {
        format_ipv4(source ? meta->src_ip : meta->dst_ip, buffer, buffer_len);
    }
}

bool parse_packet_metadata(const uint8_t *packet,
                           UINT packet_len,
                           const WINDIVERT_ADDRESS *addr,
                           packet_metadata_t *meta) {
    PWINDIVERT_IPHDR ip4 = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    UINT8 protocol = 0;
    PVOID data = NULL;
    UINT data_len = 0;

    if (!WinDivertHelperParsePacket(packet, packet_len, &ip4, &ip6, &protocol,
                                    NULL, NULL, &tcp, &udp, &data, &data_len, NULL, NULL)) {
        return false;
    }

    memset(meta, 0, sizeof(*meta));
    meta->timestamp_ns = get_time_nanoseconds();
    meta->outbound = addr->Outbound != 0;
    meta->proto = protocol;
    meta->payload_len = data_len;

    if (ip4) {
        meta->ipv6 = false;
        memcpy(meta->src_ip, &ip4->SrcAddr, 4);
        memcpy(meta->dst_ip, &ip4->DstAddr, 4);
    } else if (ip6) {
        meta->ipv6 = true;
        memcpy(meta->src_ip, &ip6->SrcAddr, 16);
        memcpy(meta->dst_ip, &ip6->DstAddr, 16);
    } else {
        return false;
    }

    if (tcp) {
        meta->src_port = ntohs(tcp->SrcPort);
        meta->dst_port = ntohs(tcp->DstPort);
        meta->tcp_fin = tcp->Fin != 0;
        meta->tcp_rst = tcp->Rst != 0;
    } else if (udp) {
        meta->src_port = ntohs(udp->SrcPort);
        meta->dst_port = ntohs(udp->DstPort);
    } else {
        meta->src_port = 0;
        meta->dst_port = 0;
    }

    return true;
}
