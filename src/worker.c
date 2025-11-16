#include "sensor.h"

#define NDPI_SERIALIZER_INIT_BUFFER   (MAX_JSON_BUFFER * 2)

static THREAD_LOCAL const packet_metadata_t *tls_packet_meta = NULL;
static THREAD_LOCAL const flow_entry_t *tls_flow_entry = NULL;
static THREAD_LOCAL const char *tls_flow_hash_hex = NULL;
static THREAD_LOCAL struct ndpi_detection_module_struct *tls_ndpi_module = NULL;

typedef struct flow_identity {
    bool ipv6;
    uint16_t local_port;
    uint16_t remote_port;
    union {
        struct {
            uint32_t local;
            uint32_t remote;
        } v4;
        struct {
            uint8_t local[16];
            uint8_t remote[16];
        } v6;
    } addr;
} flow_identity_t;

static void build_flow_identity(const packet_metadata_t *meta, flow_identity_t *id) {
    memset(id, 0, sizeof(*id));
    id->ipv6 = meta->ipv6;
    id->local_port = meta->outbound ? meta->src_port : meta->dst_port;
    id->remote_port = meta->outbound ? meta->dst_port : meta->src_port;
    if (meta->ipv6) {
        memcpy(id->addr.v6.local, meta->outbound ? meta->src_ip : meta->dst_ip, 16);
        memcpy(id->addr.v6.remote, meta->outbound ? meta->dst_ip : meta->src_ip, 16);
    } else {
        memcpy(&id->addr.v4.local, meta->outbound ? meta->src_ip : meta->dst_ip, sizeof(uint32_t));
        memcpy(&id->addr.v4.remote, meta->outbound ? meta->dst_ip : meta->src_ip, sizeof(uint32_t));
    }
}

static DWORD lookup_tcp_pid(const flow_identity_t *id) {
    ULONG size = 0;
    DWORD family = id->ipv6 ? AF_INET6 : AF_INET;
    DWORD err = GetExtendedTcpTable(NULL, &size, TRUE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (err != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }

    void *buffer = malloc(size);
    if (!buffer) {
        return 0;
    }

    err = GetExtendedTcpTable(buffer, &size, TRUE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (err != NO_ERROR) {
        free(buffer);
        return 0;
    }

    DWORD pid = 0;
    if (id->ipv6) {
        PMIB_TCP6TABLE_OWNER_PID table6 = (PMIB_TCP6TABLE_OWNER_PID)buffer;
        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
            const MIB_TCP6ROW_OWNER_PID *row = &table6->table[i];
            if (memcmp(row->ucLocalAddr, id->addr.v6.local, 16) != 0) continue;
            if (memcmp(row->ucRemoteAddr, id->addr.v6.remote, 16) != 0) continue;
            if (ntohs((u_short)row->dwLocalPort) != id->local_port) continue;
            if (ntohs((u_short)row->dwRemotePort) != id->remote_port) continue;
            pid = row->dwOwningPid;
            break;
        }
    } else {
        PMIB_TCPTABLE_OWNER_PID table4 = (PMIB_TCPTABLE_OWNER_PID)buffer;
        for (DWORD i = 0; i < table4->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID *row = &table4->table[i];
            if (row->dwLocalAddr != id->addr.v4.local) continue;
            if (row->dwRemoteAddr != id->addr.v4.remote) continue;
            if (ntohs((u_short)row->dwLocalPort) != id->local_port) continue;
            if (ntohs((u_short)row->dwRemotePort) != id->remote_port) continue;
            pid = row->dwOwningPid;
            break;
        }
    }

    free(buffer);
    return pid;
}

static DWORD lookup_udp_pid(const flow_identity_t *id) {
    ULONG size = 0;
    DWORD family = id->ipv6 ? AF_INET6 : AF_INET;
    DWORD err = GetExtendedUdpTable(NULL, &size, TRUE, family, UDP_TABLE_OWNER_PID, 0);
    if (err != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }

    void *buffer = malloc(size);
    if (!buffer) {
        return 0;
    }

    err = GetExtendedUdpTable(buffer, &size, TRUE, family, UDP_TABLE_OWNER_PID, 0);
    if (err != NO_ERROR) {
        free(buffer);
        return 0;
    }

    DWORD pid = 0;
    if (id->ipv6) {
        PMIB_UDP6TABLE_OWNER_PID table6 = (PMIB_UDP6TABLE_OWNER_PID)buffer;
        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
            const MIB_UDP6ROW_OWNER_PID *row = &table6->table[i];
            if (memcmp(row->ucLocalAddr, id->addr.v6.local, 16) != 0) continue;
            if (ntohs((u_short)row->dwLocalPort) != id->local_port) continue;
            pid = row->dwOwningPid;
            break;
        }
    } else {
        PMIB_UDPTABLE_OWNER_PID table4 = (PMIB_UDPTABLE_OWNER_PID)buffer;
        for (DWORD i = 0; i < table4->dwNumEntries; ++i) {
            const MIB_UDPROW_OWNER_PID *row = &table4->table[i];
            if (row->dwLocalAddr != id->addr.v4.local) continue;
            if (ntohs((u_short)row->dwLocalPort) != id->local_port) continue;
            pid = row->dwOwningPid;
            break;
        }
    }

    free(buffer);
    return pid;
}

static DWORD resolve_flow_pid(const packet_metadata_t *meta) {
    flow_identity_t id;
    build_flow_identity(meta, &id);
    if (meta->proto == IPPROTO_TCP) {
        return lookup_tcp_pid(&id);
    }
    if (meta->proto == IPPROTO_UDP) {
        return lookup_udp_pid(&id);
    }
    return 0;
}

static void worker_set_config(worker_context_t *worker, const char *proto, const char *param, const char *value) {
    if (!worker || !worker->ndpi_module) {
        return;
    }
    ndpi_cfg_error err = ndpi_set_config(worker->ndpi_module, proto, param, value);
    if (err != NDPI_CFG_OK) {
        fprintf(stderr, "[worker %d] ndpi_set_config %s.%s=%s failed (%d)\n",
                worker->worker_id,
                proto ? proto : "global",
                param,
                value,
                err);
    }
}

static void worker_set_config_u64(worker_context_t *worker, const char *proto, const char *param, uint64_t value) {
    if (!worker || !worker->ndpi_module) {
        return;
    }
    ndpi_cfg_error err = ndpi_set_config_u64(worker->ndpi_module, proto, param, value);
    if (err != NDPI_CFG_OK) {
        fprintf(stderr, "[worker %d] ndpi_set_config_u64 %s.%s=%llu failed (%d)\n",
                worker->worker_id,
                proto ? proto : "global",
                param,
                (unsigned long long)value,
                err);
    }
}

static int lua_helper_get_src_ip(lua_State *L) {
    if (!tls_packet_meta) {
        return 0;
    }
    char buffer[MAX_IP_STRING];
    format_ip_string(tls_packet_meta, true, buffer, sizeof(buffer));
    lua_pushstring(L, buffer);
    return 1;
}

static int lua_helper_get_dst_ip(lua_State *L) {
    if (!tls_packet_meta) {
        return 0;
    }
    char buffer[MAX_IP_STRING];
    format_ip_string(tls_packet_meta, false, buffer, sizeof(buffer));
    lua_pushstring(L, buffer);
    return 1;
}

static int lua_helper_get_flow_hash(lua_State *L) {
    if (!tls_flow_hash_hex) {
        return 0;
    }
    lua_pushstring(L, tls_flow_hash_hex);
    return 1;
}

static int lua_helper_get_sni(lua_State *L) {
    if (!tls_flow_entry || !tls_flow_entry->ndpi_flow) {
        return 0;
    }
    const char *sni = tls_flow_entry->ndpi_flow->host_server_name;
    if (sni && sni[0]) {
        lua_pushstring(L, sni);
        return 1;
    }
    return 0;
}

static int lua_helper_get_proto(lua_State *L) {
    if (!tls_flow_entry) {
        return 0;
    }
    const char *master = "";
    const char *app = "";
    if (tls_ndpi_module) {
        if (tls_flow_entry->detected.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            master = ndpi_get_proto_name(tls_ndpi_module, tls_flow_entry->detected.proto.master_protocol);
        }
        if (tls_flow_entry->detected.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            app = ndpi_get_proto_name(tls_ndpi_module, tls_flow_entry->detected.proto.app_protocol);
        }
    }
    lua_pushstring(L, master ? master : "");
    lua_pushstring(L, app ? app : "");
    return 2;
}

static void lua_install_helpers(lua_State *L) {
    lua_pushcfunction(L, lua_helper_get_src_ip);
    lua_setglobal(L, "get_src_ip");
    lua_pushcfunction(L, lua_helper_get_dst_ip);
    lua_setglobal(L, "get_dst_ip");
    lua_pushcfunction(L, lua_helper_get_sni);
    lua_setglobal(L, "get_sni");
    lua_pushcfunction(L, lua_helper_get_flow_hash);
    lua_setglobal(L, "get_flow_hash");
    lua_pushcfunction(L, lua_helper_get_proto);
    lua_setglobal(L, "get_proto");
}

bool worker_prepare_lua(worker_context_t *worker) {
    worker->lua_script_count = 0;
    for (size_t i = 0; i < worker->runtime->script_count; ++i) {
        lua_State *L = luaL_newstate();
        if (!L) {
            fprintf(stderr, "[worker %d] failed to allocate lua state\n", worker->worker_id);
            return false;
        }
        luaL_openlibs(L);
        lua_install_helpers(L);

        if (luaL_loadfile(L, worker->runtime->scripts[i].path) != LUA_OK) {
            fprintf(stderr, "[worker %d] lua load error %s: %s\n", worker->worker_id,
                    worker->runtime->scripts[i].path, lua_tostring(L, -1));
            lua_close(L);
            continue;
        }
        if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
            fprintf(stderr, "[worker %d] lua runtime error %s: %s\n", worker->worker_id,
                    worker->runtime->scripts[i].path, lua_tostring(L, -1));
            lua_close(L);
            continue;
        }

        lua_getglobal(L, "on_packet");
        if (!lua_isfunction(L, -1)) {
            fprintf(stderr, "[worker %d] script %s missing on_packet()\n", worker->worker_id,
                    worker->runtime->scripts[i].path);
            lua_pop(L, 1);
            lua_close(L);
            continue;
        }
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);

        worker->lua_scripts[worker->lua_script_count].L = L;
        worker->lua_scripts[worker->lua_script_count].on_packet_ref = ref;
        worker->lua_scripts[worker->lua_script_count].descriptor = worker->runtime->scripts[i];
        worker->lua_script_count++;
    }
    return true;
}

static bool lua_table_to_json(lua_State *L, int index, json_builder_t *jb);

static bool lua_value_to_json(lua_State *L, json_builder_t *jb, const char *key) {
    int type = lua_type(L, -1);
    switch (type) {
    case LUA_TSTRING:
        return jb_add_string(jb, key, lua_tostring(L, -1));
    case LUA_TBOOLEAN:
        return jb_add_bool(jb, key, lua_toboolean(L, -1) != 0);
    case LUA_TNUMBER:
        if (lua_isinteger(L, -1)) {
            return jb_add_int64(jb, key, lua_tointeger(L, -1));
        }
        return jb_add_double(jb, key, lua_tonumber(L, -1));
    case LUA_TTABLE:
        if (!jb_begin_object_field(jb, key)) return false;
        if (!lua_table_to_json(L, lua_gettop(L), jb)) return false;
        if (!jb_close_object(jb)) return false;
        return true;
    default:
        return true;
    }
}

static bool lua_table_to_json(lua_State *L, int index, json_builder_t *jb) {
    int abs_idx = lua_absindex(L, index);
    lua_pushnil(L);
    while (lua_next(L, abs_idx) != 0) {
        if (lua_type(L, -2) == LUA_TSTRING) {
            const char *key = lua_tostring(L, -2);
            if (!lua_value_to_json(L, jb, key)) {
                lua_pop(L, 1);
                return false;
            }
        }
        lua_pop(L, 1);
    }
    return true;
}

static bool lua_table_is_empty(lua_State *L, int index) {
    int abs_idx = lua_absindex(L, index);
    lua_pushnil(L);
    if (lua_next(L, abs_idx) == 0) {
        return true;
    }
    lua_pop(L, 1);
    lua_pop(L, 1);
    return false;
}

bool runtime_is_quarantine_permitted(sensor_runtime_t *rt, const packet_metadata_t *meta) {
    if (!rt || !meta || !rt->config->quarantine_mode) {
        return true;
    }
    return !meta->outbound;
}

static void worker_set_detection_bitmask(worker_context_t *worker) {
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_RESET(all);
    NDPI_BITMASK_SET_ALL(all);
    if (ndpi_set_protocol_detection_bitmask2(worker->ndpi_module, &all) != 0) {
        fprintf(stderr, "[worker %d] failed to set nDPI detection bitmask\n", worker->worker_id);
    }
}

static void worker_apply_ndpi_config(worker_context_t *worker) {
    static const struct {
        const char *proto;
        const char *param;
        const char *value;
    } string_cfg[] = {
        { NULL, "flow.track_payload", "enable" },
        { NULL, "flow.direction_detection", "enable" },
        { NULL, "flow.use_client_ip_in_guess", "enable" },
        { NULL, "flow.use_client_port_in_guess", "enable" },
        { NULL, "metadata.tcp_fingerprint", "enable" },
        { NULL, "fpc", "enable" },
        { NULL, "dpi.guess_ip_before_port", "enable" },
        { NULL, "dpi.compute_entropy", "1" },
        { "dns", "process_response", "enable" },
        { "dns", "subclassification", "enable" },
        { "http", "process_response", "enable" },
        { "http", "subclassification", "enable" },
        { "http", "metadata.request_content_type", "enable" },
        { "http", "metadata.referer", "enable" },
        { "http", "metadata.host", "enable" },
        { "tls", "application_blocks_tracking", "enable" },
        { "tls", "metadata.sha1_fingerprint", "enable" },
        { "tls", "metadata.versions_supported", "enable" },
        { "tls", "metadata.alpn_negotiated", "enable" },
        { "tls", "metadata.cipher", "enable" },
        { "tls", "metadata.cert_server_names", "enable" },
        { "tls", "metadata.cert_validity", "enable" },
        { "tls", "metadata.cert_issuer", "enable" },
        { "tls", "metadata.cert_subject", "enable" },
        { "tls", "metadata.ja3s_fingerprint", "enable" },
        { "tls", "metadata.ja4c_fingerprint", "enable" },
        { "tls", "metadata.ja4r_fingerprint", "enable" },
        { "tls", "subclassification", "enable" },
        { "quic", "subclassification", "enable" },
    };

    for (size_t i = 0; i < ARRAYSIZE(string_cfg); ++i) {
        worker_set_config(worker, string_cfg[i].proto, string_cfg[i].param, string_cfg[i].value);
    }

    worker_set_config_u64(worker, NULL, "dpi.guess_on_giveup", 0x3);
}

static bool worker_append_ndpi_json(worker_context_t *worker,
                                    const flow_entry_t *entry,
                                    const packet_metadata_t *meta,
                                    json_builder_t *jb) {
    if (!entry || !entry->ndpi_flow || !worker || !jb || !worker->ndpi_serializer_ready) {
        return false;
    }
    ndpi_serializer *serializer = &worker->ndpi_serializer;
    ndpi_reset_serializer(serializer);

    uint32_t src_v4 = 0;
    uint32_t dst_v4 = 0;
    struct ndpi_in6_addr src_v6;
    struct ndpi_in6_addr dst_v6;
    struct ndpi_in6_addr *src_v6_ptr = NULL;
    struct ndpi_in6_addr *dst_v6_ptr = NULL;
    memset(&src_v6, 0, sizeof(src_v6));
    memset(&dst_v6, 0, sizeof(dst_v6));

    if (meta->ipv6) {
        memcpy(&src_v6, meta->src_ip, sizeof(src_v6));
        memcpy(&dst_v6, meta->dst_ip, sizeof(dst_v6));
        src_v6_ptr = &src_v6;
        dst_v6_ptr = &dst_v6;
    } else {
        memcpy(&src_v4, meta->src_ip, sizeof(src_v4));
        memcpy(&dst_v4, meta->dst_ip, sizeof(dst_v4));
    }

    ndpi_protocol proto_for_json = entry->detected;
    int rc = ndpi_flow2json(worker->ndpi_module,
                            entry->ndpi_flow,
                            meta->ipv6 ? 6 : 4,
                            meta->proto,
                            0,
                            src_v4,
                            dst_v4,
                            src_v6_ptr,
                            dst_v6_ptr,
                            htons(meta->src_port),
                            htons(meta->dst_port),
                            proto_for_json,
                            serializer);

    bool appended = false;
    if (rc == 0) {
        uint32_t ndpi_len = 0;
        const char *ndpi_buf = ndpi_serializer_get_buffer(serializer, &ndpi_len);
        if (ndpi_buf && ndpi_len > 0) {
            if (ndpi_len >= MAX_JSON_BUFFER) {
                fprintf(stderr, "[worker %d] nDPI JSON %u bytes exceeds builder capacity\n", worker->worker_id, ndpi_len);
            } else if (!jb_add_raw(jb, "ndpi", ndpi_buf, ndpi_len)) {
                fprintf(stderr, "[worker %d] failed to append nDPI JSON (%u bytes)\n", worker->worker_id, ndpi_len);
            } else {
                appended = true;
            }
        }
    } else {
        fprintf(stderr, "[worker %d] ndpi_flow2json failed (%d)\n", worker->worker_id, rc);
    }
    return appended;
}

static size_t json_builder_write_completed_flow(worker_context_t *worker,
                                                const flow_entry_t *entry,
                                                const packet_metadata_t *meta,
                                                const nm_flow_state_t *snapshot,
                                                char *json_out,
                                                size_t json_out_size,
                                                uint64_t hash) {
    if (!worker || !entry || !meta || !snapshot || !json_out || json_out_size == 0) {
        return 0;
    }

    json_builder_t jb;
    bool lua_open = false;
    jb_reset(&jb);
    if (!jb_open_object(&jb)) {
        return 0;
    }

    char flow_hash_hex[17];
    snprintf(flow_hash_hex, sizeof(flow_hash_hex), "%016llx", (unsigned long long)hash);

    tls_packet_meta = meta;
    tls_flow_entry = entry;
    tls_flow_hash_hex = flow_hash_hex;
    tls_ndpi_module = worker->ndpi_module;

    jb_add_string(&jb, "sensor_id", worker->runtime->config->sensor_id);
    jb_add_double(&jb, "ts", entry->last_seen);
    jb_add_string(&jb, "flow_hash", flow_hash_hex);

    char src_ip[MAX_IP_STRING];
    char dst_ip[MAX_IP_STRING];
    format_ip_string(meta, true, src_ip, sizeof(src_ip));
    format_ip_string(meta, false, dst_ip, sizeof(dst_ip));

    jb_add_string(&jb, "src_ip", src_ip);
    jb_add_string(&jb, "dst_ip", dst_ip);
    jb_add_uint64(&jb, "src_port", meta->src_port);
    jb_add_uint64(&jb, "dst_port", meta->dst_port);
    jb_add_uint64(&jb, "proto_id", meta->proto);
    jb_add_bool(&jb, "outbound", meta->outbound);
    jb_add_uint64(&jb, "bytes_total", snapshot->bytes_total);
    jb_add_uint64(&jb, "packets_total", snapshot->packets_total);
    jb_add_uint64(&jb, "bytes_out", entry->bytes_outbound);
    jb_add_uint64(&jb, "bytes_in", entry->bytes_inbound);
    jb_add_uint64(&jb, "first_seen_ns", snapshot->first_seen_ts);
    jb_add_uint64(&jb, "last_seen_ns", snapshot->last_seen_ts);

    worker_append_ndpi_json(worker, entry, meta, &jb);

    const char *proto_name = ndpi_get_proto_name(worker->ndpi_module, entry->detected.proto.app_protocol);
    const char *master_name = ndpi_get_proto_name(worker->ndpi_module, entry->detected.proto.master_protocol);
    const char *category_name = ndpi_category_get_name(worker->ndpi_module, entry->detected.category);
    if (proto_name) jb_add_string(&jb, "proto", proto_name);
    if (master_name) jb_add_string(&jb, "master_proto", master_name);
    if (category_name) jb_add_string(&jb, "category", category_name);
    jb_add_uint64(&jb, "risk_mask", entry->risk);
    jb_add_uint64(&jb, "confidence", entry->ndpi_flow->confidence);

    if (entry->ndpi_flow->host_server_name[0]) {
        jb_add_string(&jb, "sni", entry->ndpi_flow->host_server_name);
    }

    jb_add_bool(&jb, "quarantine", worker->runtime->config->quarantine_mode);
    if (entry->dropped_packets > 0) {
        jb_add_uint64(&jb, "dropped_count", entry->dropped_packets);
    }
    jb_add_bool(&jb, "flow_closed", true);

    for (size_t i = 0; i < worker->lua_script_count; ++i) {
        lua_script_instance_t *inst = &worker->lua_scripts[i];
        lua_State *L = inst->L;
        lua_rawgeti(L, LUA_REGISTRYINDEX, inst->on_packet_ref);
        lua_newtable(L);
        lua_pushstring(L, src_ip); lua_setfield(L, -2, "src_ip");
        lua_pushstring(L, dst_ip); lua_setfield(L, -2, "dst_ip");
        lua_pushinteger(L, meta->src_port); lua_setfield(L, -2, "src_port");
        lua_pushinteger(L, meta->dst_port); lua_setfield(L, -2, "dst_port");
        lua_pushinteger(L, meta->proto); lua_setfield(L, -2, "proto");
        lua_pushboolean(L, meta->outbound); lua_setfield(L, -2, "outbound");
        lua_pushinteger(L, meta->payload_len); lua_setfield(L, -2, "payload_len");

        lua_newtable(L);
        lua_pushinteger(L, entry->packets); lua_setfield(L, -2, "packets");
        lua_pushinteger(L, entry->bytes); lua_setfield(L, -2, "bytes");
        lua_pushinteger(L, entry->packets_outbound); lua_setfield(L, -2, "packets_out");
        lua_pushinteger(L, entry->packets_inbound); lua_setfield(L, -2, "packets_in");
        lua_pushinteger(L, entry->bytes_outbound); lua_setfield(L, -2, "bytes_out");
        lua_pushinteger(L, entry->bytes_inbound); lua_setfield(L, -2, "bytes_in");

        tls_packet_meta = meta;
        tls_flow_entry = entry;
        tls_flow_hash_hex = flow_hash_hex;
        tls_ndpi_module = worker->ndpi_module;

        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            fprintf(stderr, "[worker %d] lua on_packet error %s: %s\n", worker->worker_id,
                    inst->descriptor.signature, lua_tostring(L, -1));
            lua_pop(L, 1);
            tls_packet_meta = NULL;
            tls_flow_entry = NULL;
            tls_flow_hash_hex = NULL;
            tls_ndpi_module = NULL;
            continue;
        }

        tls_packet_meta = NULL;
        tls_flow_entry = NULL;
        tls_flow_hash_hex = NULL;
        tls_ndpi_module = NULL;

        if (!lua_istable(L, -1) || lua_table_is_empty(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        if (!lua_open) {
            if (!jb_begin_object_field(&jb, "lua")) {
                lua_pop(L, 1);
                break;
            }
            lua_open = true;
        }

        if (!jb_begin_object_field(&jb, inst->descriptor.signature)) {
            lua_pop(L, 1);
            continue;
        }
        if (!lua_table_to_json(L, -1, &jb)) {
            jb_close_object(&jb);
            lua_pop(L, 1);
            continue;
        }
        jb_close_object(&jb);
        lua_pop(L, 1);
    }

    tls_packet_meta = NULL;
    tls_flow_entry = NULL;
    tls_flow_hash_hex = NULL;
    tls_ndpi_module = NULL;

    if (lua_open) {
        jb_close_object(&jb);
    }

    jb_close_object(&jb);

    size_t len = jb.len;
    if (len + 1 >= json_out_size) {
        return 0;
    }
    memcpy(json_out, jb.data, len);
    json_out[len] = '\n';
    json_out[len + 1] = '\0';
    return len + 1;
}

static size_t cleanup_expired_flows(worker_context_t *worker,
                                    flow_entry_t *entry,
                                    const packet_metadata_t *meta,
                                    char *json_out,
                                    size_t json_out_size,
                                    uint64_t hash) {
    if (!worker || !entry) {
        return 0;
    }

    packet_metadata_t fallback;
    const packet_metadata_t *emit_meta = meta;
    if (!emit_meta) {
        memset(&fallback, 0, sizeof(fallback));
        fallback.ipv6 = entry->key.ipv6;
        size_t addr_len = entry->key.ipv6 ? 16u : 4u;
        memcpy(fallback.src_ip, entry->key.src_ip, addr_len);
        memcpy(fallback.dst_ip, entry->key.dst_ip, addr_len);
        fallback.src_port = entry->key.src_port;
        fallback.dst_port = entry->key.dst_port;
        fallback.proto = entry->key.proto;
        fallback.timestamp_ns = (uint64_t)(entry->last_seen * 1000000000.0);
        emit_meta = &fallback;
    }

    nm_flow_state_t snapshot = flow_entry_to_store(entry);
    size_t emitted = json_builder_write_completed_flow(worker, entry, emit_meta, &snapshot, json_out, json_out_size, hash);

    if (worker->runtime->flow_store) {
        flow_store_del(worker->runtime->flow_store, hash);
    }

    entry->final_reported = true;
    flow_table_release(entry);
    return emitted;
}

static void worker_sweep_idle_flows(worker_context_t *worker) {
    if (!worker || !worker->runtime || !worker->runtime->config) {
        return;
    }

    const sensor_config_t *cfg = worker->runtime->config;
    double sweep_interval = cfg->idle_sweep_interval_seconds;
    if (sweep_interval <= 0.0) {
        return;
    }

    double now = get_time_seconds();
    if ((now - worker->last_idle_sweep) < sweep_interval) {
        return;
    }
    worker->last_idle_sweep = now;

    double tcp_timeout = cfg->tcp_idle_timeout_seconds;
    double other_timeout = cfg->other_idle_timeout_seconds;
    if (tcp_timeout <= 0.0 && other_timeout <= 0.0) {
        return;
    }

    char json_line[MAX_JSON_BUFFER];
    for (size_t i = 0; i < worker->flows.capacity; ++i) {
        flow_entry_t *entry = &worker->flows.entries[i];
        if (!entry->in_use || entry->final_reported) {
            continue;
        }

        double timeout = (entry->key.proto == IPPROTO_TCP) ? tcp_timeout : other_timeout;
        if (timeout <= 0.0) {
            continue;
        }

        double idle_for = now - entry->last_seen;
        if (idle_for < timeout) {
            continue;
        }

        uint64_t flow_hash = entry->hash;
        uint8_t proto = entry->key.proto;
        size_t len = cleanup_expired_flows(worker, entry, NULL, json_line, sizeof(json_line), flow_hash);
        if (len == 0) {
            continue;
        }

        log_manager_write_line(&worker->runtime->log_mgr, json_line);
        if (!worker->runtime->config->stdout_minimal) {
            printf("[idle-flow] hash=%016llx proto=%u idle=%.2fs\n",
                   (unsigned long long)flow_hash,
                   (unsigned int)proto,
                   idle_for);
        }
    }
}

size_t worker_process_packet(worker_context_t *worker,
                             const packet_job_t *job,
                             char *json_out,
                             size_t json_out_size,
                             bool *allow_reinject) {
    const packet_metadata_t *meta = &job->meta;

    if (!worker->runtime->include_loopback) {
        if (!meta->ipv6) {
        if (meta->src_ip[0] == 127 && meta->dst_ip[0] == 127) {
            return 0;
        }
        } else {
            static const uint8_t loopback_v6[16] = {0};
            if (memcmp(meta->src_ip, loopback_v6, 15) == 0 && meta->src_ip[15] == 1 &&
                memcmp(meta->dst_ip, loopback_v6, 15) == 0 && meta->dst_ip[15] == 1) {
                return 0;
            }
        }
    }

    flow_key_t key;
    metadata_to_flow_key(meta, &key);
    uint64_t hash = flow_hash_from_key(&key);
    bool is_new = false;
    flow_entry_t *entry = flow_table_acquire(&worker->flows, &key, hash, &is_new);
    if (!entry || !entry->ndpi_flow) {
        return 0;
    }

    size_t emitted = 0;

    double now = get_time_seconds();
    entry->last_seen = now;
    entry->packets++;
    entry->bytes += meta->payload_len;
    if (meta->outbound) {
        entry->packets_outbound++;
        entry->bytes_outbound += meta->payload_len;
    } else {
        entry->packets_inbound++;
        entry->bytes_inbound += meta->payload_len;
    }

    bool final_event = false;
    if (meta->proto == IPPROTO_TCP) {
        if (meta->tcp_rst) {
            entry->fin_seen_outbound = true;
            entry->fin_seen_inbound = true;
            final_event = true;
        } else if (meta->tcp_fin) {
            if (meta->outbound) {
                entry->fin_seen_outbound = true;
            } else {
                entry->fin_seen_inbound = true;
            }
            if (entry->fin_seen_outbound && entry->fin_seen_inbound) {
                final_event = true;
            }
        }
    }
    if (final_event && entry->final_reported) {
        final_event = false;
    }
    bool release_flow = final_event;

    uint64_t timestamp_ms = meta->timestamp_ns / 1000000ULL;
    if (entry->ndpi_flow) {
        entry->ndpi_flow->packet_direction = meta->outbound ? 1 : 0;
    }

    entry->detected = ndpi_detection_process_packet(worker->ndpi_module,
                                                    entry->ndpi_flow,
                                                    job->packet,
                                                    (uint16_t)job->packet_len,
                                                    timestamp_ms,
                                                    NULL);
    entry->risk = entry->ndpi_flow->risk;

    if (final_event && !entry->ndpi_finalized) {
        uint8_t guessed = 0;
        ndpi_protocol guess = ndpi_detection_giveup(worker->ndpi_module, entry->ndpi_flow, &guessed);
        if (ndpi_is_protocol_detected(guess) || guessed) {
            entry->detected = guess;
        }
        entry->risk = entry->ndpi_flow->risk;
        entry->ndpi_finalized = true;
    }

    bool allow = runtime_is_quarantine_permitted(worker->runtime, meta);
    if (!allow) {
        entry->dropped_packets++;
        InterlockedIncrement64(&worker->runtime->metrics.packets_dropped_quarantine);
    }
    if (allow_reinject) {
        *allow_reinject = allow && worker->runtime->config->active_mode;
    }

    InterlockedIncrement64(&worker->runtime->metrics.packets_processed);

    if (worker->runtime->flow_store) {
        nm_flow_state_t snapshot = flow_entry_to_store(entry);
        flow_store_put(worker->runtime->flow_store, hash, &snapshot);
    }

    if (final_event) {
        emitted = cleanup_expired_flows(worker, entry, meta, json_out, json_out_size, hash);
        release_flow = false;
        goto cleanup;
    }

cleanup:
    if (release_flow) {
        flow_table_release(entry);
    }
    return emitted;
}

static unsigned __stdcall worker_thread_main(void *arg) {
    worker_context_t *worker = (worker_context_t *)arg;
    char json_line[MAX_JSON_BUFFER];

    for (;;) {
        worker_sweep_idle_flows(worker);

        bool running = InterlockedCompareExchange(&worker->runtime->running, 0, 0) != 0;
        if (!running && ring_buffer_empty(&worker->queue)) {
            break;
        }

        packet_job_t job;
        if (!ring_buffer_pop(&worker->queue, &job)) {
            Sleep(1);
            continue;
        }
        if (job.packet_len == 0 && !running) {
            continue;
        }

        bool allow_reinject = false;
        size_t len = worker_process_packet(worker, &job, json_line, sizeof(json_line), &allow_reinject);
        if (len == 0) {
            continue;
        }

        log_manager_write_line(&worker->runtime->log_mgr, json_line);
        if (!worker->runtime->config->stdout_minimal) {
            char src_ip[MAX_IP_STRING];
            char dst_ip[MAX_IP_STRING];
            format_ip_string(&job.meta, true, src_ip, sizeof(src_ip));
            format_ip_string(&job.meta, false, dst_ip, sizeof(dst_ip));
            DWORD pid = resolve_flow_pid(&job.meta);
            if (pid != 0) {
                printf("[flow] %s:%u -> %s:%u bytes=%u pid=%lu\n",
                       src_ip,
                       job.meta.src_port,
                       dst_ip,
                       job.meta.dst_port,
                       job.packet_len,
                       (unsigned long)pid);
            } else {
                printf("[flow] %s:%u -> %s:%u bytes=%u pid=unknown\n",
                       src_ip,
                       job.meta.src_port,
                       dst_ip,
                       job.meta.dst_port,
                       job.packet_len);
            }
        }
    }

    return 0;
}

bool worker_context_init(worker_context_t *worker, sensor_runtime_t *runtime, int worker_id, bool spawn_thread) {
    memset(worker, 0, sizeof(*worker));
    worker->runtime = runtime;
    worker->worker_id = worker_id;
    worker->ndpi_serializer_ready = false;
    worker->last_idle_sweep = get_time_seconds();

    if (!ring_buffer_init(&worker->queue, RING_CAPACITY)) {
        return false;
    }
    if (!flow_table_init(&worker->flows, FLOW_TABLE_CAPACITY, runtime->flow_store)) {
        ring_buffer_free(&worker->queue);
        return false;
    }

    worker->ndpi_module = ndpi_init_detection_module(NULL);
    if (!worker->ndpi_module) {
        flow_table_free(&worker->flows);
        ring_buffer_free(&worker->queue);
        return false;
    }
    worker_set_detection_bitmask(worker);
    worker_apply_ndpi_config(worker);
    if (ndpi_finalize_initialization(worker->ndpi_module) != 0) {
        ndpi_exit_detection_module(worker->ndpi_module);
        worker->ndpi_module = NULL;
        flow_table_free(&worker->flows);
        ring_buffer_free(&worker->queue);
        return false;
    }

    if (ndpi_init_serializer_ll(&worker->ndpi_serializer, ndpi_serialization_format_json, NDPI_SERIALIZER_INIT_BUFFER) != 0) {
        ndpi_exit_detection_module(worker->ndpi_module);
        worker->ndpi_module = NULL;
        flow_table_free(&worker->flows);
        ring_buffer_free(&worker->queue);
        return false;
    }
    worker->ndpi_serializer_ready = true;

    if (!worker_prepare_lua(worker)) {
        if (worker->ndpi_serializer_ready) {
            ndpi_term_serializer(&worker->ndpi_serializer);
            worker->ndpi_serializer_ready = false;
        }
        ndpi_exit_detection_module(worker->ndpi_module);
        worker->ndpi_module = NULL;
        flow_table_free(&worker->flows);
        ring_buffer_free(&worker->queue);
        return false;
    }

    if (spawn_thread) {
        unsigned thread_id = 0;
        worker->thread = (HANDLE)_beginthreadex(NULL, 0, worker_thread_main, worker, 0, &thread_id);
        if (!worker->thread) {
            for (size_t i = 0; i < worker->lua_script_count; ++i) {
                if (worker->lua_scripts[i].L) {
                    lua_close(worker->lua_scripts[i].L);
                }
            }
            if (worker->ndpi_serializer_ready) {
                ndpi_term_serializer(&worker->ndpi_serializer);
                worker->ndpi_serializer_ready = false;
            }
            ndpi_exit_detection_module(worker->ndpi_module);
            worker->ndpi_module = NULL;
            flow_table_free(&worker->flows);
            ring_buffer_free(&worker->queue);
            return false;
        }
    }

    return true;
}

void worker_context_shutdown(worker_context_t *worker) {
    if (!worker) return;

    if (worker->thread) {
        WaitForSingleObject(worker->thread, INFINITE);
        CloseHandle(worker->thread);
        worker->thread = NULL;
    }

    for (size_t i = 0; i < worker->lua_script_count; ++i) {
        if (worker->lua_scripts[i].L) {
            lua_close(worker->lua_scripts[i].L);
            worker->lua_scripts[i].L = NULL;
        }
    }

    if (worker->ndpi_serializer_ready) {
        ndpi_term_serializer(&worker->ndpi_serializer);
        worker->ndpi_serializer_ready = false;
    }

    if (worker->ndpi_module) {
        ndpi_exit_detection_module(worker->ndpi_module);
        worker->ndpi_module = NULL;
    }

    flow_table_free(&worker->flows);
    ring_buffer_free(&worker->queue);
}

void signal_workers_shutdown(worker_context_t *workers, int count) {
    packet_job_t sentinel;
    memset(&sentinel, 0, sizeof(sentinel));
    for (int i = 0; i < count; ++i) {
        worker_context_t *worker = &workers[i];
        while (!ring_buffer_push(&worker->queue, &sentinel)) {
            Sleep(1);
        }
    }
}
