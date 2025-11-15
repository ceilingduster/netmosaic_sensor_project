#include "sensor.h"

static void dump_usage(const char *exe) {
    fprintf(stderr, "Usage: %s --sensor-id ID\n", exe);
    fprintf(stderr, "Optional: --flow-store-path PATH --flow-store-map-bytes N --flow-store-max-readers N\n");
}

static bool parse_dump_args(sensor_config_t *cfg, int argc, char **argv) {
    default_config(cfg);
    cfg->log_path[0] = '\0';
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (_stricmp(arg, "--sensor-id") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --sensor-id\n");
                return false;
            }
            safe_strcpy(cfg->sensor_id, sizeof(cfg->sensor_id), argv[++i]);
            cfg->sensor_id_override = true;
        } else if (_stricmp(arg, "--flow-store-path") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --flow-store-path\n");
                return false;
            }
            safe_strcpy(cfg->flow_store_path, sizeof(cfg->flow_store_path), argv[++i]);
        } else if (_stricmp(arg, "--flow-store-map-bytes") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --flow-store-map-bytes\n");
                return false;
            }
            cfg->flow_store_map_bytes = (size_t)_strtoui64(argv[++i], NULL, 10);
        } else if (_stricmp(arg, "--flow-store-max-readers") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --flow-store-max-readers\n");
                return false;
            }
            cfg->flow_store_max_readers = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (_stricmp(arg, "--help") == 0 || _stricmp(arg, "-h") == 0) {
            dump_usage(argv[0]);
            return false;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", arg);
            dump_usage(argv[0]);
            return false;
        }
    }

    if (!cfg->sensor_id_override || cfg->sensor_id[0] == '\0') {
        fprintf(stderr, "--sensor-id is required\n");
        return false;
    }

    if (cfg->flow_store_map_bytes == 0) {
        cfg->flow_store_map_bytes = DEFAULT_FLOW_STORE_MAP_BYTES;
    }
    if (cfg->flow_store_max_readers == 0) {
        cfg->flow_store_max_readers = DEFAULT_FLOW_STORE_MAX_READERS;
    }

    if (cfg->flow_store_path[0] == '\0') {
        char temp_dir[MAX_PATH];
        char filename[MAX_PATH];
        DWORD len = GetTempPathA((DWORD)sizeof(temp_dir), temp_dir);
        if (len == 0 || len >= sizeof(temp_dir)) {
            fprintf(stderr, "Failed to resolve %%TEMP%% path\n");
            return false;
        }
        snprintf(filename, sizeof(filename), "%s.lmdb", cfg->sensor_id);
        build_path(cfg->flow_store_path, sizeof(cfg->flow_store_path), temp_dir, filename);
    }

    return true;
}

static void dump_flow_state_json(const nm_flow_state_t *st, uint64_t hash) {
    printf("{\"flow_hash\":\"%016llx\",\"bytes_total\":%llu,\"packets_total\":%llu,"
           "\"first_seen_ts\":%llu,\"last_seen_ts\":%llu,\"src_ip\":%u,\"dst_ip\":%u,"
           "\"src_port\":%u,\"dst_port\":%u,\"proto_id\":%u,\"ndpi_proto_id\":%u,"
           "\"risk_score\":%u}\n",
           (unsigned long long)hash,
           (unsigned long long)st->bytes_total,
           (unsigned long long)st->packets_total,
           (unsigned long long)st->first_seen_ts,
           (unsigned long long)st->last_seen_ts,
           st->src_ip,
           st->dst_ip,
           st->src_port,
           st->dst_port,
           st->proto_id,
           st->ndpi_proto_id,
           st->risk_score);
}

int main(int argc, char **argv) {
    sensor_config_t cfg;
    flow_store_t *store = NULL;
    MDB_cursor *cursor = NULL;
    nm_flow_state_t state;
    uint64_t hash = 0;
    int rc;

    if (!parse_dump_args(&cfg, argc, argv)) {
        return 1;
    }

    rc = flow_store_open(&store,
                         cfg.flow_store_path,
                         cfg.flow_store_map_bytes,
                         cfg.flow_store_max_readers);
    if (rc != MDB_SUCCESS) {
        fprintf(stderr, "Failed to open flow store %s (%s)\n",
                cfg.flow_store_path,
                mdb_strerror(rc));
        return 1;
    }

    while ((rc = flow_store_iter(store, &cursor, &hash, &state)) == MDB_SUCCESS) {
        dump_flow_state_json(&state, hash);
    }

    if (rc != MDB_NOTFOUND) {
        fprintf(stderr, "Iteration error: %s\n", mdb_strerror(rc));
    }

    flow_store_iter_end(cursor);
    flow_store_close(store);
    return (rc == MDB_NOTFOUND || rc == MDB_SUCCESS) ? 0 : 1;
}
