#include "sensor.h"

static bool ensure_flow_store_settings(sensor_config_t *cfg) {
    char temp_dir[MAX_PATH];
    char filename[MAX_PATH];

    if (!cfg) {
        return false;
    }

    if (cfg->flow_store_map_bytes == 0) {
        cfg->flow_store_map_bytes = DEFAULT_FLOW_STORE_MAP_BYTES;
    }
    if (cfg->flow_store_max_readers == 0) {
        cfg->flow_store_max_readers = DEFAULT_FLOW_STORE_MAX_READERS;
    }

    if (cfg->flow_store_path[0] == '\0') {
        DWORD len = GetTempPathA((DWORD)sizeof(temp_dir), temp_dir);
        if (len == 0 || len >= sizeof(temp_dir)) {
            return false;
        }
        const char *sensor_id = (cfg->sensor_id[0] != '\0') ? cfg->sensor_id : "UNKNOWN-SENSOR";
        snprintf(filename, sizeof(filename), "%s.lmdb", sensor_id);
        build_path(cfg->flow_store_path, sizeof(cfg->flow_store_path), temp_dir, filename);
    }

    return true;
}

bool initialize_runtime(sensor_runtime_t *rt, sensor_config_t *cfg, bool *wsa_started) {
    memset(rt, 0, sizeof(*rt));
    rt->config = cfg;
    rt->include_loopback = cfg->include_loopback;
    sensor_debugf("[runtime] initialize start (log=%s, workers=%d)", cfg->log_path, cfg->workers);

    if (!cfg->sensor_id_override) {
        if (!read_machine_guid(cfg->sensor_id, sizeof(cfg->sensor_id))) {
            safe_strcpy(cfg->sensor_id, sizeof(cfg->sensor_id), "UNKNOWN-SENSOR");
        }
    }

    if (!ensure_flow_store_settings(cfg)) {
        fprintf(stderr, "[runtime] failed to derive LMDB path from TEMP\n");
        sensor_debugf("[runtime] flow store path derivation failed");
        return false;
    }

    WSADATA wsa;
    if (wsa_started && !*wsa_started) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "[runtime] WSAStartup failed\n");
            sensor_debugf("[runtime] WSAStartup failed (err=%lu)", WSAGetLastError());
            return false;
        }
        *wsa_started = true;
    }

    if (!log_manager_init(&rt->log_mgr,
                          cfg->log_path,
                          cfg->log_max_bytes,
                          cfg->log_buffer_bytes,
                          cfg->log_flush_interval_ms,
                          cfg->log_force_flush_on_malicious)) {
        fprintf(stderr, "[runtime] failed to initialize log manager\n");
        sensor_debugf("[runtime] log manager init failed");
        return false;
    }

    int fs_rc = flow_store_open(&rt->flow_store,
                                cfg->flow_store_path,
                                cfg->flow_store_map_bytes,
                                cfg->flow_store_max_readers);
    if (fs_rc != MDB_SUCCESS) {
        fprintf(stderr, "[runtime] failed to open flow store (%s)\n", mdb_strerror(fs_rc));
        sensor_debugf("[runtime] flow_store_open failed err=%d", fs_rc);
        return false;
    }

    if (!load_lua_scripts(rt)) {
        fprintf(stderr, "[runtime] failed to load Lua scripts\n");
        sensor_debugf("[runtime] load_lua_scripts failed");
        flow_store_close(rt->flow_store);
        rt->flow_store = NULL;
        return false;
    }

    InterlockedExchange(&rt->running, 1);
    sensor_debugf("[runtime] initialize complete (flow_store=%s, map=%llu, readers=%u)",
                  cfg->flow_store_path,
                  (unsigned long long)cfg->flow_store_map_bytes,
                  cfg->flow_store_max_readers);
    return true;
}

void shutdown_runtime(sensor_runtime_t *rt, bool *wsa_started) {
    if (!rt) return;
    InterlockedExchange(&rt->running, 0);
    flow_store_close(rt->flow_store);
    log_manager_close(&rt->log_mgr);
    if (wsa_started && *wsa_started) {
        WSACleanup();
        *wsa_started = false;
    }
}
