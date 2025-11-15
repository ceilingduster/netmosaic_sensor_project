#include "sensor.h"

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

    if (!load_lua_scripts(rt)) {
        fprintf(stderr, "[runtime] failed to load Lua scripts\n");
        sensor_debugf("[runtime] load_lua_scripts failed");
        return false;
    }

    InterlockedExchange(&rt->running, 1);
    sensor_debugf("[runtime] initialize complete");
    return true;
}

void shutdown_runtime(sensor_runtime_t *rt, bool *wsa_started) {
    if (!rt) return;
    InterlockedExchange(&rt->running, 0);
    log_manager_close(&rt->log_mgr);
    if (wsa_started && *wsa_started) {
        WSACleanup();
        *wsa_started = false;
    }
}
