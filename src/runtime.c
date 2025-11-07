#include "sensor.h"

void runtime_update_syslog_allow(sensor_runtime_t *rt) {
    rt->syslog_allow_v4_valid = false;
    rt->syslog_allow_v6_valid = false;
    if (!rt || !rt->config) {
        return;
    }
    struct in_addr addr4;
    if (InetPtonA(AF_INET, rt->config->syslog_ip, &addr4) == 1) {
        rt->syslog_allowed_v4 = addr4.S_un.S_addr;
        rt->syslog_allow_v4_valid = true;
        return;
    }
    if (InetPtonA(AF_INET6, rt->config->syslog_ip, &rt->syslog_allowed_v6) == 1) {
        rt->syslog_allow_v6_valid = true;
    }
}

bool initialize_runtime(sensor_runtime_t *rt, sensor_config_t *cfg, bool *wsa_started) {
    memset(rt, 0, sizeof(*rt));
    rt->config = cfg;
    rt->include_loopback = cfg->include_loopback;

    if (!cfg->sensor_id_override) {
        if (!read_machine_guid(cfg->sensor_id, sizeof(cfg->sensor_id))) {
            safe_strcpy(cfg->sensor_id, sizeof(cfg->sensor_id), "UNKNOWN-SENSOR");
        }
    }

    WSADATA wsa;
    if (wsa_started && !*wsa_started) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "[runtime] WSAStartup failed\n");
            return false;
        }
        *wsa_started = true;
    }

    if (!log_manager_init(&rt->log_mgr, cfg->log_path, cfg->log_max_bytes)) {
        fprintf(stderr, "[runtime] failed to initialize log manager\n");
        return false;
    }

    if (!syslog_target_init(&rt->syslog, cfg)) {
        fprintf(stderr, "[runtime] syslog disabled due to initialization failure\n");
    }

    runtime_update_syslog_allow(rt);

    if (!load_lua_scripts(rt)) {
        fprintf(stderr, "[runtime] failed to load Lua scripts\n");
        return false;
    }

    InterlockedExchange(&rt->running, 1);
    return true;
}

void shutdown_runtime(sensor_runtime_t *rt, bool *wsa_started) {
    if (!rt) return;
    InterlockedExchange(&rt->running, 0);
    log_manager_close(&rt->log_mgr);
    syslog_target_close(&rt->syslog);
    if (wsa_started && *wsa_started) {
        WSACleanup();
        *wsa_started = false;
    }
}
