#include "sensor.h"

bool syslog_target_init(syslog_target_t *target, const sensor_config_t *cfg) {
    memset(target, 0, sizeof(*target));
    InitializeCriticalSection(&target->lock);

    if (cfg->syslog_ip[0] == '\0') {
        target->enabled = false;
        return true;
    }

    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    memset(&addr4, 0, sizeof(addr4));
    memset(&addr6, 0, sizeof(addr6));

    if (InetPtonA(AF_INET, cfg->syslog_ip, &addr4.sin_addr) == 1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(cfg->syslog_port);
        memcpy(&target->addr, &addr4, sizeof(addr4));
        target->addr_len = sizeof(addr4);
        target->enabled = true;
    } else if (InetPtonA(AF_INET6, cfg->syslog_ip, &addr6.sin6_addr) == 1) {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(cfg->syslog_port);
        memcpy(&target->addr, &addr6, sizeof(addr6));
        target->addr_len = sizeof(addr6);
        target->enabled = true;
    } else {
        fprintf(stderr, "[syslog] invalid IP address: %s\n", cfg->syslog_ip);
        target->enabled = false;
        return false;
    }

    target->sock = socket(target->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (target->sock == INVALID_SOCKET) {
        fprintf(stderr, "[syslog] socket() failed: %lu\n", GetLastError());
        target->enabled = false;
        return false;
    }
    return true;
}

void syslog_target_close(syslog_target_t *target) {
    EnterCriticalSection(&target->lock);
    if (target->sock != INVALID_SOCKET) {
        closesocket(target->sock);
        target->sock = INVALID_SOCKET;
    }
    LeaveCriticalSection(&target->lock);
    DeleteCriticalSection(&target->lock);
}

bool syslog_target_send(syslog_target_t *target, const char *line) {
    if (!target->enabled || target->sock == INVALID_SOCKET || !line) {
        return false;
    }
    size_t len = strlen(line);
    if (len == 0) {
        return false;
    }
    EnterCriticalSection(&target->lock);
    int result = sendto(target->sock, line, (int)len, 0, (struct sockaddr *)&target->addr, target->addr_len);
    LeaveCriticalSection(&target->lock);
    return result == (int)len;
}
