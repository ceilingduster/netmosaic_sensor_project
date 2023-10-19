#include "sensor.h"

void safe_strcpy(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || dest_size == 0) {
        return;
    }
    if (src == NULL) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

uint32_t swap_u32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0x0000FF00U) | ((v << 8) & 0x00FF0000U) | (v << 24);
}

uint16_t swap_u16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}

uint64_t fnv1a64(const void *data, size_t len) {
    const uint8_t *ptr = (const uint8_t *)data;
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= ptr[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

uint64_t get_time_nanoseconds(void) {
    FILETIME ft;
    ULARGE_INTEGER li;
#if _WIN32_WINNT >= 0x0601
    GetSystemTimePreciseAsFileTime(&ft);
#else
    GetSystemTimeAsFileTime(&ft);
#endif
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return li.QuadPart * 100ULL;
}

double get_time_seconds(void) {
    return (double)get_time_nanoseconds() / 1e9;
}

bool read_machine_guid(char *buffer, size_t length) {
    HKEY key = NULL;
    DWORD type = 0;
    DWORD size = (DWORD)length;
    LONG status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (status != ERROR_SUCCESS) {
        return false;
    }
    status = RegQueryValueExA(key, "MachineGuid", NULL, &type, (LPBYTE)buffer, &size);
    RegCloseKey(key);
    return status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ);
}

bool ensure_directory_exists(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }

    char tmp[MAX_PATH];
    safe_strcpy(tmp, sizeof(tmp), path);
    for (char *p = tmp; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            char old = *p;
            *p = '\0';
            if (strlen(tmp) > 0) {
                _mkdir(tmp);
            }
            *p = old;
        }
    }
    return _mkdir(tmp) == 0 || errno == EEXIST;
}

bool ensure_parent_directory(const char *filepath) {
    if (filepath == NULL) {
        return false;
    }
    char tmp[MAX_PATH];
    safe_strcpy(tmp, sizeof(tmp), filepath);
    char *slash = strrchr(tmp, '\\');
    char *slash2 = strrchr(tmp, '/');
    char *pivot = slash;
    if (slash2 != NULL && (pivot == NULL || slash2 > pivot)) {
        pivot = slash2;
    }
    if (pivot == NULL) {
        return true;
    }
    *pivot = '\0';
    if (tmp[0] == '\0') {
        return true;
    }
    return ensure_directory_exists(tmp);
}

void build_path(char *dst, size_t dst_size, const char *dir, const char *name) {
    if (dir == NULL || dir[0] == '\0') {
        safe_strcpy(dst, dst_size, name);
        return;
    }
    size_t len = strlen(dir);
    if (len > 0 && (dir[len - 1] == '\\' || dir[len - 1] == '/')) {
        snprintf(dst, dst_size, "%s%s", dir, name);
    } else {
        snprintf(dst, dst_size, "%s\\%s", dir, name);
    }
}
