#include "sensor.h"

typedef struct rotation_file {
    char path[MAX_PATH];
    FILETIME last_write;
} rotation_file_t;

static int compare_rotation_newest(const void *lhs, const void *rhs) {
    const rotation_file_t *a = (const rotation_file_t *)lhs;
    const rotation_file_t *b = (const rotation_file_t *)rhs;
    LONG cmp = CompareFileTime(&b->last_write, &a->last_write);
    if (cmp < 0) return -1;
    if (cmp > 0) return 1;
    return 0;
}

static void log_manager_cleanup_rotations(log_manager_t *mgr) {
    char pattern[MAX_PATH];
    build_path(pattern, sizeof(pattern), mgr->directory, "netmosaic-*.jsonl");

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    rotation_file_t files[128];
    size_t count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (count >= ARRAYSIZE(files)) {
            break;
        }
        char full_path[MAX_PATH];
        build_path(full_path, sizeof(full_path), mgr->directory, fd.cFileName);
        safe_strcpy(files[count].path, sizeof(files[count].path), full_path);
        files[count].last_write = fd.ftLastWriteTime;
        ++count;
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (count <= LOG_ROTATION_HISTORY) {
        return;
    }

    qsort(files, count, sizeof(rotation_file_t), compare_rotation_newest);

    for (size_t i = LOG_ROTATION_HISTORY; i < count; ++i) {
        DeleteFileA(files[i].path);
    }
}

static bool log_manager_reopen(log_manager_t *mgr) {
    if (!ensure_parent_directory(mgr->filename)) {
        return false;
    }
    mgr->file = fopen(mgr->filename, "ab");
    if (!mgr->file) {
        return false;
    }
    if (_fseeki64(mgr->file, 0, SEEK_END) == 0) {
        long long pos = _ftelli64(mgr->file);
        if (pos > 0) {
            mgr->current_size = (size_t)pos;
        }
    }
    return true;
}

bool log_manager_init(log_manager_t *mgr, const char *path, size_t rotate_bytes) {
    memset(mgr, 0, sizeof(*mgr));
    InitializeCriticalSection(&mgr->lock);
    mgr->rotate_bytes = rotate_bytes;
    safe_strcpy(mgr->filename, sizeof(mgr->filename), path);

    const char *last_slash = strrchr(path, '\\');
    const char *last_fwd = strrchr(path, '/');
    const char *pivot = last_slash;
    if (last_fwd != NULL && (pivot == NULL || last_fwd > pivot)) {
        pivot = last_fwd;
    }
    if (pivot != NULL) {
        size_t len = (size_t)(pivot - path);
        if (len >= sizeof(mgr->directory)) {
            len = sizeof(mgr->directory) - 1;
        }
        memcpy(mgr->directory, path, len);
        mgr->directory[len] = '\0';
        ensure_directory_exists(mgr->directory);
    }

    if (!log_manager_reopen(mgr)) {
        DeleteCriticalSection(&mgr->lock);
        return false;
    }
    return true;
}

void log_manager_close(log_manager_t *mgr) {
    EnterCriticalSection(&mgr->lock);
    if (mgr->file) {
        fflush(mgr->file);
        fclose(mgr->file);
        mgr->file = NULL;
    }
    LeaveCriticalSection(&mgr->lock);
    DeleteCriticalSection(&mgr->lock);
}

static bool log_manager_rotate(log_manager_t *mgr) {
    if (!mgr->file) {
        return false;
    }
    fflush(mgr->file);
    fclose(mgr->file);
    mgr->file = NULL;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char rotated_name[64];
    snprintf(rotated_name, sizeof(rotated_name),
             "netmosaic-%04d%02d%02d-%02d%02d%02d.jsonl",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    char rotated_path[MAX_PATH];
    build_path(rotated_path, sizeof(rotated_path), mgr->directory, rotated_name);

    MoveFileExA(mgr->filename, rotated_path, MOVEFILE_REPLACE_EXISTING);
    log_manager_cleanup_rotations(mgr);
    mgr->current_size = 0;
    printf("[log] rotated to %s\n", rotated_path);
    return log_manager_reopen(mgr);
}

bool log_manager_write_line(log_manager_t *mgr, const char *line) {
    if (!mgr || !mgr->file || !line) {
        return false;
    }
    size_t len = strlen(line);
    EnterCriticalSection(&mgr->lock);
    if (mgr->rotate_bytes > 0 && (mgr->current_size + len) >= mgr->rotate_bytes) {
        if (!log_manager_rotate(mgr)) {
            LeaveCriticalSection(&mgr->lock);
            return false;
        }
    }
    size_t written = fwrite(line, 1, len, mgr->file);
    if (written == len) {
        mgr->current_size += written;
        fflush(mgr->file);
        LeaveCriticalSection(&mgr->lock);
        return true;
    }
    LeaveCriticalSection(&mgr->lock);
    return false;
}
