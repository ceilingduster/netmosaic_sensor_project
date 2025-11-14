#include "sensor.h"
#include <malloc.h>
#include <stddef.h>

#ifndef MEMORY_ALLOCATION_ALIGNMENT
#define MEMORY_ALLOCATION_ALIGNMENT 16
#endif

typedef struct rotation_file {
    char path[MAX_PATH];
    FILETIME last_write;
} rotation_file_t;

typedef struct log_queue_node {
    SLIST_ENTRY entry;
    struct log_queue_node *next;
    size_t len;
    bool force_flush;
    char data[1];
} log_queue_node_t;

typedef struct log_batch {
    log_queue_node_t *head;
    size_t total_bytes;
    bool force_flush;
} log_batch_t;

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

static bool log_manager_open_primary(log_manager_t *mgr, DWORD extra_flags) {
    if (!ensure_parent_directory(mgr->filename)) {
        return false;
    }

    DWORD attributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | extra_flags;
    HANDLE handle = CreateFileA(mgr->filename,
                                FILE_GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_ALWAYS,
                                attributes,
                                NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size;
    size.QuadPart = 0;
    if (GetFileSizeEx(handle, &size)) {
        SetFilePointerEx(handle, size, NULL, FILE_BEGIN);
    }

    if (mgr->file && mgr->file != INVALID_HANDLE_VALUE) {
        CloseHandle(mgr->file);
    }
    mgr->file = handle;
    mgr->current_size = (size_t)size.QuadPart;
    return true;
}

static HANDLE log_manager_open_write_through(const log_manager_t *mgr) {
    DWORD attributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_WRITE_THROUGH;
    HANDLE handle = CreateFileA(mgr->filename,
                                FILE_GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_ALWAYS,
                                attributes,
                                NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    SetFilePointerEx(handle, zero, NULL, FILE_END);
    return handle;
}

static bool log_manager_rotate_locked(log_manager_t *mgr) {
    if (mgr->file && mgr->file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(mgr->file);
        CloseHandle(mgr->file);
        mgr->file = INVALID_HANDLE_VALUE;
    }

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
    return log_manager_open_primary(mgr, 0);
}

static void log_manager_free_batch(log_queue_node_t *node) {
    while (node) {
        log_queue_node_t *next = node->next;
        _aligned_free(node);
        node = next;
    }
}

static bool log_manager_write_nodes(HANDLE handle, log_queue_node_t *node, size_t *current_size) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    while (node) {
        const char *cursor = node->data;
        size_t remaining = node->len;
        while (remaining > 0) {
            DWORD chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
            DWORD written = 0;
            if (!WriteFile(handle, cursor, chunk, &written, NULL) || written != chunk) {
                return false;
            }
            remaining -= written;
            cursor += written;
            if (current_size) {
                *current_size += written;
            }
        }
        node = node->next;
    }
    return true;
}

static bool log_manager_write_batch(log_manager_t *mgr, const log_batch_t *batch) {
    if (!batch->head || batch->total_bytes == 0) {
        log_manager_free_batch(batch->head);
        return true;
    }

    EnterCriticalSection(&mgr->lock);

    if (!mgr->file || mgr->file == INVALID_HANDLE_VALUE) {
        if (!log_manager_open_primary(mgr, 0)) {
            LeaveCriticalSection(&mgr->lock);
            log_manager_free_batch(batch->head);
            return false;
        }
    }

    if (mgr->rotate_bytes > 0 && (mgr->current_size + batch->total_bytes) >= mgr->rotate_bytes) {
        if (!log_manager_rotate_locked(mgr)) {
            LeaveCriticalSection(&mgr->lock);
            log_manager_free_batch(batch->head);
            return false;
        }
    }

    HANDLE target = mgr->file;
    HANDLE forced = INVALID_HANDLE_VALUE;
    bool flush_main = false;
    if (batch->force_flush && mgr->force_flush_on_malicious) {
        forced = log_manager_open_write_through(mgr);
        if (forced != INVALID_HANDLE_VALUE) {
            target = forced;
        } else {
            flush_main = true;
        }
    }

    bool ok = log_manager_write_nodes(target, batch->head, &mgr->current_size);

    if (forced != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(forced);
        CloseHandle(forced);
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        SetFilePointerEx(mgr->file, zero, NULL, FILE_END);
    } else if (flush_main && mgr->file && mgr->file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(mgr->file);
    }

    LeaveCriticalSection(&mgr->lock);

    if (!ok) {
        DWORD err = GetLastError();
        fprintf(stderr, "[log] write batch failed (err=%lu)\n", err);
    }

    log_manager_free_batch(batch->head);
    return ok;
}

static bool log_manager_collect_batch(log_manager_t *mgr, log_batch_t *batch) {
    PSLIST_ENTRY raw = InterlockedFlushSList(&mgr->queue_head);
    if (!raw) {
        return false;
    }

    log_queue_node_t *ordered = NULL;
    size_t total = 0;
    bool force_flush = false;

    while (raw) {
        PSLIST_ENTRY next = raw->Next;
        log_queue_node_t *node = CONTAINING_RECORD(raw, log_queue_node_t, entry);
        total += node->len;
        force_flush |= node->force_flush;
        node->next = ordered;
        ordered = node;
        raw = next;
    }

    InterlockedExchangeAdd64(&mgr->queue_bytes, -((LONG64)total));
    if (force_flush) {
        InterlockedExchange(&mgr->pending_force_flush, 0);
    }

    batch->head = ordered;
    batch->total_bytes = total;
    batch->force_flush = force_flush;
    return true;
}

static bool log_manager_flush_pending(log_manager_t *mgr) {
    log_batch_t batch;
    if (!log_manager_collect_batch(mgr, &batch)) {
        return false;
    }
    return log_manager_write_batch(mgr, &batch);
}

static unsigned __stdcall log_manager_flush_thread(void *param) {
    log_manager_t *mgr = (log_manager_t *)param;

    for (;;) {
        while (log_manager_flush_pending(mgr)) {
            if (InterlockedCompareExchange(&mgr->shutdown, 0, 0) != 0) {
                break;
            }
        }

        if (InterlockedCompareExchange(&mgr->shutdown, 0, 0) != 0) {
            break;
        }

        DWORD wait_time = mgr->flush_interval_ms ? mgr->flush_interval_ms : INFINITE;
        DWORD result = WaitForSingleObject(mgr->flush_event, wait_time);
        (void)result;
    }

    while (log_manager_flush_pending(mgr)) {
        // drain remaining data before exit
    }

    return 0;
}

static void log_manager_enqueue(log_manager_t *mgr, log_queue_node_t *node) {
    node->entry.Next = NULL;
    InterlockedPushEntrySList(&mgr->queue_head, &node->entry);

    LONG64 previous = InterlockedExchangeAdd64(&mgr->queue_bytes, (LONG64)node->len);
    size_t new_total = (size_t)(previous + node->len);

    if (node->force_flush) {
        InterlockedExchange(&mgr->pending_force_flush, 1);
        SetEvent(mgr->flush_event);
        return;
    }

    if (mgr->max_buffer_bytes == 0 || new_total >= mgr->max_buffer_bytes || mgr->flush_interval_ms == 0) {
        SetEvent(mgr->flush_event);
    }
}

static bool log_manager_write_line_internal(log_manager_t *mgr, const char *line, bool force_flush) {
    if (!mgr || !line || !mgr->flush_event) {
        return false;
    }

    size_t len = strlen(line);
    if (len == 0) {
        return true;
    }

    bool require_flush = force_flush && mgr->force_flush_on_malicious;
    size_t alloc_size = offsetof(log_queue_node_t, data) + len + 1;
    log_queue_node_t *node = (log_queue_node_t *)_aligned_malloc(alloc_size, MEMORY_ALLOCATION_ALIGNMENT);
    if (!node) {
        return false;
    }

    node->len = len;
    node->force_flush = require_flush;
    node->next = NULL;
    memcpy(node->data, line, len + 1);

    log_manager_enqueue(mgr, node);
    return true;
}

bool log_manager_init(log_manager_t *mgr,
                      const char *path,
                      size_t rotate_bytes,
                      size_t max_buffer_bytes,
                      uint32_t flush_interval_ms,
                      bool force_flush_on_malicious_event) {
    if (!mgr || !path) {
        return false;
    }

    memset(mgr, 0, sizeof(*mgr));
    mgr->file = INVALID_HANDLE_VALUE;
    mgr->rotate_bytes = rotate_bytes;
    mgr->max_buffer_bytes = max_buffer_bytes ? max_buffer_bytes : DEFAULT_LOG_BUFFER_BYTES;
    mgr->flush_interval_ms = flush_interval_ms;
    mgr->force_flush_on_malicious = force_flush_on_malicious_event;
    InitializeCriticalSection(&mgr->lock);
    InitializeSListHead(&mgr->queue_head);

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

    if (!log_manager_open_primary(mgr, 0)) {
        DeleteCriticalSection(&mgr->lock);
        return false;
    }

    mgr->flush_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!mgr->flush_event) {
        log_manager_close(mgr);
        return false;
    }

    uintptr_t thread = _beginthreadex(NULL, 0, log_manager_flush_thread, mgr, 0, NULL);
    if (!thread) {
        log_manager_close(mgr);
        return false;
    }
    mgr->flush_thread = (HANDLE)thread;

    return true;
}

void log_manager_close(log_manager_t *mgr) {
    if (!mgr) {
        return;
    }

    InterlockedExchange(&mgr->shutdown, 1);
    if (mgr->flush_event) {
        SetEvent(mgr->flush_event);
    }
    if (mgr->flush_thread) {
        WaitForSingleObject(mgr->flush_thread, INFINITE);
        CloseHandle(mgr->flush_thread);
        mgr->flush_thread = NULL;
    }
    if (mgr->flush_event) {
        CloseHandle(mgr->flush_event);
        mgr->flush_event = NULL;
    }

    EnterCriticalSection(&mgr->lock);
    if (mgr->file && mgr->file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(mgr->file);
        CloseHandle(mgr->file);
        mgr->file = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&mgr->lock);
    DeleteCriticalSection(&mgr->lock);

    PSLIST_ENTRY leftover = InterlockedFlushSList(&mgr->queue_head);
    while (leftover) {
        PSLIST_ENTRY next = leftover->Next;
        log_queue_node_t *node = CONTAINING_RECORD(leftover, log_queue_node_t, entry);
        _aligned_free(node);
        leftover = next;
    }
}

bool log_manager_write_line(log_manager_t *mgr, const char *line) {
    return log_manager_write_line_internal(mgr, line, false);
}

bool log_manager_write_line_critical(log_manager_t *mgr, const char *line) {
    return log_manager_write_line_internal(mgr, line, true);
}
