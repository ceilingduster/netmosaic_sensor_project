#include "sensor.h"

static unsigned __stdcall capture_thread_main(void *arg) {
    capture_context_t *ctx = (capture_context_t *)arg;
    UINT64 flags = 0;
    if (!ctx->runtime->config->active_mode) {
        flags |= WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;
    }

    ctx->divert_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, flags);
    if (ctx->divert_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[capture] WinDivertOpen failed: %lu\n", GetLastError());
        InterlockedExchange(&ctx->runtime->running, 0);
        return 1;
    }

    WinDivertSetParam(ctx->divert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(ctx->divert_handle, WINDIVERT_PARAM_QUEUE_TIME, 512);

    while (InterlockedCompareExchange(&ctx->runtime->running, 0, 0)) {
        packet_job_t job;
        UINT recv_len = 0;
        WINDIVERT_ADDRESS addr;
        memset(&job, 0, sizeof(job));

        if (!WinDivertRecv(ctx->divert_handle, job.packet, sizeof(job.packet), &recv_len, &addr)) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED) {
                break;
            }
            Sleep(1);
            continue;
        }

        job.packet_len = recv_len;
        job.addr = addr;

        if (!parse_packet_metadata(job.packet, job.packet_len, &job.addr, &job.meta)) {
            continue;
        }

        bool dst_syslog_v4 = (!job.meta.ipv6 && ctx->runtime->syslog_allow_v4_valid &&
                               memcmp(job.meta.dst_ip, &ctx->runtime->syslog_allowed_v4, 4) == 0);
        bool dst_syslog_v6 = (job.meta.ipv6 && ctx->runtime->syslog_allow_v6_valid &&
                               memcmp(job.meta.dst_ip, &ctx->runtime->syslog_allowed_v6, 16) == 0);
        bool src_syslog_v4 = (!job.meta.ipv6 && ctx->runtime->syslog_allow_v4_valid &&
                               memcmp(job.meta.src_ip, &ctx->runtime->syslog_allowed_v4, 4) == 0);
        bool src_syslog_v6 = (job.meta.ipv6 && ctx->runtime->syslog_allow_v6_valid &&
                               memcmp(job.meta.src_ip, &ctx->runtime->syslog_allowed_v6, 16) == 0);
        bool syslog_match = (job.meta.proto == IPPROTO_UDP &&
                             ((job.meta.dst_port == ctx->runtime->config->syslog_port && (dst_syslog_v4 || dst_syslog_v6)) ||
                              (job.meta.src_port == ctx->runtime->config->syslog_port && (src_syslog_v4 || src_syslog_v6))));
        if (syslog_match) {
            continue;
        }

        flow_key_t key;
        metadata_to_flow_key(&job.meta, &key);
        uint64_t hash = flow_hash_from_key(&key);
        size_t worker_index = hash % ctx->worker_count;

        if (!ring_buffer_push(&ctx->workers[worker_index].queue, &job)) {
            continue;
        }

        InterlockedIncrement64(&ctx->runtime->metrics.packets_received);

        if (ctx->runtime->config->active_mode) {
            bool allow = runtime_is_quarantine_permitted(ctx->runtime, &job.meta);
            if (allow) {
                WinDivertSend(ctx->divert_handle, job.packet, job.packet_len, NULL, &addr);
            }
        }
    }

    WinDivertClose(ctx->divert_handle);
    ctx->divert_handle = INVALID_HANDLE_VALUE;
    return 0;
}

bool start_capture(capture_context_t *ctx, sensor_runtime_t *runtime, worker_context_t *workers, int worker_count) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->runtime = runtime;
    ctx->workers = workers;
    ctx->worker_count = worker_count;
    ctx->divert_handle = INVALID_HANDLE_VALUE;

    unsigned thread_id = 0;
    ctx->thread = (HANDLE)_beginthreadex(NULL, 0, capture_thread_main, ctx, 0, &thread_id);
    return ctx->thread != NULL;
}

void stop_capture(capture_context_t *ctx) {
    if (!ctx) return;
    if (ctx->divert_handle != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(ctx->divert_handle, WINDIVERT_SHUTDOWN_RECV);
    }
    if (ctx->thread) {
        WaitForSingleObject(ctx->thread, INFINITE);
        CloseHandle(ctx->thread);
        ctx->thread = NULL;
    }
    if (ctx->divert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(ctx->divert_handle);
        ctx->divert_handle = INVALID_HANDLE_VALUE;
    }
}
