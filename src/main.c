#include "sensor.h"

static sensor_config_t g_config;
static sensor_runtime_t g_runtime;
static bool g_wsa_started = false;
static volatile LONG g_signal_received = 0;

static void print_windivert_driver_path(void) {
    const char *driver_name = (sizeof(void *) == 8) ? "WinDivert64.sys" : "WinDivert32.sys";
    HMODULE windivert = GetModuleHandleA("WinDivert.dll");
    if (!windivert) {
        windivert = LoadLibraryA("WinDivert.dll");
        if (!windivert) {
            fprintf(stderr, "[main] unable to load WinDivert.dll (err=%lu)\n", GetLastError());
            return;
        }
    }

    char dll_path[MAX_PATH];
    DWORD len = GetModuleFileNameA(windivert, dll_path, ARRAYSIZE(dll_path));
    if (len == 0 || len >= ARRAYSIZE(dll_path)) {
        fprintf(stderr, "[main] unable to determine WinDivert.dll path (err=%lu)\n", GetLastError());
        return;
    }

    char directory[MAX_PATH];
    safe_strcpy(directory, sizeof(directory), dll_path);
    char *slash = strrchr(directory, '\\');
    char *slash2 = strrchr(directory, '/');
    char *pivot = slash;
    if (slash2 && (!pivot || slash2 > pivot)) {
        pivot = slash2;
    }
    if (pivot) {
        *pivot = '\0';
    } else {
        directory[0] = '\0';
    }

    char driver_path[MAX_PATH];
    build_path(driver_path, sizeof(driver_path), directory, driver_name);

    printf("[main] WinDivert driver path: %s\n", driver_path);
    sensor_debugf("[main] WinDivert driver path: %s", driver_path);
}

static BOOL WINAPI console_ctrl_handler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        InterlockedExchange(&g_signal_received, 1);
        InterlockedExchange(&g_runtime.running, 0);
        return TRUE;
    default:
        return FALSE;
    }
}

int main(int argc, char **argv) {
    sensor_debugf("[main] startup argc=%d", argc);
    FILE *trace = fopen("trace.log", "a");
    if (trace) {
        fprintf(trace, "entered main with %d args\n", argc);
        fclose(trace);
    }
    default_config(&g_config);
    print_windivert_driver_path();
    if (!parse_arguments(&g_config, argc, argv)) {
        sensor_debugf("[main] parse_arguments returned false");
        return 1;
    }

    if (!initialize_runtime(&g_runtime, &g_config, &g_wsa_started)) {
        sensor_debugf("[main] initialize_runtime failed");
        return 1;
    }

    if (g_config.test_logs) {
        sensor_debugf("[main] running log test mode");
        run_test_logs(&g_runtime);
        shutdown_runtime(&g_runtime, &g_wsa_started);
        return 0;
    }

    if (g_config.test_synthetic) {
        sensor_debugf("[main] running synthetic test mode");
        run_test_synthetic(&g_runtime);
        shutdown_runtime(&g_runtime, &g_wsa_started);
        return 0;
    }

    if (g_config.test_pcap) {
        sensor_debugf("[main] running pcap test mode (%s)", g_config.test_pcap_path);
        bool ok = run_test_pcap(&g_runtime, g_config.test_pcap_path);
        shutdown_runtime(&g_runtime, &g_wsa_started);
        return ok ? 0 : 1;
    }

    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        fprintf(stderr, "[main] failed to install console handler\n");
    }

    worker_context_t *workers = (worker_context_t *)calloc(g_config.workers, sizeof(worker_context_t));
    if (!workers) {
        fprintf(stderr, "[main] failed to allocate worker contexts\n");
        shutdown_runtime(&g_runtime, &g_wsa_started);
        return 1;
    }

    bool workers_ok = true;
    int started_workers = 0;
    for (int i = 0; i < g_config.workers; ++i) {
        if (!worker_context_init(&workers[i], &g_runtime, i, true)) {
            workers_ok = false;
            break;
        }
        started_workers++;
    }

    if (!workers_ok) {
        InterlockedExchange(&g_runtime.running, 0);
        if (started_workers > 0) {
            signal_workers_shutdown(workers, started_workers);
        }
        for (int i = 0; i < started_workers; ++i) {
            worker_context_shutdown(&workers[i]);
        }
        free(workers);
        shutdown_runtime(&g_runtime, &g_wsa_started);
        return 1;
    }

    capture_context_t capture;
    if (!start_capture(&capture, &g_runtime, workers, started_workers)) {
        fprintf(stderr, "[main] failed to start capture thread\n");
        InterlockedExchange(&g_runtime.running, 0);
        signal_workers_shutdown(workers, started_workers);
        for (int i = 0; i < started_workers; ++i) {
            worker_context_shutdown(&workers[i]);
        }
        free(workers);
        shutdown_runtime(&g_runtime, &g_wsa_started);
        return 1;
    }

    printf("[%s] running with %d worker(s). Press Ctrl+C to stop.\n", APP_NAME, g_config.workers);

    while (InterlockedCompareExchange(&g_runtime.running, 0, 0)) {
        Sleep(200);
    }

    stop_capture(&capture);
    signal_workers_shutdown(workers, started_workers);
    for (int i = 0; i < started_workers; ++i) {
        worker_context_shutdown(&workers[i]);
    }

    free(workers);
    shutdown_runtime(&g_runtime, &g_wsa_started);
    return 0;
}
