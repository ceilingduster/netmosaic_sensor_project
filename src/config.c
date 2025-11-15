#include "sensor.h"

void print_usage(void) {
    fprintf(stderr,
        "%s %s\n"
        "Usage: netmosaic_sensor [options]\n"
        "  --workers N           Number of worker threads (default %d)\n"
        "  --active              Enable inline reinjection\n"
        "  --quarantine          Enable quarantine mode (drops outbound reinjection)\n"
        "  --log-file PATH       JSONL log path (default ./logs/network.jsonl)\n"
        "  --log-buffer-bytes N   Buffered log queue threshold in bytes (default %llu)\n"
        "  --log-flush-interval-ms MS  Max milliseconds before writer flush (default %u)\n"
        "  --no-log-force-flush  Disable write-through flush for malicious events\n"
        "  --sensor-id ID        Override sensor identifier\n"
        "  --stdout-minimal      Suppress verbose stdout logging\n"
        "  --include-loopback    Do not suppress loopback-only flows\n"
        "  --test-pcap FILE      Offline test mode using PCAP (lightweight parser)\n"
        "  --test-synthetic      Generate synthetic packets for testing\n"
        "  --test-logs           Exercise logger without capture\n"
        , APP_NAME, VERSION_STRING, DEFAULT_WORKER_COUNT,
        (unsigned long long)DEFAULT_LOG_BUFFER_BYTES,
        DEFAULT_LOG_FLUSH_INTERVAL_MS);
}

void default_config(sensor_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->workers = DEFAULT_WORKER_COUNT;
    cfg->log_max_bytes = DEFAULT_LOG_MAX_BYTES;
    cfg->log_buffer_bytes = DEFAULT_LOG_BUFFER_BYTES;
    cfg->log_flush_interval_ms = DEFAULT_LOG_FLUSH_INTERVAL_MS;
    cfg->log_force_flush_on_malicious = DEFAULT_FORCE_FLUSH_ON_MALICIOUS;
    cfg->stdout_minimal = false;
    cfg->include_loopback = false;
    safe_strcpy(cfg->log_path, sizeof(cfg->log_path), "logs\\network.jsonl");
}

bool parse_arguments(sensor_config_t *cfg, int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (_stricmp(arg, "--workers") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --workers\n");
                return false;
            }
            cfg->workers = atoi(argv[++i]);
            if (cfg->workers <= 0 || cfg->workers > MAX_WORKERS) {
                fprintf(stderr, "Invalid worker count: %d\n", cfg->workers);
                return false;
            }
        } else if (_stricmp(arg, "--active") == 0) {
            cfg->active_mode = true;
        } else if (_stricmp(arg, "--quarantine") == 0) {
            cfg->quarantine_mode = true;
            cfg->active_mode = true;
        } else if (_stricmp(arg, "--log-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --log-file\n");
                return false;
            }
            safe_strcpy(cfg->log_path, sizeof(cfg->log_path), argv[++i]);
        } else if (_stricmp(arg, "--log-buffer-bytes") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --log-buffer-bytes\n");
                return false;
            }
            cfg->log_buffer_bytes = (size_t)_strtoui64(argv[++i], NULL, 10);
            if (cfg->log_buffer_bytes == 0) {
                fprintf(stderr, "--log-buffer-bytes must be greater than zero\n");
                return false;
            }
        } else if (_stricmp(arg, "--log-flush-interval-ms") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --log-flush-interval-ms\n");
                return false;
            }
            cfg->log_flush_interval_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (_stricmp(arg, "--no-log-force-flush") == 0) {
            cfg->log_force_flush_on_malicious = false;
        } else if (_stricmp(arg, "--sensor-id") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --sensor-id\n");
                return false;
            }
            safe_strcpy(cfg->sensor_id, sizeof(cfg->sensor_id), argv[++i]);
            cfg->sensor_id_override = true;
        } else if (_stricmp(arg, "--stdout-minimal") == 0) {
            cfg->stdout_minimal = true;
        } else if (_stricmp(arg, "--include-loopback") == 0) {
            cfg->include_loopback = true;
        } else if (_stricmp(arg, "--test-pcap") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --test-pcap\n");
                return false;
            }
            cfg->test_pcap = true;
            safe_strcpy(cfg->test_pcap_path, sizeof(cfg->test_pcap_path), argv[++i]);
        } else if (_stricmp(arg, "--test-synthetic") == 0) {
            cfg->test_synthetic = true;
        } else if (_stricmp(arg, "--test-logs") == 0) {
            cfg->test_logs = true;
        } else if (_stricmp(arg, "--help") == 0 || _stricmp(arg, "-h") == 0) {
            print_usage();
            return false;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", arg);
            print_usage();
            return false;
        }
    }

    if (cfg->test_pcap || cfg->test_synthetic || cfg->test_logs) {
        cfg->active_mode = false;
        cfg->quarantine_mode = false;
    }

    return true;
}
