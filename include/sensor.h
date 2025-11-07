#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <process.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <direct.h>
#include <sys/stat.h>

#include "libs/windivert/include/windivert.h"

#include "libs/nDPI-4.14/src/include/ndpi_api.h"
#include "libs/nDPI-4.14/src/include/ndpi_main.h"
#include "libs/nDPI-4.14/src/include/ndpi_typedefs.h"
#include "libs/nDPI-4.14/src/include/ndpi_protocol_ids.h"

#include "libs/lua/src/lua.h"
#include "libs/lua/src/lualib.h"
#include "libs/lua/src/lauxlib.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

#define APP_NAME                 "NetMosaic Sensor"
#define VERSION_STRING           "1.0.0"
#define DEFAULT_WORKER_COUNT     4
#define MAX_WORKERS              32
#define RING_CAPACITY            2048u
#define MAX_PACKET_SIZE          0xFFFFu
#define PACKET_BATCH_MAX         1u
#define FLOW_TABLE_CAPACITY      65536u
#define LOG_ROTATION_HISTORY     10u
#define DEFAULT_LOG_MAX_BYTES    (10u * 1024u * 1024u)
#define LUA_MAX_SIGNATURE        96u
#define LUA_MAX_SCRIPTS          128u
#define MAX_SYSLOG_LINE          4096u
#define MAX_JSON_BUFFER          8192u
#define MAX_IP_STRING            128u
#define FLOW_VOLUME_BYTES_THRESHOLD 256ULL
#define FLOW_VOLUME_PACKET_THRESHOLD 4ULL

typedef struct sensor_config {
    int workers;
    bool active_mode;
    bool quarantine_mode;
    bool stdout_minimal;
    bool test_pcap;
    bool test_synthetic;
    bool test_logs;
    bool sensor_id_override;
    bool include_loopback;
    uint16_t syslog_port;
    size_t log_max_bytes;
    char syslog_ip[MAX_IP_STRING];
    char log_path[MAX_PATH];
    char sensor_id[128];
    char test_pcap_path[MAX_PATH];
} sensor_config_t;

typedef struct log_manager {
    FILE *file;
    char directory[MAX_PATH];
    char filename[MAX_PATH];
    size_t current_size;
    size_t rotate_bytes;
    CRITICAL_SECTION lock;
} log_manager_t;

typedef struct syslog_target {
    SOCKET sock;
    struct sockaddr_storage addr;
    int addr_len;
    bool enabled;
    CRITICAL_SECTION lock;
} syslog_target_t;

typedef struct lua_script_descriptor {
    char signature[LUA_MAX_SIGNATURE];
    char path[MAX_PATH];
} lua_script_descriptor_t;

typedef struct lua_script_instance {
    lua_State *L;
    int on_packet_ref;
    lua_script_descriptor_t descriptor;
} lua_script_instance_t;

typedef struct flow_key {
    bool ipv6;
    uint8_t proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
} flow_key_t;

typedef struct flow_entry {
    bool in_use;
    uint64_t hash;
    flow_key_t key;
    struct ndpi_flow_struct *ndpi_flow;
    uint64_t bytes;
    uint64_t packets;
    uint64_t bytes_inbound;
    uint64_t bytes_outbound;
    uint64_t packets_inbound;
    uint64_t packets_outbound;
    double first_seen;
    double last_seen;
    uint32_t risk;
    uint32_t dropped_packets;
    bool reported;
    bool payload_reported;
    bool final_reported;
    bool fin_seen_outbound;
    bool fin_seen_inbound;
    bool ndpi_finalized;
    uint16_t last_reported_master;
    uint16_t last_reported_app;
    uint32_t last_reported_risk;
    uint32_t last_reported_drops;
    uint64_t last_reported_bytes;
    uint64_t last_reported_packets;
    ndpi_protocol detected;
} flow_entry_t;

typedef struct flow_table {
    flow_entry_t *entries;
    size_t capacity;
} flow_table_t;

typedef struct packet_metadata {
    bool ipv6;
    bool outbound;
    uint8_t proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint64_t timestamp_ns;
    uint32_t payload_len;
    bool tcp_fin;
    bool tcp_rst;
} packet_metadata_t;

typedef struct packet_job {
    packet_metadata_t meta;
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    uint8_t packet[MAX_PACKET_SIZE];
} packet_job_t;

typedef struct ring_buffer {
    packet_job_t *slots;
    size_t capacity;
    volatile LONG write_index;
    volatile LONG read_index;
} ring_buffer_t;

typedef struct runtime_metrics {
    volatile LONG64 packets_received;
    volatile LONG64 packets_processed;
    volatile LONG64 packets_dropped_quarantine;
} runtime_metrics_t;

typedef struct worker_context worker_context_t;

typedef struct sensor_runtime {
    sensor_config_t *config;
    log_manager_t log_mgr;
    syslog_target_t syslog;
    runtime_metrics_t metrics;
    lua_script_descriptor_t scripts[LUA_MAX_SCRIPTS];
    size_t script_count;
    volatile LONG running;
    uint32_t syslog_allowed_v4;
    struct in6_addr syslog_allowed_v6;
    bool syslog_allow_v4_valid;
    bool syslog_allow_v6_valid;
    bool include_loopback;
} sensor_runtime_t;

struct worker_context {
    sensor_runtime_t *runtime;
    int worker_id;
    ring_buffer_t queue;
    HANDLE thread;
    flow_table_t flows;
    struct ndpi_detection_module_struct *ndpi_module;
    ndpi_serializer ndpi_serializer;
    bool ndpi_serializer_ready;
    lua_script_instance_t lua_scripts[LUA_MAX_SCRIPTS];
    size_t lua_script_count;
};

typedef struct capture_context {
    sensor_runtime_t *runtime;
    worker_context_t *workers;
    int worker_count;
    HANDLE thread;
    HANDLE shutdown_event;
    HANDLE divert_handle;
} capture_context_t;

typedef struct json_builder {
    char data[MAX_JSON_BUFFER];
    size_t len;
    int depth;
    bool first[16];
} json_builder_t;

#ifdef __cplusplus
extern "C" {
#endif

void safe_strcpy(char *dest, size_t dest_size, const char *src);
uint32_t swap_u32(uint32_t v);
uint16_t swap_u16(uint16_t v);
uint64_t fnv1a64(const void *data, size_t len);
uint64_t get_time_nanoseconds(void);
double get_time_seconds(void);
bool read_machine_guid(char *buffer, size_t length);
bool ensure_directory_exists(const char *path);
bool ensure_parent_directory(const char *filepath);
void build_path(char *dst, size_t dst_size, const char *dir, const char *name);

void jb_reset(json_builder_t *jb);
bool jb_open_object(json_builder_t *jb);
bool jb_close_object(json_builder_t *jb);
bool jb_add_string(json_builder_t *jb, const char *key, const char *value);
bool jb_add_uint64(json_builder_t *jb, const char *key, uint64_t value);
bool jb_add_int64(json_builder_t *jb, const char *key, int64_t value);
bool jb_add_double(json_builder_t *jb, const char *key, double value);
bool jb_add_bool(json_builder_t *jb, const char *key, bool value);
bool jb_begin_object_field(json_builder_t *jb, const char *key);
bool jb_add_raw(json_builder_t *jb, const char *key, const char *raw_json, size_t raw_len);

bool ring_buffer_init(ring_buffer_t *rb, size_t capacity);
void ring_buffer_free(ring_buffer_t *rb);
bool ring_buffer_push(ring_buffer_t *rb, const packet_job_t *job);
bool ring_buffer_pop(ring_buffer_t *rb, packet_job_t *out_job);
bool ring_buffer_empty(const ring_buffer_t *rb);

bool flow_table_init(flow_table_t *table, size_t capacity);
void flow_table_free(flow_table_t *table);
void flow_table_release(flow_entry_t *entry);
flow_entry_t *flow_table_acquire(flow_table_t *table, const flow_key_t *key, uint64_t hash, bool *is_new);
void metadata_to_flow_key(const packet_metadata_t *meta, flow_key_t *key);
uint64_t flow_hash_from_key(const flow_key_t *key);
void format_ip_string(const packet_metadata_t *meta, bool source, char *buffer, size_t buffer_len);
bool parse_packet_metadata(const uint8_t *packet, UINT packet_len, const WINDIVERT_ADDRESS *addr, packet_metadata_t *meta);

bool load_lua_scripts(sensor_runtime_t *rt);
bool worker_prepare_lua(worker_context_t *worker);

bool log_manager_init(log_manager_t *mgr, const char *path, size_t rotate_bytes);
void log_manager_close(log_manager_t *mgr);
bool log_manager_write_line(log_manager_t *mgr, const char *line);

bool syslog_target_init(syslog_target_t *target, const sensor_config_t *cfg);
void syslog_target_close(syslog_target_t *target);
bool syslog_target_send(syslog_target_t *target, const char *line);

void runtime_update_syslog_allow(sensor_runtime_t *rt);
bool initialize_runtime(sensor_runtime_t *rt, sensor_config_t *cfg, bool *wsa_started);
void shutdown_runtime(sensor_runtime_t *rt, bool *wsa_started);
bool runtime_is_quarantine_permitted(sensor_runtime_t *rt, const packet_metadata_t *meta);

bool worker_context_init(worker_context_t *worker, sensor_runtime_t *runtime, int worker_id, bool spawn_thread);
void worker_context_shutdown(worker_context_t *worker);
void signal_workers_shutdown(worker_context_t *workers, int count);
size_t worker_process_packet(worker_context_t *worker,
                             const packet_job_t *job,
                             char *json_out,
                             size_t json_out_size,
                             bool *allow_reinject);

bool start_capture(capture_context_t *ctx, sensor_runtime_t *runtime, worker_context_t *workers, int worker_count);
void stop_capture(capture_context_t *ctx);

void default_config(sensor_config_t *cfg);
bool parse_arguments(sensor_config_t *cfg, int argc, char **argv);
void print_usage(void);

bool run_test_logs(sensor_runtime_t *runtime);
bool run_test_synthetic(sensor_runtime_t *runtime);
bool run_test_pcap(sensor_runtime_t *runtime, const char *path);

#ifdef __cplusplus
}
#endif
