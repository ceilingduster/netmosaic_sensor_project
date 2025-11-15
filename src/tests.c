#include "sensor.h"

bool run_test_logs(sensor_runtime_t *runtime) {
    const char *sample = "{\"sensor_id\":\"TEST\",\"ts\":0.0,\"flow_hash\":\"0000000000000000\",\"proto\":\"TEST\",\"quarantine\":false}\n";
    log_manager_write_line(&runtime->log_mgr, sample);
    printf("[test-logs] wrote sample event to %s\n", runtime->config->log_path);
    return true;
}

static bool build_synthetic_packet(packet_job_t *job, bool outbound) {
    uint8_t payload[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t tcp_payload_len = sizeof(payload) - 1;
    size_t ip_header_len = sizeof(WINDIVERT_IPHDR);
    size_t tcp_header_len = sizeof(WINDIVERT_TCPHDR);
    size_t total_len = ip_header_len + tcp_header_len + tcp_payload_len;
    if (total_len > sizeof(job->packet)) {
        return false;
    }

    memset(job, 0, sizeof(*job));
    WINDIVERT_IPHDR *ip = (WINDIVERT_IPHDR *)job->packet;
    WINDIVERT_TCPHDR *tcp = (WINDIVERT_TCPHDR *)(job->packet + ip_header_len);

    ip->Version = 4;
    ip->HdrLength = 5;
    ip->TOS = 0;
    ip->Length = htons((uint16_t)total_len);
    ip->Id = htons(1);
    ip->FragOff0 = 0;
    ip->TTL = 64;
    ip->Protocol = IPPROTO_TCP;
    ip->SrcAddr = outbound ? htonl(0xC0A8010A) : htonl(0x08080808);
    ip->DstAddr = outbound ? htonl(0x08080808) : htonl(0xC0A8010A);

    tcp->SrcPort = htons(outbound ? 54321 : 80);
    tcp->DstPort = htons(outbound ? 80 : 54321);
    tcp->SeqNum = htonl(1);
    tcp->AckNum = 0;
    tcp->HdrLength = (uint8_t)(5 << 4);
    tcp->Window = htons(1024);

    memcpy(job->packet + ip_header_len + tcp_header_len, payload, tcp_payload_len);

    job->packet_len = (UINT)total_len;
    job->addr.Outbound = outbound ? 1 : 0;
    job->addr.IPv6 = 0;

    WinDivertHelperCalcChecksums(job->packet, job->packet_len, &job->addr, 0);

    if (!parse_packet_metadata(job->packet, job->packet_len, &job->addr, &job->meta)) {
        return false;
    }
    job->meta.timestamp_ns = get_time_nanoseconds();
    return true;
}

bool run_test_synthetic(sensor_runtime_t *runtime) {
    worker_context_t worker;
    if (!worker_context_init(&worker, runtime, 0, false)) {
        fprintf(stderr, "[test-synthetic] failed to create worker context\n");
        return false;
    }

    char json_line[MAX_JSON_BUFFER];
    packet_job_t job;
    if (!build_synthetic_packet(&job, true)) {
        fprintf(stderr, "[test-synthetic] failed to build packet\n");
        worker_context_shutdown(&worker);
        return false;
    }

    bool allow_reinject = false;
    size_t len = worker_process_packet(&worker, &job, json_line, sizeof(json_line), &allow_reinject);
    if (len > 0) {
        log_manager_write_line(&runtime->log_mgr, json_line);
        printf("[test-synthetic] generated event: %.*s", (int)len, json_line);
    }

    worker_context_shutdown(&worker);
    return len > 0;
}

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_header_t;
#pragma pack(pop)

static bool extract_ip_payload(const uint8_t *frame, uint32_t frame_len, const uint8_t **packet, uint32_t *packet_len) {
    if (frame_len < 14) {
        return false;
    }
    uint16_t ether_type = ntohs(*(uint16_t *)(frame + 12));
    size_t offset = 14;
    if (ether_type == 0x8100) {
        if (frame_len < 18) return false;
        ether_type = ntohs(*(uint16_t *)(frame + 16));
        offset += 4;
    }
    if (ether_type != 0x0800 && ether_type != 0x86DD) {
        return false;
    }
    if (frame_len <= offset) {
        return false;
    }
    *packet = frame + offset;
    *packet_len = frame_len - (uint32_t)offset;
    return true;
}

bool run_test_pcap(sensor_runtime_t *runtime, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[test-pcap] unable to open %s\n", path);
        return false;
    }

    pcap_file_header_t file_header;
    if (fread(&file_header, sizeof(file_header), 1, fp) != 1) {
        fclose(fp);
        return false;
    }
    if (file_header.magic != 0xA1B2C3D4 && file_header.magic != 0xD4C3B2A1) {
        fprintf(stderr, "[test-pcap] unsupported magic\n");
        fclose(fp);
        return false;
    }
    bool swapped = (file_header.magic == 0xD4C3B2A1);
    if (swapped) {
        file_header.version_major = swap_u16(file_header.version_major);
        file_header.version_minor = swap_u16(file_header.version_minor);
        file_header.snaplen = swap_u32(file_header.snaplen);
        file_header.network = swap_u32(file_header.network);
    }

    if (file_header.network != 1) {
        fprintf(stderr, "[test-pcap] unsupported linktype %u\n", file_header.network);
        fclose(fp);
        return false;
    }

    worker_context_t worker;
    if (!worker_context_init(&worker, runtime, 0, false)) {
        fclose(fp);
        return false;
    }

    uint8_t frame[MAX_PACKET_SIZE + 64];
    pcap_record_header_t rec;
    size_t events = 0;
    while (fread(&rec, sizeof(rec), 1, fp) == 1) {
        if (swapped) {
            rec.ts_sec = swap_u32(rec.ts_sec);
            rec.ts_usec = swap_u32(rec.ts_usec);
            rec.incl_len = swap_u32(rec.incl_len);
            rec.orig_len = swap_u32(rec.orig_len);
        }
        if (rec.incl_len > sizeof(frame)) {
            fseek(fp, rec.incl_len, SEEK_CUR);
            continue;
        }
        if (fread(frame, rec.incl_len, 1, fp) != 1) {
            break;
        }

        const uint8_t *packet_ptr = NULL;
        uint32_t packet_len = 0;
        if (!extract_ip_payload(frame, rec.incl_len, &packet_ptr, &packet_len)) {
            continue;
        }

        packet_job_t job;
        memset(&job, 0, sizeof(job));
        if (packet_len > MAX_PACKET_SIZE) {
            packet_len = MAX_PACKET_SIZE;
        }
        memcpy(job.packet, packet_ptr, packet_len);
        job.packet_len = packet_len;
        job.addr.Outbound = 0;
        job.addr.IPv6 = (packet_ptr[0] >> 4) == 6 ? 1 : 0;

        if (!parse_packet_metadata(job.packet, job.packet_len, &job.addr, &job.meta)) {
            continue;
        }
        job.meta.timestamp_ns = ((uint64_t)rec.ts_sec * 1000000000ULL) + ((uint64_t)rec.ts_usec * 1000ULL);

        char json_line[MAX_JSON_BUFFER];
        bool allow_reinject = false;
        size_t len = worker_process_packet(&worker, &job, json_line, sizeof(json_line), &allow_reinject);
        if (len > 0) {
            log_manager_write_line(&runtime->log_mgr, json_line);
            events++;
        }
    }

    printf("[test-pcap] processed %zu PCAP packets\n", events);
    worker_context_shutdown(&worker);
    fclose(fp);
    return events > 0;
}
