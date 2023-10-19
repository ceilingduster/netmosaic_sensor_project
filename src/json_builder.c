#include "sensor.h"

static bool jb_putc(json_builder_t *jb, char c) {
    if (jb->len + 1 >= sizeof(jb->data)) {
        return false;
    }
    jb->data[jb->len++] = c;
    jb->data[jb->len] = '\0';
    return true;
}

static bool jb_puts(json_builder_t *jb, const char *s) {
    while (s && *s) {
        if (!jb_putc(jb, *s++)) {
            return false;
        }
    }
    return true;
}

static bool jb_put_raw(json_builder_t *jb, const char *raw, size_t len) {
    if (!raw) {
        return jb_puts(jb, "null");
    }
    for (size_t i = 0; i < len; ++i) {
        if (!jb_putc(jb, raw[i])) {
            return false;
        }
    }
    return true;
}

static bool jb_escape_and_puts(json_builder_t *jb, const char *s) {
    if (!s) {
        return jb_puts(jb, "null");
    }
    if (!jb_putc(jb, '"')) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        switch (*p) {
        case '\"': if (!jb_puts(jb, "\\\"")) return false; break;
        case '\\': if (!jb_puts(jb, "\\\\")) return false; break;
        case '\b': if (!jb_puts(jb, "\\b")) return false; break;
        case '\f': if (!jb_puts(jb, "\\f")) return false; break;
        case '\n': if (!jb_puts(jb, "\\n")) return false; break;
        case '\r': if (!jb_puts(jb, "\\r")) return false; break;
        case '\t': if (!jb_puts(jb, "\\t")) return false; break;
        default:
            if (*p < 0x20) {
                char buf[7];
                snprintf(buf, sizeof(buf), "\\u%04x", *p);
                if (!jb_puts(jb, buf)) return false;
            } else {
                if (!jb_putc(jb, (char)*p)) return false;
            }
            break;
        }
    }
    return jb_putc(jb, '"');
}

static bool jb_push_field(json_builder_t *jb, const char *key) {
    int level = jb->depth - 1;
    if (level < 0) {
        level = 0;
    }
    if (!jb->first[level]) {
        if (!jb_putc(jb, ',')) return false;
    } else {
        jb->first[level] = false;
    }
    if (!jb_escape_and_puts(jb, key)) return false;
    return jb_putc(jb, ':');
}

void jb_reset(json_builder_t *jb) {
    memset(jb, 0, sizeof(*jb));
}

bool jb_open_object(json_builder_t *jb) {
    if (!jb_putc(jb, '{')) return false;
    jb->first[jb->depth] = true;
    jb->depth++;
    return true;
}

bool jb_close_object(json_builder_t *jb) {
    if (jb->depth <= 0) return false;
    jb->depth--;
    return jb_putc(jb, '}');
}

bool jb_add_string(json_builder_t *jb, const char *key, const char *value) {
    if (!jb_push_field(jb, key)) return false;
    return jb_escape_and_puts(jb, value ? value : "");
}

bool jb_add_uint64(json_builder_t *jb, const char *key, uint64_t value) {
    if (!jb_push_field(jb, key)) return false;
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    return jb_puts(jb, buf);
}

bool jb_add_int64(json_builder_t *jb, const char *key, int64_t value) {
    if (!jb_push_field(jb, key)) return false;
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", (long long)value);
    return jb_puts(jb, buf);
}

bool jb_add_double(json_builder_t *jb, const char *key, double value) {
    if (!jb_push_field(jb, key)) return false;
    char buf[64];
    snprintf(buf, sizeof(buf), "%.6f", value);
    return jb_puts(jb, buf);
}

bool jb_add_bool(json_builder_t *jb, const char *key, bool value) {
    if (!jb_push_field(jb, key)) return false;
    return jb_puts(jb, value ? "true" : "false");
}

bool jb_begin_object_field(json_builder_t *jb, const char *key) {
    if (!jb_push_field(jb, key)) return false;
    return jb_open_object(jb);
}

bool jb_add_raw(json_builder_t *jb, const char *key, const char *raw_json, size_t raw_len) {
    if (!jb_push_field(jb, key)) return false;
    return jb_put_raw(jb, raw_json, raw_len);
}
