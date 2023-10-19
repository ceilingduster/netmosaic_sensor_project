#include "sensor.h"

static size_t next_power_of_two(size_t value) {
    size_t n = 1;
    while (n < value) {
        n <<= 1;
    }
    return n;
}

bool ring_buffer_init(ring_buffer_t *rb, size_t capacity) {
    memset(rb, 0, sizeof(*rb));
    rb->capacity = next_power_of_two(capacity);
    rb->slots = (packet_job_t *)calloc(rb->capacity, sizeof(packet_job_t));
    rb->write_index = 0;
    rb->read_index = 0;
    return rb->slots != NULL;
}

void ring_buffer_free(ring_buffer_t *rb) {
    if (rb->slots) {
        free(rb->slots);
        rb->slots = NULL;
    }
}

bool ring_buffer_push(ring_buffer_t *rb, const packet_job_t *job) {
    LONG head = rb->write_index;
    LONG tail = rb->read_index;
    LONG next = (head + 1) % (LONG)rb->capacity;
    if (next == tail) {
        return false; /* full */
    }
    rb->slots[head] = *job;
    _InterlockedExchange(&rb->write_index, next);
    return true;
}

bool ring_buffer_pop(ring_buffer_t *rb, packet_job_t *out_job) {
    LONG head = rb->write_index;
    LONG tail = rb->read_index;
    if (tail == head) {
        return false;
    }
    if (out_job) {
        *out_job = rb->slots[tail];
    }
    LONG next = (tail + 1) % (LONG)rb->capacity;
    _InterlockedExchange(&rb->read_index, next);
    return true;
}

bool ring_buffer_empty(const ring_buffer_t *rb) {
    return rb->write_index == rb->read_index;
}
