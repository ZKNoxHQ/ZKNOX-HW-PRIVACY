/* sim shim buffer.h — SDK-compatible subset */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
typedef struct { const uint8_t *ptr; size_t size; size_t offset; } buffer_t;
static inline bool buffer_can_read(const buffer_t *b, size_t n) { return b->size - b->offset >= n; }
static inline bool buffer_read_u8(buffer_t *b, uint8_t *out) {
    if (!buffer_can_read(b, 1)) return false;
    *out = b->ptr[b->offset++]; return true;
}
static inline bool buffer_read_u32(buffer_t *b, uint32_t *out, int be) {
    if (!buffer_can_read(b, 4)) return false;
    const uint8_t *p = b->ptr + b->offset;
    *out = be ? ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]
              : ((uint32_t)p[3]<<24)|((uint32_t)p[2]<<16)|((uint32_t)p[1]<<8)|p[0];
    b->offset += 4; return true;
}
static inline bool buffer_move(buffer_t *b, uint8_t *out, size_t n) {
    if (!buffer_can_read(b, n)) return false;
    memmove(out, b->ptr + b->offset, n); b->offset += n; return true;
}
static inline bool buffer_seek_cur(buffer_t *b, size_t n) {
    if (!buffer_can_read(b, n)) return false;
    b->offset += n; return true;
}
#define BE 1
#define LE 0
