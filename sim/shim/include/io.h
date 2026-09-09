/* sim shim io.h */
#pragma once
#include <stdint.h>
#include <stddef.h>
int io_send_sw(uint16_t sw);
int io_send_response_pointer(const uint8_t *ptr, size_t size, uint16_t sw);
extern uint8_t G_io_apdu_buffer[260];
