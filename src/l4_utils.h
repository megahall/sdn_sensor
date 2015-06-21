#pragma once

#include <stddef.h>
#include <stdint.h>

#include "common.h"

/* BEGIN PROTOTYPES */

int ss_buffer_dump(const char* source, uint8_t* buffer, uint16_t length);
int ss_frame_layer_off_len_get(ss_frame_t* rx_buf, void* layer_start, size_t layer_hdr_size, uint8_t** layer_offset, uint16_t* layer_length);
int ss_frame_find_l4_header(ss_frame_t* rx_buf, uint8_t ip_protocol);
uint8_t* ss_phdr_append(rte_mbuf_t* pmbuf, void* data, uint16_t length);
int ss_frame_prepare_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_prepare_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
void ss_frame_destroy(ss_frame_t* fbuf);

/* END PROTOTYPES */
