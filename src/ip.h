#pragma once

#include <stdint.h>

#include "common.h"

/* BEGIN PROTOTYPES */

int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_check_ipv4(ip4_hdr_t* ip4, uint32_t l2_length);

/* END PROTOTYPES */
