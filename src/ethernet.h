#pragma once

#include <stdint.h>

#include "common.h"

/* BEGIN PROTOTYPES */

void ss_frame_handle(rte_mbuf_t* mbuf, unsigned int lcore_id, uint8_t port_id);
int ss_frame_prepare_eth(ss_frame_t* tx_buf, uint8_t port_id, eth_addr_t* d_addr, uint16_t type);
int ss_frame_handle_eth(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_arp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ndp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);

/* END PROTOTYPES */
