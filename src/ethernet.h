#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include <stdint.h>

#include "common.h"

/* BEGIN PROTOTYPES */

void ss_frame_handle(struct rte_mbuf* mbuf, unsigned int lcore_id, unsigned int port_id);
int ss_frame_prepare_eth(ss_frame_t* tx_buf, int port_id, eth_addr_t* d_addr, uint16_t type);
int ss_frame_handle_eth(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_arp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ndp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);

/* END PROTOTYPES */

#endif /* __ETHERNET_H__ */
