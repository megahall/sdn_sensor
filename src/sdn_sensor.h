#ifndef __SDN_SENSOR_H__
#define __SDN_SENSOR_H__

#include <stdint.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_memory.h>

#include "common.h"

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 8  /**< Default values of TX write-back threshold reg. */

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */

struct mbuf_table {
    unsigned length;
    struct rte_mbuf* mbufs[MAX_PKT_BURST];
} __rte_cache_aligned;

struct lcore_queue_conf {
    unsigned rx_port_count;
    unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
    struct mbuf_table tx_table[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct ss_port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
} __rte_cache_aligned;

/* BEGIN PROTOTYPES */

int ss_send_burst(struct lcore_queue_conf* queue_conf, unsigned int n, uint8_t port);
int ss_send_packet(struct rte_mbuf* m, uint8_t port_id);
int ss_frame_prep_eth(ss_frame_t* tx_buf, int port_id, eth_addr_t* d_addr, uint16_t type);
void ss_frame_handle(struct rte_mbuf* mbuf, unsigned int port_id);
int ss_frame_handle_eth(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_arp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ndp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_prepare_icmp6(ss_frame_t* tx_buf, uint8_t* pl_ptr, uint32_t pl_len);
int ss_frame_handle_echo4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_echo6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_icmp4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_icmp6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
void ss_main_loop(void);
int ss_launch_one_lcore(void* dummy);
int main(int argc, char* argv[]);

/* END PROTOTYPES */

#endif /* __SDN_SENSOR_H__ */
