#pragma once

#include <assert.h>
#include <stdint.h>

#include <rte_config.h>
#include <rte_ether.h>
#include <rte_memory.h>
#include <rte_timer.h>

#include <pcap/pcap.h>

#include "common.h"
#include "sensor_conf.h"

/* DEFINES */

#define MBUF_SIZE (ETHER_MAX_LEN + sizeof(rte_mbuf_t) + RTE_PKTMBUF_HEADROOM)
#define MBUF_COUNT 6144

#define SOCKET_COUNT 2
#define NUMA_ENABLED 1

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

#define LCORE_RX_QUEUE_MAX    16
#define LCORE_PARAMS_MAX    1024
#define PORT_TX_QUEUE_MAX     16

#define MAX_TIMER_PERIOD 86400 /* 1 day max */

/* GLOBAL VARIABLES */

extern pcap_t*        ss_pcap;
extern ss_conf_t*     ss_conf;
extern rte_mempool_t* ss_pool[SOCKET_COUNT];
extern struct ether_addr port_eth_addrs[];

/* STRUCTURES */

struct mbuf_table_entry {
    unsigned int length;
    rte_mbuf_t* mbufs[MAX_PKT_BURST];
};

typedef struct mbuf_table_entry mbuf_table_entry_t;

struct ss_port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
} __rte_cache_aligned;

typedef struct ss_port_statistics ss_port_statistics_t;

/* BEGIN PROTOTYPES */

int ss_send_burst(uint8_t port_id, unsigned int lcore_id);
int ss_send_packet(rte_mbuf_t* mbuf, uint8_t port_id, unsigned int lcore_id);
void ss_main_loop(void);
int ss_launch_one_lcore(void* dummy);
void fatal_signal_handler(int signal);
void signal_handler_init(const char* signal_name, int signal);
int main(int argc, char* argv[]);

/* END PROTOTYPES */
