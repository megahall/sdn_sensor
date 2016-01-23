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

#define BURST_PACKETS_MAX       32

// RX queue size is 128 by default
// RX burst size is 32 by default
#define BURST_PACKETS_BATCH_1   (BURST_PACKETS_MAX * 1)
#define BURST_PACKETS_BATCH_2   (BURST_PACKETS_MAX * 2)
#define BURST_PACKETS_BATCH_3   (BURST_PACKETS_MAX * 3)

#define BURST_TREND_BATCH_1     1
#define BURST_TREND_BATCH_2     100
#define BURST_TREND_FREQ_UP     10000

// TX drain every ~100 usecs
#define BURST_TX_DRAIN_USECS    100

// around 100 msecs at 2 GHz
#define TIMER_RESOLUTION_CYCLES 200000000ULL
// 100 msecs interval
#define TIMER_TICKS_PER_SEC     10
// 1 day max
#define TIMER_PERIOD_MAX 86400

// 100000 usecs
#define SCALING_PERIOD          (1000000 / TIMER_TICKS_PER_SEC)
#define SCALING_TIME_RATIO      0.25
#define ZERO_RX_MIN_COUNT       10

#define LCORE_SLEEP_USECS       1
#define LCORE_SUSPEND_USECS     300

/* GLOBAL VARIABLES */

extern pcap_t*        ss_pcap;
extern ss_conf_t*     ss_conf;
extern rte_mempool_t* ss_pool[SOCKET_COUNT];
extern struct ether_addr port_eth_addrs[];

/* STRUCTURES */

enum ss_freq_hint_e {
    FREQ_LOWER   = -1,
    FREQ_CURRENT =  0,
    FREQ_HIGHER  =  1,
    FREQ_HIGHEST =  2,
};

typedef enum ss_freq_hint_e ss_freq_hint_t;

struct mbuf_table_entry_s {
    unsigned int length;
    rte_mbuf_t* mbufs[BURST_PACKETS_MAX];
};

typedef struct mbuf_table_entry_s mbuf_table_entry_t;

struct ss_port_statistics_s {
    rte_spinlock_t port_lock;
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
    struct rte_eth_stats* eth_stats;
} __rte_cache_aligned;

typedef struct ss_port_statistics_s ss_port_statistics_t;

static_assert(sizeof(ss_port_statistics_t) == 64, "ss_port_statistics_t should consume one cacheline");

struct ss_queue_statistics_s {
    uint64_t zero_rx;
    uint32_t idle_hint;
    ss_freq_hint_t freq_hint;
    uint64_t padding[6];
} __rte_cache_aligned;

typedef struct ss_queue_statistics_s ss_queue_statistics_t;

static_assert(sizeof(ss_queue_statistics_t) == 64, "ss_queue_statistics_t should consume one cacheline");

struct ss_core_statistics_s {
    /* sleep time in msecs since last scale down */
    uint64_t sleep_msecs;
    /* number of long sleep recently */
    uint64_t long_sleep;
    /* freq. scaling up trend */
    uint64_t freq_trend;
    /* total packet processed recently */
    uint64_t rx_processed;
    /* total iterations looped recently */
    uint64_t loop_iterations;

    uint64_t padding[3];
} __rte_cache_aligned;

typedef struct ss_core_statistics_s ss_core_statistics_t;

static_assert(sizeof(ss_core_statistics_t) == 64, "ss_core_statistics_t should consume one cacheline");

/* BEGIN PROTOTYPES */

int ss_send_burst(uint8_t port_id, uint16_t lcore_id);
int ss_send_packet(rte_mbuf_t* mbuf, uint8_t port_id, uint16_t lcore_id);
void ss_power_timer_callback(struct rte_timer* timer, void* arg);
uint32_t ss_power_check_idle(uint64_t zero_rx);
ss_freq_hint_t ss_power_check_scale_up(uint16_t lcore_id, uint8_t port_id);
int ss_power_irq_register(uint16_t lcore_id);
int ss_power_irq_enable(uint16_t lcore_id);
int ss_power_irq_handle(void);
int ss_main_loop(void* arg);
void ss_fatal_signal_handler(int signal);
void ss_signal_handler_init(const char* signal_name, int signal);
int main(int argc, char* argv[]);

/* END PROTOTYPES */
