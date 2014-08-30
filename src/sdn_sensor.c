#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wordexp.h>

#include <bsd/sys/queue.h>

#include <net/if_arp.h>
#include <netinet/in.h>

#include <sys/types.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_hexdump.h>

#include <pcap/pcap.h>

#include "checksum.h"
#include "common.h"
#include "ethernet.h"
#include "sdn_sensor.h"
#include "dpdk.h"
#include "sensor_conf.h"

/* GLOBAL VARIABLES */

pcap_t* ss_pcap = NULL;
ss_conf_t* ss_conf = NULL;
rte_mempool_t* ss_pool = NULL;

/* ethernet addresses of ports */
struct ether_addr port_eth_addrs[RTE_MAX_ETHPORTS];

//const char* icmp_payload = "mhallmhallmhallmhallmhallmhallmhallmhall!!!!!!!!";

static uint16_t rxd_count = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t txd_count = RTE_TEST_TX_DESC_DEFAULT;

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = RX_PTHRESH,
        .hthresh = RX_HTHRESH,
        .wthresh = RX_WTHRESH,
    },
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = TX_PTHRESH,
        .hthresh = TX_HTHRESH,
        .wthresh = TX_WTHRESH,
    },
    .tx_free_thresh = 0, /* Use PMD default values */
    .tx_rs_thresh = 0, /* Use PMD default values */
    .txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

struct ss_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
/* default period is 10 seconds */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000;

/* Send the burst of packets on an output interface */
int ss_send_burst(struct lcore_queue_conf *queue_conf, unsigned int n, uint8_t port) {
    struct rte_mbuf** mbufs;
    unsigned int rv;
    unsigned int queueid =0;

    mbufs = (struct rte_mbuf**) queue_conf->tx_table[port].mbufs;

    rv = rte_eth_tx_burst(port, (uint16_t) queueid, mbufs, (uint16_t) n);
    port_statistics[port].tx += rv;
    if (unlikely(rv < n)) {
        port_statistics[port].dropped += (n - rv);
        do {
            rte_pktmbuf_free(mbufs[rv]);
        } while (++rv < n);
    }

    return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
int ss_send_packet(struct rte_mbuf *m, uint8_t port_id) {
    unsigned int lcore_id;
    unsigned int length;
    struct lcore_queue_conf *queue_conf;

    lcore_id = rte_lcore_id();

    queue_conf = &lcore_queue_conf[lcore_id];
    length = queue_conf->tx_table[port_id].length;
    queue_conf->tx_table[port_id].mbufs[length] = m;
    length++;

    /* enough pkts to be sent */
    if (unlikely(length == MAX_PKT_BURST)) {
        ss_send_burst(queue_conf, MAX_PKT_BURST, port_id);
        length = 0;
    }

    queue_conf->tx_table[port_id].length = length;
    return 0;
}

/* main processing loop */
void ss_main_loop(void) {
    struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf* m;
    unsigned int lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned i, j, port_id, rx_count;
    struct lcore_queue_conf* queue_conf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id = rte_lcore_id();
    queue_conf = &lcore_queue_conf[lcore_id];

    if (queue_conf->rx_port_count == 0) {
        RTE_LOG(INFO, SS, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, SS, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < queue_conf->rx_port_count; i++) {
        port_id = queue_conf->rx_port_list[i];
        RTE_LOG(INFO, SS, " -- lcoreid=%u port_id=%u\n", lcore_id, port_id);
    }

    while (1) {
        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {

            for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                //RTE_LOG(INFO, SS, "attempt send for port %d\n", port_id);
                if (queue_conf->tx_table[port_id].length == 0) {
                    //RTE_LOG(INFO, SS, "send no frames for port %d\n", port_id);
                    continue;
                }
                //RTE_LOG(INFO, SS, "send %u frames for port %d\n", queue_conf->tx_table[port_id].length, port_id);
                ss_send_burst(&lcore_queue_conf[lcore_id], queue_conf->tx_table[port_id].length, (uint8_t) port_id);
                queue_conf->tx_table[port_id].length = 0;
            }

            /* if timer is enabled */
            if (timer_period > 0) {
                /* advance the timer */
                timer_tsc += diff_tsc;

                /* if timer has reached its timeout */
                if (unlikely(timer_tsc >= (uint64_t) timer_period)) {

                    /* do this only on master core */
                    if (lcore_id == rte_get_master_lcore()) {
                        ss_port_stats_print(port_statistics, ss_conf->port_count);
                        /* reset the timer */
                        timer_tsc = 0;
                    }
                }
            }

            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < queue_conf->rx_port_count; i++) {
            port_id = queue_conf->rx_port_list[i];
            rx_count = rte_eth_rx_burst((uint8_t) port_id, 0, pkts_burst, MAX_PKT_BURST);
            
            port_statistics[port_id].rx += rx_count;
            
            for (j = 0; j < rx_count; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                ss_frame_handle(m, port_id);
            }
        }
    }
}

int ss_launch_one_lcore(__attribute__((unused)) void *dummy) {
    ss_main_loop();
    return 0;
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "launching sdn_sensor version %s\n", SS_VERSION);
    
    ss_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    if (ss_pcap == NULL) {
        fprintf(stderr, "could not prepare pcap_t\n");
        exit(1);
    }
    
    ss_conf = ss_conf_file_parse();
    if (ss_conf == NULL) {
        fprintf(stderr, "could not parse sdn_sensor configuration\n");
        exit(1);
    }
    
    struct lcore_queue_conf* queue_conf;
    struct rte_eth_dev_info dev_info;
    int rv;
    uint8_t port_id, last_port;
    unsigned int lcore_id;
    unsigned int rx_lcore_id;

    /* init EAL */
    rv = rte_eal_init(ss_conf->eal_vector.we_wordc, ss_conf->eal_vector.we_wordv);
    if (rv < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }

    /* create the mbuf pool */
    ss_pool =
        rte_mempool_create("mbuf_pool", NB_MBUF,
                   MBUF_SIZE, 32,
                   sizeof(struct rte_pktmbuf_pool_private),
                   rte_pktmbuf_pool_init, NULL,
                   rte_pktmbuf_init, NULL,
                   rte_socket_id(), 0);
    if (ss_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }
    
    if (rte_eal_pci_probe() < 0) {
        rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");
    }
    
    ss_conf->port_count = rte_eth_dev_count();
    printf("port_count %d\n", ss_conf->port_count);
    if (ss_conf->port_count == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
    }

    if (ss_conf->port_count > RTE_MAX_ETHPORTS) {
        ss_conf->port_count = RTE_MAX_ETHPORTS;
    }

    last_port = 0;

    /*
     * Each logical core is assigned a dedicated TX queue on each port.
     */
    rx_lcore_id = 0;
    queue_conf = NULL;
    for (port_id = 0; port_id < ss_conf->port_count; port_id++) {
        rte_eth_dev_info_get(port_id, &dev_info);
        
        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               lcore_queue_conf[rx_lcore_id].rx_port_count ==
               ss_conf->queue_count) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE) {
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
            }
        }

        if (queue_conf != &lcore_queue_conf[rx_lcore_id]) {
            /* Assigned a new logical core in the loop above. */
            queue_conf = &lcore_queue_conf[rx_lcore_id];
        }

        queue_conf->rx_port_list[queue_conf->rx_port_count] = port_id;
        queue_conf->rx_port_count++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) port_id);
        
        /* init port */
        printf("Initializing port %u... ", (unsigned) port_id);
        fflush(stdout);
        rv = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        rte_eth_macaddr_get(port_id, &port_eth_addrs[port_id]);

        /* init one RX queue */
        fflush(stdout);
        rv = rte_eth_rx_queue_setup(port_id, 0, rxd_count,
                         rte_eth_dev_socket_id(port_id), &rx_conf,
                         ss_pool);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        /* init one TX queue on each port */
        fflush(stdout);
        rv = rte_eth_tx_queue_setup(port_id, 0, txd_count, rte_eth_dev_socket_id(port_id), &tx_conf);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        /* Start device */
        rv = rte_eth_dev_start(port_id);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        printf("done: \n");

        rte_eth_promiscuous_enable(port_id);

        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                (unsigned) port_id,
                port_eth_addrs[port_id].addr_bytes[0],
                port_eth_addrs[port_id].addr_bytes[1],
                port_eth_addrs[port_id].addr_bytes[2],
                port_eth_addrs[port_id].addr_bytes[3],
                port_eth_addrs[port_id].addr_bytes[4],
                port_eth_addrs[port_id].addr_bytes[5]);

        /* initialize port stats */
        memset(&port_statistics, 0, sizeof(port_statistics));
    }

    //ss_port_link_status_check_all(ss_conf->port_count);

    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(ss_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    return 0;
}
