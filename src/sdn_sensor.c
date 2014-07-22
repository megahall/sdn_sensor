#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/queue.h>

#include <log4c.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "common.h"
#include "sdn_sensor.h"
#include "dpdk.h"
#include "sensor_configuration.h"

static uint16_t rxd_count = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t txd_count = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr port_eth_addrs[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t ss_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t ss_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int ss_rx_queue_per_lcore = 1;

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

struct rte_mempool* ss_pktmbuf_pool = NULL;

struct ss_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
/* default period is 10 seconds */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000;

/* Send the burst of packets on an output interface */
int ss_send_burst(struct lcore_queue_conf *qconf, unsigned int n, uint8_t port) {
    struct rte_mbuf** mbufs;
    unsigned int rv;
    unsigned int queueid =0;

    mbufs = (struct rte_mbuf**) qconf->tx_table[port].mbufs;

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
int ss_send_packet(struct rte_mbuf *m, uint8_t port) {
    unsigned int lcore_id;
    unsigned int length;
    struct lcore_queue_conf *qconf;

    lcore_id = rte_lcore_id();

    qconf = &lcore_queue_conf[lcore_id];
    length = qconf->tx_table[port].length;
    qconf->tx_table[port].mbufs[length] = m;
    length++;

    /* enough pkts to be sent */
    if (unlikely(length == MAX_PKT_BURST)) {
        ss_send_burst(qconf, MAX_PKT_BURST, port);
        length = 0;
    }

    qconf->tx_table[port].length = length;
    return 0;
}

void ss_process_frame(struct rte_mbuf* mbuf, unsigned int port_id) {
    ss_frame_t fbuf;
    void* tmp;
    fbuf.ethernet = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    
    switch (fbuf.ethernet->ether_type) {
        case ETHER_TYPE_VLAN: {
            RTE_LOG(INFO, SS, "port %u received unsupported VLAN frame\n", port_id);
            rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
            break;
        }
        case ETHER_TYPE_ARP:  {
            ss_process_frame_arp(&fbuf);
            break;
        }
        case ETHER_TYPE_IPV4: {
            break;
        }
        case ETHER_TYPE_IPV6: {
            break;
        }
        default: {
            RTE_LOG(INFO, SS, "port %u received unsupported 0x%04hx frame\n", port_id, fbuf.ethernet->ether_type);
            rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
            break;
        }
    }
    //d_addr, s_addr, ether_type;

    /* 02:00:00:00:00:xx */
    tmp = &fbuf.ethernet->d_addr.addr_bytes[0];
    *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)port_id << 40);

    /* src addr */
    ether_addr_copy(&port_eth_addrs[port_id], &fbuf.ethernet->s_addr);

    rte_pktmbuf_free(mbuf);
    // ss_send_packet(mbuf, (uint8_t) port_id);
}

// XXX: eventually allow VLAN to be recursive
void ss_process_frame_ethernet(ss_frame_t* fbuf) {
}

void ss_process_frame_arp(ss_frame_t* fbuf) {
}

void ss_process_frame_icmpv4() {
}

void ss_process_frame_icmpv6() {
}

/* main processing loop */
void ss_main_loop(void) {
    struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf* m;
    unsigned int lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned i, j, port_id, rx_count;
    struct lcore_queue_conf* qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lcore_queue_conf[lcore_id];

    if (qconf->rx_port_count == 0) {
        RTE_LOG(INFO, SS, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, SS, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->rx_port_count; i++) {
        port_id = qconf->rx_port_list[i];
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
                if (qconf->tx_table[port_id].length == 0)
                    continue;
                ss_send_burst(&lcore_queue_conf[lcore_id], qconf->tx_table[port_id].length, (uint8_t) port_id);
                qconf->tx_table[port_id].length = 0;
            }

            /* if timer is enabled */
            if (timer_period > 0) {
                /* advance the timer */
                timer_tsc += diff_tsc;

                /* if timer has reached its timeout */
                if (unlikely(timer_tsc >= (uint64_t) timer_period)) {

                    /* do this only on master core */
                    if (lcore_id == rte_get_master_lcore()) {
                        ss_port_stats_print(port_statistics, RTE_MAX_ETHPORTS, ss_enabled_port_mask);
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
        for (i = 0; i < qconf->rx_port_count; i++) {
            port_id = qconf->rx_port_list[i];
            rx_count = rte_eth_rx_burst((uint8_t) port_id, 0, pkts_burst, MAX_PKT_BURST);
            
            port_statistics[port_id].rx += rx_count;
            
            for (j = 0; j < rx_count; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                ss_process_frame(m, port_id);
            }
        }
    }
}

int ss_launch_one_lcore(__attribute__((unused)) void *dummy) {
    ss_main_loop();
    return 0;
}

int main(int argc, char* argv[]) {
    ss_conf_t* ss_conf = ss_conf_file_parse();
    
    struct lcore_queue_conf* qconf;
    struct rte_eth_dev_info dev_info;
    int rv;
    uint8_t nb_ports;
    uint8_t nb_ports_available;
    uint8_t port_id, last_port;
    unsigned int lcore_id;
    unsigned int rx_lcore_id;
    unsigned int nb_ports_in_mask = 0;

    /* init EAL */
    rv = rte_eal_init(argc, argv);
    if (rv < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }
    argc -= rv;
    argv += rv;

    /* parse application arguments (after the EAL ones) */
    ss_enabled_port_mask = ss_parse_portmask(ss_conf->port_mask);
    if (ss_enabled_port_mask == 0) {
        printf("invalid portmask\n");
        return -1;
    }

    ss_rx_queue_per_lcore = ss_parse_nqueue(ss_conf->queue_count);
    if (ss_rx_queue_per_lcore == 0) {
        printf("invalid queue number\n");
        return -1;
    }

    timer_period = ss_parse_timer_period(ss_conf->timer_msec) * 1000 * TIMER_MILLISECOND;
    if (timer_period < 0) {
        printf("invalid timer period\n");
        return -1;
    }
    
    /* create the mbuf pool */
    ss_pktmbuf_pool =
        rte_mempool_create("mbuf_pool", NB_MBUF,
                   MBUF_SIZE, 32,
                   sizeof(struct rte_pktmbuf_pool_private),
                   rte_pktmbuf_pool_init, NULL,
                   rte_pktmbuf_init, NULL,
                   rte_socket_id(), 0);
    if (ss_pktmbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }

    if (rte_eal_pci_probe() < 0) {
        rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");
    }

    nb_ports = rte_eth_dev_count();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
    }

    if (nb_ports > RTE_MAX_ETHPORTS) {
        nb_ports = RTE_MAX_ETHPORTS;
    }

    /* reset ss_dst_ports */
    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        ss_dst_ports[port_id] = 0;
    }
    
    last_port = 0;

    /*
     * Each logical core is assigned a dedicated TX queue on each port.
     */
    for (port_id = 0; port_id < nb_ports; port_id++) {
        /* skip ports that are not enabled */
        if ((ss_enabled_port_mask & (1 << port_id)) == 0)
            continue;

        if (nb_ports_in_mask % 2) {
            ss_dst_ports[port_id] = last_port;
            ss_dst_ports[last_port] = port_id;
        }
        else
            last_port = port_id;

        nb_ports_in_mask++;

        rte_eth_dev_info_get(port_id, &dev_info);
    }
    if (nb_ports_in_mask % 2) {
        printf("Notice: odd number of ports in portmask.\n");
        ss_dst_ports[last_port] = last_port;
    }

    rx_lcore_id = 0;
    qconf = NULL;

    /* Initialize the port/queue configuration of each logical core */
    for (port_id = 0; port_id < nb_ports; port_id++) {
        /* skip ports that are not enabled */
        if ((ss_enabled_port_mask & (1 << port_id)) == 0)
            continue;

        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               lcore_queue_conf[rx_lcore_id].rx_port_count ==
               ss_rx_queue_per_lcore) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE) {
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
            }
        }

        if (qconf != &lcore_queue_conf[rx_lcore_id]) {
            /* Assigned a new logical core in the loop above. */
            qconf = &lcore_queue_conf[rx_lcore_id];
        }

        qconf->rx_port_list[qconf->rx_port_count] = port_id;
        qconf->rx_port_count++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) port_id);
    }

    nb_ports_available = nb_ports;

    /* Initialise each port */
    for (port_id = 0; port_id < nb_ports; port_id++) {
        /* skip ports that are not enabled */
        if ((ss_enabled_port_mask & (1 << port_id)) == 0) {
            printf("Skipping disabled port %u\n", (unsigned) port_id);
            nb_ports_available--;
            continue;
        }
        /* init port */
        printf("Initializing port %u... ", (unsigned) port_id);
        fflush(stdout);
        rv = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", rv, (unsigned) port_id);
        }

        rte_eth_macaddr_get(port_id,&port_eth_addrs[port_id]);

        /* init one RX queue */
        fflush(stdout);
        rv = rte_eth_rx_queue_setup(port_id, 0, rxd_count,
                         rte_eth_dev_socket_id(port_id), &rx_conf,
                         ss_pktmbuf_pool);
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
                (unsigned) portid,
                ss_ports_eth_addr[portid].addr_bytes[0],
                ss_ports_eth_addr[portid].addr_bytes[1],
                ss_ports_eth_addr[portid].addr_bytes[2],
                ss_ports_eth_addr[portid].addr_bytes[3],
                ss_ports_eth_addr[portid].addr_bytes[4],
                ss_ports_eth_addr[portid].addr_bytes[5]);

        /* initialize port stats */
        memset(&port_statistics, 0, sizeof(port_statistics));
    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
            "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(nb_ports, ss_enabled_port_mask);

    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(ss_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    return 0;
}
