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

#include <netinet/in.h>
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

#include "sdn_sensor.h"
#include "dpdk.h"
#include "sensor_configuration.h"

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr ss_ports_eth_addr[RTE_MAX_ETHPORTS];

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
    struct rte_mbuf **m_table;
    unsigned int ret;
    unsigned int queueid =0;

    m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

    ret = rte_eth_tx_burst(port, (uint16_t) queueid, m_table, (uint16_t) n);
    port_statistics[port].tx += ret;
    if (unlikely(ret < n)) {
        port_statistics[port].dropped += (n - ret);
        do {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < n);
    }

    return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
int ss_send_packet(struct rte_mbuf *m, uint8_t port) {
    unsigned int lcore_id;
    unsigned int len;
    struct lcore_queue_conf *qconf;

    lcore_id = rte_lcore_id();

    qconf = &lcore_queue_conf[lcore_id];
    len = qconf->tx_mbufs[port].len;
    qconf->tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        ss_send_burst(qconf, MAX_PKT_BURST, port);
        len = 0;
    }

    qconf->tx_mbufs[port].len = len;
    return 0;
}

void ss_simple_forward(struct rte_mbuf *m, unsigned int portid) {
    struct ether_hdr *eth;
    void *tmp;
    unsigned int dst_port;

    dst_port = ss_dst_ports[portid];
    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    /* 02:00:00:00:00:xx */
    tmp = &eth->d_addr.addr_bytes[0];
    *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dst_port << 40);

    /* src addr */
    ether_addr_copy(&ss_ports_eth_addr[dst_port], &eth->s_addr);

    ss_send_packet(m, (uint8_t) dst_port);
}

/* main processing loop */
void ss_main_loop(void) {
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    unsigned int lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned i, j, portid, nb_rx;
    struct lcore_queue_conf *qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lcore_queue_conf[lcore_id];

    if (qconf->n_rx_port == 0) {
        RTE_LOG(INFO, SS, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, SS, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_port; i++) {
        portid = qconf->rx_port_list[i];
        RTE_LOG(INFO, SS, " -- lcoreid=%u portid=%u\n", lcore_id,
            portid);
    }

    while (1) {

        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {

            for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
                if (qconf->tx_mbufs[portid].len == 0)
                    continue;
                ss_send_burst(&lcore_queue_conf[lcore_id],
                         qconf->tx_mbufs[portid].len,
                         (uint8_t) portid);
                qconf->tx_mbufs[portid].len = 0;
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
        for (i = 0; i < qconf->n_rx_port; i++) {

            portid = qconf->rx_port_list[i];
            nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
                         pkts_burst, MAX_PKT_BURST);

            port_statistics[portid].rx += nb_rx;

            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                ss_simple_forward(m, portid);
            }
        }
    }
}

int ss_launch_one_lcore(__attribute__((unused)) void *dummy) {
    ss_main_loop();
    return 0;
}

/* display usage */
void ss_usage(const char *prgname) {
    printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
           "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
           "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n",
           prgname);
}

int main(int argc, char* argv[]) {
    ss_conf_t* ss_conf = ss_conf_file_parse();
    
    struct lcore_queue_conf *qconf;
    struct rte_eth_dev_info dev_info;
    int ret;
    uint8_t nb_ports;
    uint8_t nb_ports_available;
    uint8_t portid, last_port;
    unsigned int lcore_id;
    unsigned int rx_lcore_id;
    unsigned int nb_ports_in_mask = 0;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

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
    if (ss_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    if (rte_eal_pci_probe() < 0)
        rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");

    nb_ports = rte_eth_dev_count();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    if (nb_ports > RTE_MAX_ETHPORTS)
        nb_ports = RTE_MAX_ETHPORTS;

    /* reset ss_dst_ports */
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
        ss_dst_ports[portid] = 0;
    last_port = 0;

    /*
     * Each logical core is assigned a dedicated TX queue on each port.
     */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((ss_enabled_port_mask & (1 << portid)) == 0)
            continue;

        if (nb_ports_in_mask % 2) {
            ss_dst_ports[portid] = last_port;
            ss_dst_ports[last_port] = portid;
        }
        else
            last_port = portid;

        nb_ports_in_mask++;

        rte_eth_dev_info_get(portid, &dev_info);
    }
    if (nb_ports_in_mask % 2) {
        printf("Notice: odd number of ports in portmask.\n");
        ss_dst_ports[last_port] = last_port;
    }

    rx_lcore_id = 0;
    qconf = NULL;

    /* Initialize the port/queue configuration of each logical core */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((ss_enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               lcore_queue_conf[rx_lcore_id].n_rx_port ==
               ss_rx_queue_per_lcore) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE)
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
        }

        if (qconf != &lcore_queue_conf[rx_lcore_id])
            /* Assigned a new logical core in the loop above. */
            qconf = &lcore_queue_conf[rx_lcore_id];

        qconf->rx_port_list[qconf->n_rx_port] = portid;
        qconf->n_rx_port++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
    }

    nb_ports_available = nb_ports;

    /* Initialise each port */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((ss_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", (unsigned) portid);
            nb_ports_available--;
            continue;
        }
        /* init port */
        printf("Initializing port %u... ", (unsigned) portid);
        fflush(stdout);
        ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                  ret, (unsigned) portid);

        rte_eth_macaddr_get(portid,&ss_ports_eth_addr[portid]);

        /* init one RX queue */
        fflush(stdout);
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                         rte_eth_dev_socket_id(portid), &rx_conf,
                         ss_pktmbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                  ret, (unsigned) portid);

        /* init one TX queue on each port */
        fflush(stdout);
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                rte_eth_dev_socket_id(portid), &tx_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                ret, (unsigned) portid);

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                  ret, (unsigned) portid);

        printf("done: \n");

        rte_eth_promiscuous_enable(portid);

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
