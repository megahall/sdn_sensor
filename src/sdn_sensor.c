#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wordexp.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pci.h>
#include <rte_prefetch.h>

#include <pcap/pcap.h>

#include "common.h"
#include "dpdk.h"
#include "ethernet.h"
#include "je_utils.h"
#include "re_utils.h"
#include "sdn_sensor.h"
#include "sensor_conf.h"
#include "tcp.h"

/* GLOBAL VARIABLES */

pcap_t*        ss_pcap = NULL;
ss_conf_t*     ss_conf = NULL;
rte_mempool_t* ss_pool[SOCKET_COUNT] = { NULL };

/* ethernet addresses of ports */
struct ether_addr port_eth_addrs[RTE_MAX_ETHPORTS];

static mbuf_table_entry_t mbuf_table[RTE_MAX_ETHPORTS][RTE_MAX_LCORE];

static unsigned int port_count = 0;

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode        = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = MBUF_SIZE,
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key    = NULL,
            .rss_hf     = 0,
        },
    },
    .txmode = {
        .mq_mode        = ETH_MQ_TX_NONE,
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
    .tx_rs_thresh = 1, /* Use PMD default values */
    .txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

static struct ss_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* TX burst of packets on a port */
int ss_send_burst(uint8_t port_id, unsigned int lcore_id) {
    unsigned int count;
    rte_mbuf_t** mbufs;
    unsigned int rv;
    
    count = mbuf_table[port_id][lcore_id].length;
    mbufs = (rte_mbuf_t**) mbuf_table[port_id][lcore_id].mbufs;

    rv = rte_eth_tx_burst(port_id, (uint16_t) lcore_id, mbufs, (uint16_t) count);
    port_statistics[port_id].tx += rv;
    if (unlikely(rv < count)) {
        port_statistics[port_id].dropped += (count - rv);
        do {
            rte_pktmbuf_free(mbufs[rv]);
        } while (++rv < count);
    }

    return 0;
}

/* Queue and prepare packets for TX in a burst */
int ss_send_packet(rte_mbuf_t* mbuf, uint8_t port_id, unsigned int lcore_id) {
    mbuf_table_entry_t* mbuf_entry;
    unsigned int length;

    mbuf_entry = &mbuf_table[port_id][lcore_id];
    length     = mbuf_entry->length;
    mbuf_entry->mbufs[length] = mbuf;
    length++;

    /* enough pkts to be sent */
    if (unlikely(length == MAX_PKT_BURST)) {
        ss_send_burst(port_id, lcore_id);
        length = 0;
    }

    mbuf_entry->length = length;
    return 0;
}

static void ss_timer_callback(uint16_t lcore_id, uint64_t* timer_tsc) {
    uint8_t port_id;
    
    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        //RTE_LOG(INFO, SS, "attempt send for port %d\n", port_id);
        if (mbuf_table[port_id][lcore_id].length == 0) {
            //RTE_LOG(INFO, SS, "send no frames for port %d\n", port_id);
            continue;
        }
        //RTE_LOG(INFO, SS, "send %u frames for port %d\n", queue_conf->tx_table[port_id].length, port_id);
        ss_send_burst((uint8_t) port_id, lcore_id);
        mbuf_table[port_id][lcore_id].length = 0;
    }

    /* return if statistics timer is not ready yet */
    if (likely(*timer_tsc < ss_conf->timer_cycles)) return;
    
    /* return if not on master lcore */
    if (likely(lcore_id != rte_get_master_lcore())) return;

    double elapsed = *timer_tsc / (double) rte_get_tsc_hz();
    RTE_LOG(NOTICE, SS, "call ss_port_stats_print after %011.6f secs.\n", elapsed);
    ss_port_stats_print(port_statistics, rte_eth_dev_count());
    
    ss_tcp_timer_callback();
    
    *timer_tsc = 0;
}

/* main processing loop */
void ss_main_loop(void) __attribute__ ((noreturn)) {
    rte_mbuf_t* mbufs[MAX_PKT_BURST];
    rte_mbuf_t* mbuf;
    uint16_t lcore_id, socket_id;
    uint64_t prev_tsc, diff_tsc, curr_tsc, timer_tsc;
    unsigned int rx_count;
    uint8_t i, port_id;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
    timer_tsc = 0;

    lcore_id   = (uint16_t) rte_lcore_id();
    socket_id  = (uint16_t) rte_socket_id();

    RTE_LOG(INFO, SS, "entering main loop on lcore %u\n", lcore_id);

    while (1) {
        curr_tsc = rte_rdtsc();

        /* TX queue drain */
        diff_tsc = curr_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                //RTE_LOG(INFO, SS, "attempt send for port %d\n", port_id);
                if (mbuf_table[port_id][lcore_id].length == 0) {
                    //RTE_LOG(INFO, SS, "send no frames for port %d\n", port_id);
                    continue;
                }
                //RTE_LOG(INFO, SS, "send %u frames for port %d\n", queue_conf->tx_table[port_id].length, port_id);
                ss_send_burst((uint8_t) port_id, lcore_id);
                mbuf_table[port_id][lcore_id].length = 0;
            }

            /* advance the timer */
            timer_tsc += diff_tsc;

            /* if timer has reached its timeout */
            if (unlikely(timer_tsc >= (uint64_t) ss_conf->timer_cycles)) {
                /* do this only on master core */
                if (lcore_id == rte_get_master_lcore()) {
                    double elapsed = timer_tsc / (double) rte_get_tsc_hz();
                    RTE_LOG(NOTICE, SS, "call ss_port_stats_print after %011.6f secs.\n", elapsed);
                    ss_port_stats_print(port_statistics, rte_eth_dev_count());
                    /* reset the timer */
                    timer_tsc = 0;
                }
            }

            ss_timer_callback(lcore_id, &timer_tsc);
            prev_tsc = curr_tsc;
        }

        /* RX queue processing */
        for (port_id = 0; port_id < rte_eth_dev_count(); port_id++) {
            rx_count = rte_eth_rx_burst((uint8_t) port_id, lcore_id, mbufs, MAX_PKT_BURST);
            if (rx_count == 0) {
                continue;
            }
            
            port_statistics[port_id].rx += rx_count;
            
            for (i = 0; i < rx_count; i++) {
                mbuf = mbufs[i];
                rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));
                ss_frame_handle(mbuf, lcore_id, port_id);
            }
        }
    }
}

int ss_launch_one_lcore(__attribute__((unused)) void *dummy) __attribute__ ((noreturn)) {
    ss_main_loop();
    //return 0;
}

void fatal_signal_handler(int signal) {
    fprintf(stderr, "received fatal signal %d...\n", signal);
    for (uint8_t port = 0; port < port_count; ++port) {
        fprintf(stderr, "closing dpdk port_id %d...\n", port);
        rte_eth_dev_close(port);
        fprintf(stderr, "closed dpdk port_id %d.\n", port);
    }
    ss_conf_destroy();
    kill(getpid(), signal);
}

void signal_handler_init(const char* signal_name, int signal) {
    int rv;
    struct sigaction sa;
    
    memset(&sa, 0, sizeof(sa));
    
    sa.sa_handler = &fatal_signal_handler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags   = SA_RESTART | ~SA_SIGINFO;
    
    rv = sigaction(SIGINT, &sa, NULL);
    if (rv) {
        fprintf(stderr, "warning: could not install %s handler: rv %d: %s\n",
            signal_name, rv, strerror(errno));
    }
}

int main(int argc, char* argv[]) {
    struct rte_eth_dev_info dev_info;
    int rv;
    int c;
    uint8_t port_id, last_port;
    uint16_t lcore_count, lcore_id;
    char* conf_path = NULL;
    char pool_name[32];
    
    fprintf(stderr, "launching sdn_sensor version %s\n", SS_VERSION);
    
    opterr = 0;
    while ((c = getopt(argc, argv, "c:")) != -1) {
        switch (c) {
            case 'c': {
                rv = access(optarg, R_OK);
                if (rv != 0) {
                    fprintf(stderr, "could not read conf file: %s: %s\n", optarg, strerror(errno));
                    exit(1);
                }
                conf_path = je_strdup(optarg);
                break;
            }
            case '?': {
                break;
            }
            default: {
                break;
            }
        }
    }
    
    // NOTE: optind must be reset, since it contains hidden state,
    // otherwise rte_eal_init will fail extremely mysteriously
    optind = 1;
    
    rv = ss_re_init();
    if (rv) {
        fprintf(stderr, "could not initialize libpcre\n");
        exit(1);
    }
    
    ss_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    if (ss_pcap == NULL) {
        fprintf(stderr, "could not prepare pcap_t\n");
        exit(1);
    }
    
    ss_conf = ss_conf_file_parse(conf_path);
    if (ss_conf == NULL) {
        fprintf(stderr, "could not parse sdn_sensor configuration\n");
        exit(1);
    }
    
    /* copy over any ss_conf settings used in DPDK */
    if (ss_conf->rss_enabled) {
        port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;
    }
    else {
        port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    }

    /* init EAL */
    rv = rte_eal_init((int) ss_conf->eal_vector.we_wordc, ss_conf->eal_vector.we_wordv);
    if (rv < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }
    rte_set_log_level(ss_conf->log_level);
    
    /* create the mbuf pool */
    for (int i = 0; i < SOCKET_COUNT; ++i) {
        snprintf(pool_name, sizeof(pool_name), "mbuf_pool_socket_%02d", i);
        RTE_LOG(WARNING, SS, "create mbuf_pool %s\n", pool_name);
        ss_pool[i] =
            rte_mempool_create(pool_name, MBUF_COUNT,
                       MBUF_SIZE, 32,
                       sizeof(struct rte_pktmbuf_pool_private),
                       rte_pktmbuf_pool_init, NULL,
                       rte_pktmbuf_init, NULL,
                       (int) rte_socket_id(), 0);
        if (ss_pool[i] == NULL) {
            rte_exit(EXIT_FAILURE, "could not create mbuf_pool %s\n", pool_name);
        }
    }

    rv = ss_tcp_init();
    if (rv) {
        rte_exit(EXIT_FAILURE, "could not initialize tcp protocol\n");
    }
    
    if (rte_eal_pci_probe() < 0) {
        rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");
    }
    
    lcore_count = (uint16_t) rte_lcore_count();
    port_count = rte_eth_dev_count();
    RTE_LOG(NOTICE, SS, "port_count %d\n", port_count);
    if (port_count == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
    }

    if (port_count > RTE_MAX_ETHPORTS) {
        port_count = RTE_MAX_ETHPORTS;
    }
    
    signal_handler_init("SIGHUP",  SIGHUP);
    signal_handler_init("SIGINT",  SIGINT);
    signal_handler_init("SIGQUIT", SIGQUIT);
    signal_handler_init("SIGILL",  SIGILL);
    signal_handler_init("SIGABRT", SIGABRT);
    signal_handler_init("SIGSEGV", SIGSEGV);
    signal_handler_init("SIGPIPE", SIGPIPE);
    signal_handler_init("SIGTERM", SIGTERM);
    signal_handler_init("SIGBUS",  SIGBUS);

    last_port = 0;
    
    /* XXX: simple hard-coded lcore mapping */
    /* each lcore has 1 RX and 1 TX queue on each port */
    for (port_id = 0; port_id < port_count; port_id++) {
        rte_eth_dev_info_get(port_id, &dev_info);
        
        /* Configure port */
        RTE_LOG(INFO, SS, "Initializing port %u... ", (unsigned) port_id);
        fflush(stderr);
        rv = rte_eth_dev_configure(port_id, lcore_count, lcore_count, &port_conf);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", rv, (unsigned) port_id);
        }
        
        for (lcore_id = 0; lcore_id < lcore_count; ++lcore_id) {
            int eth_socket_id = rte_eth_dev_socket_id(port_id);
            // XXX: work around non-NUMA socket ID bug
            if (eth_socket_id == -1) eth_socket_id = 0;
            u_int u_eth_socket_id = (u_int) eth_socket_id;
            
            /* init one RX queue */
            fflush(stderr);
            rv = rte_eth_rx_queue_setup(
                port_id, lcore_id /*queue_id*/, ss_conf->rxd_count,
                u_eth_socket_id, &rx_conf,
                ss_pool[u_eth_socket_id]);
            if (rv < 0) {
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: error: port: %u lcore: %d error: %d\n", port_id, lcore_id, rv);
            }
            
            /* init one TX queue */
            fflush(stderr);
            rv = rte_eth_tx_queue_setup(
                port_id, lcore_id /*queue_id*/, ss_conf->txd_count,
                u_eth_socket_id, &tx_conf);
            if (rv < 0) {
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: error: port: %u lcore: %d error: %d\n", port_id, lcore_id, rv);
            }
        }
        
        /* Cache MAC address */
        rte_eth_macaddr_get(port_id, &port_eth_addrs[port_id]);
        
        /* Start port */
        rv = rte_eth_dev_start(port_id);
        if (rv < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", rv, (unsigned) port_id);
        }
        
        RTE_LOG(INFO, SS, "done: \n");
        
        rte_eth_promiscuous_enable(port_id);
        
        RTE_LOG(INFO, SS, "Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
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
