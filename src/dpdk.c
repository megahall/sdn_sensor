#include <inttypes.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_memory.h>

#include "sdn_sensor.h"
#include "dpdk.h"

/* Print out statistics on packets dropped */
void ss_port_stats_print(struct ss_port_statistics* port_statistics, unsigned int port_limit) {
    uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
    unsigned int port_id;

    total_packets_dropped = 0;
    total_packets_tx = 0;
    total_packets_rx = 0;

    //const char clr[] = { 27, '[', '2', 'J', '\0' };
    //const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

    /* Clear screen and move to top left */
    //printf("%s%s", clr, topLeft);

    printf("\nPort statistics ====================================");

    for (port_id = 0; port_id < port_limit; port_id++) {
        printf("\nStatistics for port %u ------------------------------"
               "\nPackets sent: %24"PRIu64
               "\nPackets received: %20"PRIu64
               "\nPackets dropped: %21"PRIu64,
               port_id,
               port_statistics[port_id].tx,
               port_statistics[port_id].rx,
               port_statistics[port_id].dropped);

        total_packets_dropped += port_statistics[port_id].dropped;
        total_packets_tx += port_statistics[port_id].tx;
        total_packets_rx += port_statistics[port_id].rx;
    }
    printf("\nAggregate statistics ==============================="
           "\nTotal packets sent: %18"PRIu64
           "\nTotal packets received: %14"PRIu64
           "\nTotal packets dropped: %15"PRIu64,
           total_packets_tx,
           total_packets_rx,
           total_packets_dropped);
    printf("\n====================================================\n");
}

/* Check the link status of all ports in up to 9s, and print them finally */
void ss_port_link_status_check_all(uint8_t port_limit) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t port_id, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (port_id = 0; port_id < port_limit; port_id++) {
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(port_id, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (uint8_t)port_id,
                        (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                        (uint8_t)port_id);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}
