#ifndef __DPDK_H__
#define __DPDK_H__

#include <stdint.h>

/* BEGIN PROTOTYPES */

void ss_port_stats_print(struct ss_port_statistics* port_statistics, unsigned int port_limit);
void ss_port_link_status_check_all(uint8_t port_limit);

/* END PROTOTYPES */

#endif /* __DPDK_H__ */
