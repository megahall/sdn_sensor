#ifndef __DPDK_H__
#define __DPDK_H__

/* BEGIN PROTOTYPES */

void ss_port_stats_print(struct ss_port_statistics* port_statistics, unsigned int port_count, uint32_t enabled_port_mask);
int ss_parse_portmask(const char* portmask);
unsigned int ss_parse_nqueue(const char* q_arg);
int ss_parse_timer_period(const char* q_arg);
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

/* END PROTOTYPES */

#endif /* __DPDK_H__ */
