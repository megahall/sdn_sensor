#ifndef __TCP_H__
#define __TCP_H__

#include "common.h"

/* BEGIN PROTOTYPES */

int ss_tcp_init(void);
int ss_flow_key_dump(const char* message, ss_flow_key_t* key);
const char* ss_tcp_flags_dump(uint8_t tcp_flags);
int ss_tcp_socket_init(ss_flow_key_t* key, ss_tcp_socket_t* socket);
ss_tcp_socket_t* ss_tcp_socket_create(ss_flow_key_t* key, ss_frame_t* rx_buf);
int ss_tcp_socket_delete(ss_flow_key_t* key);
ss_tcp_socket_t* ss_tcp_socket_lookup(ss_flow_key_t* key);
int ss_frame_handle_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_handle_close(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_handle_open(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_handle_update(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_prepare_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_prepare_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_prepare_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
uint8_t* ss_phdr_append(rte_mbuf_t* pmbuf, void* data, uint32_t length);
int ss_tcp_prepare_checksum(ss_frame_t* tx_buf);

/* END PROTOTYPES */

#endif /* __TCP_H__ */
