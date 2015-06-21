#pragma once


#include "common.h"

/* BEGIN PROTOTYPES */

int ss_tcp_init(void);
int ss_tcp_timer_callback(void);
int ss_frame_handle_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_extract_syslog(ss_tcp_socket_t* socket, ss_frame_t* rx_buf);
int ss_tcp_socket_init(ss_flow_key_t* key, ss_tcp_socket_t* socket);
ss_tcp_socket_t* ss_tcp_socket_create(ss_flow_key_t* key, ss_frame_t* rx_buf);
int ss_tcp_socket_delete(ss_flow_key_t* key, int is_locked);
ss_tcp_socket_t* ss_tcp_socket_lookup(ss_flow_key_t* key);
int ss_tcp_prepare_rx(ss_frame_t* rx_buf, ss_tcp_socket_t* socket);
int ss_tcp_prepare_tx(ss_frame_t* tx_buf, ss_tcp_socket_t* socket, ss_tcp_state_t state);
uint16_t ss_tcp_rx_mss_get(ss_tcp_socket_t* socket);
int ss_tcp_handle_close(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_handle_open(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_handle_update(ss_tcp_socket_t* socket, ss_frame_t* rx_buf, ss_frame_t* tx_buf, uint32_t* curr_ack_seq_ptr);
int ss_frame_prepare_tcp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_tcp_prepare_checksum(ss_frame_t* tx_buf);

/* END PROTOTYPES */
