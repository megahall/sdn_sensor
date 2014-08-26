#ifndef __ICMP_H__
#define __ICMP_H__

#include "common.h"
#include "sdn_sensor.h"

/* BEGIN PROTOTYPES */

int ss_frame_prepare_icmp6(ss_frame_t* tx_buf, uint8_t* pl_ptr, uint32_t pl_len);
int ss_frame_handle_echo4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_echo6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_icmp4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_icmp6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);

/* END PROTOTYPES */

#endif /* __ICMP_H__ */
