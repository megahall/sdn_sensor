#ifndef __IP_H__
#define __IP_H__

#include "common.h"

/* BEGIN PROTOTYPES */

int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_find_l4_header(ss_frame_t* rx_buf, uint8_t ip_protocol);

/* END PROTOTYPES */

#endif /* __IP_H__ */
