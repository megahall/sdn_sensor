#ifndef __IP_H__
#define __IP_H__

#include "common.h"
#include "sdn_sensor.h"

/* BEGIN PROTOTYPES */

int ss_frame_handle_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_handle_ip(ss_frame_t* rx_buf, ss_frame_t* tx_buf);

/* END PROTOTYPES */

#endif /* __IP_H__ */
