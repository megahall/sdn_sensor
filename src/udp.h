#ifndef __UDP_H__
#define __UDP_H__

#include "common.h"

/* BEGIN PROTOTYPES */

int ss_frame_handle_udp(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_udp_extract_syslog(ss_frame_t* fbuf);

/* END PROTOTYPES */

#endif /* __UDP_H__ */
