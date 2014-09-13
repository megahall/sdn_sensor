#ifndef __EXTRACTOR_H__
#define __EXTRACTOR_H__

#include "common.h"

/* BEGIN PROTOTYPES */

int ss_extract_eth(ss_frame_t* fbuf);
int ss_extract_dns(ss_frame_t* fbuf);

/* END PROTOTYPES */

#endif /* __EXTRACTOR_H__ */
