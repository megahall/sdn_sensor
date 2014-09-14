#ifndef __EXTRACTOR_H__
#define __EXTRACTOR_H__

#include "common.h"

#include "dns.h"

/* BEGIN PROTOTYPES */

int ss_extract_eth(ss_frame_t* fbuf);
int ss_extract_dns(ss_frame_t* fbuf);
int ss_extract_dns_atype(ss_answer_t* result, dns_answer_t* aptr);

/* END PROTOTYPES */

#endif /* __EXTRACTOR_H__ */
