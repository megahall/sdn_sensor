#ifndef __EXTRACTOR_H__
#define __EXTRACTOR_H__

#include "common.h"
#include "pcre_utils.h"

#include "dns.h"

/* BEGIN PROTOTYPES */

int ss_extract_eth(ss_frame_t* fbuf);
int ss_extract_dns(ss_frame_t* fbuf);
int ss_extract_dns_atype(ss_answer_t* result, dns_answer_t* aptr);
int ss_extract_syslog(ss_frame_t* fbuf);
int ss_extract_syslog_complete(ss_frame_t* fbuf, ss_re_entry_t* rptr);
int ss_extract_syslog_substring(ss_frame_t* fbuf, ss_re_entry_t* rptr);

/* END PROTOTYPES */

#endif /* __EXTRACTOR_H__ */
