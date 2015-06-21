#pragma once

#include "common.h"
#include "re_utils.h"

#include "dns.h"

/* BEGIN PROTOTYPES */

int ss_extract_eth(ss_frame_t* fbuf);
int ss_extract_dns(ss_frame_t* fbuf);
int ss_extract_dns_atype(ss_answer_t* result, dns_answer_t* aptr);
int ss_extract_syslog(const char* source, ss_frame_t* fbuf, uint8_t* l4_offset, uint16_t l4_length);

/* END PROTOTYPES */
