#ifndef __EXTRACTOR_H__
#define __EXTRACTOR_H__


/* BEGIN PROTOTYPES */

int ss_extract_eth(ss_frame_t* fbuf);
int ss_extract_arp(ss_frame_t* fbuf);
int ss_extract_ndp(ss_frame_t* fbuf);
int ss_extract_ip4(ss_frame_t* fbuf);
int ss_extract_ip6(ss_frame_t* fbuf);
int ss_extract_icmp4(ss_frame_t* fbuf);
int ss_extract_icmp6(ss_frame_t* fbuf);
int ss_extract_echo4(ss_frame_t* fbuf);
int ss_extract_echo6(ss_frame_t* fbuf);
int ss_extract_tcp4(ss_frame_t* fbuf);
int ss_extract_tcp6(ss_frame_t* fbuf);
int ss_extract_udp4(ss_frame_t* fbuf);
int ss_extract_udp6(ss_frame_t* fbuf);

/* END PROTOTYPES */

#endif /* __EXTRACTOR_H__ */
