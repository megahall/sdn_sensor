#ifndef __L4_UTILS_H__
#define __L4_UTILS_H__


/* BEGIN PROTOTYPES */

int ss_buffer_dump(const char* source, uint8_t* buffer, uint16_t length);
int ss_frame_layer_off_len_get(ss_frame_t* rx_buf, void* layer_start, size_t layer_hdr_size, uint8_t* *layer_offset, uint16_t* layer_length);
uint8_t* ss_phdr_append(rte_mbuf_t* pmbuf, void* data, uint16_t length);
int ss_frame_prepare_ip4(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
int ss_frame_prepare_ip6(ss_frame_t* rx_buf, ss_frame_t* tx_buf);
void ss_frame_destroy(ss_frame_t* fbuf);

/* END PROTOTYPES */

#endif /* __L4_UTILS_H__ */
