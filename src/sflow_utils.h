#ifndef __SFLOW_UTILS_H__
#define __SFLOW_UTILS_H__

#include <stddef.h>
#include <stdint.h>

#include "sflow.h"
#include "ip_utils.h"

/* BEGIN PROTOTYPES */

char sflow_nybble_to_hex(char x);
char* sflow_print_uuid(uint8_t* u);
char* sflow_url_encode(char* in, char* out, size_t out_len);
char* sflow_mac_string(uint8_t* m);
char* sflow_ip_string(sflow_ip_t* ip, char* i, size_t i_len);
uint32_t sflow_get_data_32_nobswap(sflow_sample_t* sample);
uint32_t sflow_get_data_32(sflow_sample_t* sample);
float sflow_get_float(sflow_sample_t* sample);
uint64_t sflow_get_data_64(sflow_sample_t* sample);
void sflow_skip_bytes(sflow_sample_t* sample, size_t bytes);
uint32_t sflow_log_next_32(sflow_sample_t* sample, char* field_name);
uint64_t sflow_log_next_64(sflow_sample_t* sample, char* field_name);
double sflow_log_next_percentage(sflow_sample_t* sample, char* field_name);
float sflow_log_next_float(sflow_sample_t* sample, char* field_name);
void sflow_log_next_mac(sflow_sample_t* sample, char* field_name);
uint32_t sflow_parse_string(sflow_sample_t* sample, char* buf, uint32_t buf_len);
uint32_t sflow_parse_ip(sflow_sample_t* sample, sflow_ip_t* ip);
char* sflow_tag_dump(uint32_t tag);
char* sflow_sample_type_dump(uint32_t sample_type);
char* sflow_ds_type_dump(uint32_t ds_type);
char* sflow_port_id_dump(uint32_t format, uint32_t port);
char* sflow_sample_format_dump(uint32_t sample_type, uint32_t sample_format);
char* sflow_flow_format_dump(uint32_t sample_format);
char* sflow_header_protocol_dump(uint32_t header_protocol);
char* sflow_counters_format_dump(uint32_t sample_format);
char* sflow_counters_direction_dump(uint32_t ifDirection);
char* sflow_counters_status_dump(uint32_t ifStatus);
void sflow_skip_tlv(sflow_sample_t* sample, uint32_t tag, uint32_t len, char* description);
int is_ip4_mapped_ip(ip6_addr_t* ip6, ip4_addr_t* ip4);

/* END PROTOTYPES */

#endif /* __SFLOW_UTILS_H__ */
