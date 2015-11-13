#pragma once

#include "sflow.h"

/* BEGIN PROTOTYPES */

int sflow_init(void);
int sflow_timer_callback(void);
int sflow_frame_handle(ss_frame_t* rx_buf);
int sflow_socket_init(sflow_key_t* key, sflow_socket_t* socket);
sflow_socket_t* sflow_socket_create(sflow_key_t* key, ss_frame_t* rx_buf);
int sflow_socket_delete(sflow_key_t* key, _Bool is_locked);
sflow_socket_t* sflow_socket_lookup(sflow_key_t* key);
int sflow_prepare_rx(ss_frame_t* rx_buf, sflow_socket_t* socket);
void sflow_sample_callback(sflow_sample_t* sample, uint32_t s_index, uint32_t e_index);
void sflow_flow_sample_callback(sflow_sample_t* sample, sflow_sampled_header_t* header, uint32_t s_index, uint32_t e_index);
void sflow_counter_sample_callback(sflow_sample_t* sample, sflow_if_counters_t* if_counters, uint32_t s_index, uint32_t e_index);
void sflow_log(sflow_sample_t* sample, char* fmt, ...);
void sflow_log_clf(sflow_sample_t* sample, char* auth_user, char* uri, uint32_t protocol, char* referrer, char* user_agent, uint32_t method, uint32_t status, uint64_t resp_bytes);

/* END PROTOTYPES */
