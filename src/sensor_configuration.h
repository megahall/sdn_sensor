#ifndef __SENSOR_CONFIGURATION_H__
#define __SENSOR_CONFIGURATION_H__

#include <json-c/json.h>

#include "common.h"

typedef enum json_type json_type_t;
typedef enum json_tokener_error json_error_t;
typedef struct array_list array_list_t;

struct ss_conf_s {
    // options
    int promiscuous_mode;
    
    ss_re_chain_t re_chain;
    ss_pcap_chain_t pcap_chain;
    ss_cidr_table_t cidr_table;
    ss_string_trie_t string_trie;
};

typedef struct ss_conf_s ss_conf_t;

/* BEGIN PROTOTYPES */

int ss_conf_destroy(ss_conf_t* conf);
char* ss_conf_path_get(void);
char* ss_conf_file_read(void);
struct cidr* ss_parse_cidr(char* cidr);
struct sockaddr* ss_parse_ip(char* ip);
ss_conf_t* ss_conf_file_parse(void);

/* END PROTOTYPES */

#endif /* __SENSOR_CONFIGURATION_H__ */
