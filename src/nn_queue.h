#ifndef __NN_QUEUE_H__
#define __NN_QUEUE_H__

#include <stdint.h>

#include <bsd/sys/queue.h>
#include <json-c/json.h>
#include <pcap/pcap.h>
#include <pcre.h>

#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <rte_ether.h>
#include <rte_log.h>
#include <rte_lpm.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "common.h"

struct ss_frame_s;
typedef struct ss_frame_s ss_frame_t;

/* should be enough for the nanomsg queue URL */
#define NN_URL_MAX 256

enum nn_content_type_e {
    NN_OBJECT_PCAP    = 1,
    NN_OBJECT_SYSLOG  = 2,
    NN_OBJECT_SFLOW   = 3,
    NN_OBJECT_NETFLOW = 4,
    NN_OBJECT_MAX,
};

typedef enum nn_content_type_e nn_content_type_t;

enum nn_queue_format_e {
    NN_FORMAT_METADATA = 1,
    NN_FORMAT_PACKET   = 2,
    NN_FORMAT_MAX,
};

typedef enum nn_queue_format_e nn_queue_format_t;

struct nn_queue_s {
    int               conn;
    nn_queue_format_t format;
    nn_content_type_t content;
    int               type;
    char              url[NN_URL_MAX];
};

typedef struct nn_queue_s nn_queue_t;

/* BEGIN PROTOTYPES */

int ss_nn_queue_create(json_object* items, nn_queue_t* nn_queue);
int ss_nn_queue_destroy(nn_queue_t* nn_queue);
uint8_t* ss_nn_queue_prepare_pcap(nn_queue_t* nn_queue, ss_frame_t* fbuf);
int ss_nn_queue_send(nn_queue_t* nn_queue, uint8_t* message, uint16_t length);

/* END PROTOTYPES */

#endif /* __NN_QUEUE_H__ */
