#ifndef __RE_CHAIN_H__
#define __RE_CHAIN_H__

#include <bsd/sys/queue.h>
#include <pcre.h>
#include <uthash.h>

struct {
    pcre* re;
} ss_re_entry_s;

typedef struct ss_re_entry_s ss_re_entry_t;

TAILQ_HEAD(ss_re_list_s, ss_re_entry_s);
typedef struct ss_re_list_s ss_re_list_t;

struct {
    ss_re_list_t re_list;
} ss_re_chain_s;

typedef struct ss_re_chain_s ss_re_chain_t;

#endif /* __RE_CHAIN_H__ */
