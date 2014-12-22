#define _GNU_SOURCE /* strcasestr */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>

#include <jemalloc/jemalloc.h>

#include <json-c/json.h>
#include <json-c/json_object_private.h>

#include <rte_log.h>

#include "ioc.h"

#include "common.h"
#include "ip_utils.h"
#include "je_utils.h"
#include "json.h"
#include "netflow_addr.h"
#include "netflow_format.h"
#include "sdn_sensor.h"

#if defined(SS_IOC_BACKEND_RAM) && defined(SS_IOC_BACKEND_DISK)
#error "SS_IOC_BACKEND_RAM and SS_IOC_BACKEND_DISK are mutually exclusive"
#endif

#define SS_IOC_LINE_DELIMITER   '\n'
#define SS_IOC_FIELD_DELIMITERS ",\n"

#define SS_IOC_HTTP_URL  "http://"
#define SS_IOC_HTTPS_URL "https://"

int ss_ioc_file_load(json_object* ioc_json) {
    int rv = -1;
    uint64_t id;
    FILE* ioc_fd   = NULL;
    
    id = ss_conf->ioc_file_id++;
    ss_ioc_file_t* ioc_file = &ss_conf->ioc_files[id];
    memset(ioc_file, 0, sizeof(*ioc_file));
    ioc_file->file_id = id;
    
    if (!ioc_json) {
        fprintf(stderr, "ioc_json is null\n");
        goto error_out;
    }
    if (!json_object_is_type(ioc_json, json_type_object)) {
        fprintf(stderr, "ioc_json is not object\n");
        goto error_out;
    }
    
    ioc_file->path = ss_json_string_get(ioc_json, "path");
    if (ioc_file->path == NULL) {
        fprintf(stderr, "ioc_path is null\n");
        goto error_out;
    }
    
    rv = ss_nn_queue_create(ioc_json, &ioc_file->nn_queue);
    if (rv) {
        fprintf(stderr, "could not allocate ioc_file %s nm_queue\n", ioc_file->path);
        goto error_out;
    }
    
    ioc_fd = fopen(ioc_file->path, "r");
    if (ioc_fd == NULL) {
        fprintf(stderr, "could not open ioc file %s: %s\n",
            ioc_file->path, strerror(errno));
        goto error_out;
    }
    
    ssize_t grv;
    char* ioc_str;
    size_t ioc_len;
    ss_ioc_entry_t* ioc;
    uint64_t line = 0;
    uint64_t indicators = 0;
    
    while (1) {
        ++line;
        
        errno = 0;
        grv = getdelim(&ioc_str, &ioc_len, SS_IOC_LINE_DELIMITER, ioc_fd);
        if (grv < 0 && errno) {
            fprintf(stderr, "could not read IOC file %s, line %lu: %s\n",
                ioc_file->path, line, strerror(errno));
            continue;
        }
        else if (grv < 0) {
            fprintf(stderr, "finished reading IOC file %s, line %lu\n",
                ioc_file->path, line);
            break;
        }
        
        ioc = ss_ioc_entry_create(ioc_file, ioc_str);
        if (ioc == NULL) {
            fprintf(stderr, "could not create IOC from file %s, line: %lu, payload: %s\n",
                ioc_file->path, line, ioc_str);
            continue;
        }
        
        ss_ioc_chain_add(ioc);
        ++indicators;
        if (indicators && indicators % 10000 == 0) {
            fprintf(stderr, "checkpoint IOC file %s, line %lu\n",
                ioc_file->path, line);
        }
    }
    
    fprintf(stderr, "loaded %lu IOCs from %s\n", indicators, ioc_file->path);
    rv = 0;
    
    error_out:
    if (ioc_file->path) je_free(ioc_file->path);
    if (ioc_fd)         fclose(ioc_fd);
    if (rv != 0) {
        fprintf(stderr, "ioc_file %s could not be loaded\n", ioc_file->path);
    }
    
    return rv;
}

int ss_ioc_chain_dump(uint64_t limit) {
    uint64_t counter = 1;
    ss_ioc_entry_t* iptr;
    ss_ioc_entry_t* itmp;
    
    fprintf(stderr, "dumping %lu entries from ioc_chain...\n", limit);
    TAILQ_FOREACH_SAFE(iptr, &ss_conf->ioc_chain.ioc_list, entry, itmp) {
        fprintf(stderr, "ioc chain entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
    
    return 0;
}

int ss_ioc_tables_dump(uint64_t limit) {
    uint64_t counter;
    ss_ioc_entry_t* iptr;
#ifdef SS_IOC_BACKEND_RAM
    ss_ioc_entry_t* itmp;
#elif SS_IOC_BACKEND_DISK
    int rv;
    MDB_txn*    txn;
    MDB_cursor* cursor;
    MDB_val     key, value;
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, 0, &txn);
#endif
    
    counter = 1;
    fprintf(stderr, "dumping %lu entries from ip4_table...\n", limit);
#ifdef SS_IOC_BACKEND_RAM
    HASH_ITER(hh, ss_conf->ip4_table, iptr, itmp) {
        fprintf(stderr, "ip4_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
#elif SS_IOC_BACKEND_DISK
    rv = mdb_cursor_open(txn, ss_conf->ip4_dbi, &cursor);
    while (mdb_cursor_get(cursor, &key, &value, MDB_NEXT) == 0) {
        fprintf(stderr, "ip4_table entry number %lu\n", counter);
        iptr = (ss_ioc_entry_t*) value.mv_data;
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
    mdb_cursor_close(cursor);
#endif
    
    counter = 1;
    fprintf(stderr, "dumping %lu entries from ip6_table...\n", limit);
#ifdef SS_IOC_BACKEND_RAM
    HASH_ITER(hh, ss_conf->ip6_table, iptr, itmp) {
        fprintf(stderr, "ip6_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
#elif SS_IOC_BACKEND_DISK
    rv = mdb_cursor_open(txn, ss_conf->ip6_dbi, &cursor);
    while (mdb_cursor_get(cursor, &key, &value, MDB_NEXT) == 0) {
        fprintf(stderr, "ip6_table entry number %lu\n", counter);
        iptr = (ss_ioc_entry_t*) value.mv_data;
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
    mdb_cursor_close(cursor);
#endif
    
    counter = 1;
    fprintf(stderr, "dumping %lu entries from domain_table...\n", limit);
#ifdef SS_IOC_BACKEND_RAM
    HASH_ITER(hh, ss_conf->domain_table, iptr, itmp) {
        fprintf(stderr, "domain_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
#elif SS_IOC_BACKEND_DISK
    rv = mdb_cursor_open(txn, ss_conf->domain_dbi, &cursor);
    while (mdb_cursor_get(cursor, &key, &value, MDB_NEXT) == 0) {
        fprintf(stderr, "domain_table entry number %lu\n", counter);
        iptr = (ss_ioc_entry_t*) value.mv_data;
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
    mdb_cursor_close(cursor);
#endif
    
    counter = 1;
    fprintf(stderr, "dumping %lu entries from url_table...\n", limit);
#ifdef SS_IOC_BACKEND_RAM
    HASH_ITER(hh_full, ss_conf->url_table, iptr, itmp) {
        fprintf(stderr, "url_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
#elif SS_IOC_BACKEND_DISK
    rv = mdb_cursor_open(txn, ss_conf->url_dbi, &cursor);
    while (mdb_cursor_get(cursor, &key, &value, MDB_NEXT) == 0) {
        fprintf(stderr, "url_table entry number %lu\n", counter);
        iptr = (ss_ioc_entry_t*) value.mv_data;
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
    mdb_cursor_close(cursor);
#endif

    counter = 1;
    fprintf(stderr, "dumping %lu entries from email_table...\n", limit);
#ifdef SS_IOC_BACKEND_RAM
    HASH_ITER(hh_full, ss_conf->email_table, iptr, itmp) {
        fprintf(stderr, "email_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
#elif SS_IOC_BACKEND_DISK
    rv = mdb_cursor_open(txn, ss_conf->email_dbi, &cursor);
    while (mdb_cursor_get(cursor, &key, &value, MDB_NEXT) == 0) {
        fprintf(stderr, "email_table entry number %lu\n", counter);
        iptr = (ss_ioc_entry_t*) value.mv_data;
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter > limit) break;
    }
    mdb_cursor_close(cursor);
#endif

#ifdef SS_IOC_BACKEND_DISK
    if (txn) mdb_txn_abort(txn);
#endif
    
    return 0;
}

ss_ioc_entry_t* ss_ioc_entry_create(ss_ioc_file_t* ioc_file, char* ioc_str) {
    ss_ioc_entry_t* ioc = NULL;
    char* sepptr  = je_strdup(ioc_str);
    char* freeptr = sepptr;
    char* field   = NULL;
    int rv = 0;
    
    //fprintf(stderr, "attempt to parse ioc: %s\n", ioc_str);
    
    ioc = je_calloc(1, sizeof(ss_ioc_entry_t));
    if (ioc == NULL) {
        fprintf(stderr, "could not allocate ioc entry\n");
        goto error_out;
    }
    ioc->file_id = ioc_file->file_id;
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    errno = 0;
    ioc->id          = strtoll(field, NULL, 10);
    if (errno) {
        fprintf(stderr, "ioc id: %s: id was corrupt: %s\n",
            field, strerror(errno));
        goto error_out;
    }
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    ioc->type        = ss_ioc_type_load(field);
    if (ioc->type == (ss_ioc_type_t) -1) {
        fprintf(stderr, "ioc id: %lu: type was corrupt: %s\n",
            ioc->id, field);
        goto error_out;
    }
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    strlcpy(ioc->threat_type, field, sizeof(ioc->threat_type));
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    rv = ss_cidr_parse(field, &ioc->ip);
    if (rv != 1) {
        fprintf(stderr, "ioc id: %lu: ip was corrupt: %s\n",
            ioc->id, field);
        goto error_out;
    }
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    strlcpy(ioc->dns, field, sizeof(ioc->dns));
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    strlcpy(ioc->value, field, sizeof(ioc->value));
    
    je_free(freeptr); freeptr = NULL;
    return ioc;
    
    error_out:
    if (ioc) ss_ioc_entry_destroy(ioc);
    if (freeptr) je_free(freeptr); freeptr = NULL;
    return NULL;
}

int ss_ioc_entry_destroy(ss_ioc_entry_t* ioc_entry) {
    ioc_entry->id      = -1;
    ioc_entry->file_id = -1;
    ioc_entry->type    = -1;
    memset(&ioc_entry->threat_type, 0, sizeof(ioc_entry->threat_type));
    memset(&ioc_entry->ip, 0, sizeof(ioc_entry->ip));
    memset(&ioc_entry->dns, 0, sizeof(ioc_entry->dns));
    memset(&ioc_entry->value, 0, sizeof(ioc_entry->value));
    je_free(ioc_entry);
    return 0;
}

// used when the rte_log code is uninitialized
// typically during configuration file parsing
int ss_ioc_entry_dump(ss_ioc_entry_t* ioc) {
    char ip_str[SS_ADDR_STR_MAX];
    ss_inet_ntop(&ioc->ip, ip_str, sizeof(ip_str));
    fprintf(stderr, "ioc entry: id: %lu type: %s threat_type: %s ip: %s dns: %s value: %s\n",
        ioc->id, ss_ioc_type_dump(ioc->type), ioc->threat_type, ip_str, ioc->dns, ioc->value);
    return 0;
}

// used when the rte_log code is initialized
// typically during runtime when ioc matches are found
int ss_ioc_entry_dump_dpdk(ss_ioc_entry_t* ioc) {
    char ip_str[SS_ADDR_STR_MAX];
    ss_inet_ntop(&ioc->ip, ip_str, sizeof(ip_str));
    RTE_LOG(NOTICE, IOC, "ioc entry: id: %lu type: %s threat_type: %s ip: %s dns: %s value: %s\n",
        ioc->id, ss_ioc_type_dump(ioc->type), ioc->threat_type, ip_str, ioc->dns, ioc->value);
    return 0;
}

ss_ioc_type_t ss_ioc_type_load(const char* ioc_type) {
    if (!strcasecmp(ioc_type, "ip"))     return SS_IOC_TYPE_IP;
    if (!strcasecmp(ioc_type, "domain")) return SS_IOC_TYPE_DOMAIN;
    if (!strcasecmp(ioc_type, "url"))    return SS_IOC_TYPE_URL;
    if (!strcasecmp(ioc_type, "email"))  return SS_IOC_TYPE_EMAIL;
    if (!strcasecmp(ioc_type, "md5"))    return SS_IOC_TYPE_MD5;
    if (!strcasecmp(ioc_type, "sha256")) return SS_IOC_TYPE_SHA256;
    return -1;
}

const char* ss_ioc_type_dump(ss_ioc_type_t ioc_type) {
    switch (ioc_type) {
        case SS_IOC_TYPE_IP:     return "IP";
        case SS_IOC_TYPE_DOMAIN: return "DOMAIN";
        case SS_IOC_TYPE_URL:    return "URL";
        case SS_IOC_TYPE_EMAIL:  return "EMAIL";
        case SS_IOC_TYPE_MD5:    return "MD5";
        case SS_IOC_TYPE_SHA256: return "SHA256";
        default:                 return "UNKNOWN";
    }
}

int ss_ioc_chain_destroy() {
    return 0;
}

int ss_ioc_chain_add(ss_ioc_entry_t* ioc_entry) {
    TAILQ_INSERT_TAIL(&ss_conf->ioc_chain.ioc_list, ioc_entry, entry);
    return 0;
}

int ss_ioc_chain_remove_index(int index) {
    int counter = 0;
    ss_ioc_entry_t* iptr;
    ss_ioc_entry_t* itmp;
    TAILQ_FOREACH_SAFE(iptr, &ss_conf->ioc_chain.ioc_list, entry, itmp) {
       if (counter == index) {
            TAILQ_REMOVE(&ss_conf->ioc_chain.ioc_list, iptr, entry);
            return 0;
        }
        ++counter;
    }
    return -1;
}

int ss_ioc_chain_remove_id(uint64_t id) {
    ss_ioc_entry_t* iptr;
    ss_ioc_entry_t* itmp;
    TAILQ_FOREACH_SAFE(iptr, &ss_conf->ioc_chain.ioc_list, entry, itmp) {
        if (id == iptr->id) {
            TAILQ_REMOVE(&ss_conf->ioc_chain.ioc_list, iptr, entry);
            return 0;
        }
    }
    return -1;
}

int ss_ioc_chain_optimize() {
    ss_ioc_entry_t* iptr;
    ss_ioc_entry_t* itmp;
    char* header;
    char  tvalue[SS_DNS_NAME_MAX];
    int   offset;
#ifdef SS_IOC_BACKEND_RAM
    ss_ioc_entry_t* hiptr;
#elif SS_IOC_BACKEND_DISK
    int   rv;
    MDB_txn* txn = NULL;
    MDB_val  key, value;
    
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, 0, &txn);
    if (rv) {
        fprintf(stderr, "could not begin ioc optimization mdb transaction: %s\n", mdb_strerror(rv));
        return -1;
    }
#endif
    
    fprintf(stderr, "optimizing IOCs...\n");
    
    uint64_t indicators = 0;
    next_ioc: TAILQ_FOREACH_SAFE(iptr, &ss_conf->ioc_chain.ioc_list, entry, itmp) {
        switch (iptr->type) {
            case SS_IOC_TYPE_IP: {
                const char* result = ss_inet_ntop(&iptr->ip, tvalue, sizeof(tvalue));
                if (result == NULL) {
                    fprintf(stderr, "ioc id %lu: could not parse ip value\n", iptr->id);
                    goto next_ioc;
                }
                //fprintf(stderr, "ioc id %lu, extracted ip value: %s\n", iptr->id, tvalue);
                switch (iptr->ip.family) {
                    case SS_AF_INET4: {
#ifdef SS_IOC_BACKEND_RAM
                        HASH_FIND_INT(ss_conf->ip4_table, &iptr->ip.ip4_addr, hiptr);
                        if (hiptr == NULL) {
                            HASH_ADD_INT(ss_conf->ip4_table, &iptr->ip.ip4_addr, iptr);
                        }
                        else {
                            fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, result);
                        }
#elif SS_IOC_BACKEND_DISK
                        key.mv_size   = sizeof(iptr->ip.ip4_addr);
                        key.mv_data   = &iptr->ip.ip4_addr;
                        value.mv_size = sizeof(*iptr);
                        value.mv_data = iptr;
                        rv = mdb_put(txn, ss_conf->ip4_dbi, &key, &value, 0);
                        if (rv) {
                            fprintf(stderr, "ioc id %lu: could not insert in ip4_dbi: %s\n", iptr->id, mdb_strerror(rv));
                            goto next_ioc;
                        }
#endif
                        break;
                    }
                    case SS_AF_INET6: {
#ifdef SS_IOC_BACKEND_RAM
                        HASH_FIND(hh, ss_conf->ip6_table, &iptr->ip.ip6_addr, sizeof(iptr->ip.ip6_addr), hiptr);
                        if (hiptr == NULL) {
                            HASH_ADD(hh, ss_conf->ip6_table, &iptr->ip.ip6_addr, sizeof(iptr->ip.ip6_addr), iptr);
                        }
                        else {
                            fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, result);
                        }
#elif SS_IOC_BACKEND_DISK
                        key.mv_size   = sizeof(iptr->ip.ip6_addr);
                        key.mv_data   = &iptr->ip.ip6_addr;
                        value.mv_size = sizeof(*iptr);
                        value.mv_data = iptr;
                        rv = mdb_put(txn, ss_conf->ip6_dbi, &key, &value, 0);
                        if (rv) {
                            fprintf(stderr, "ioc id %lu: could not insert in ip6_dbi: %s\n", iptr->id, mdb_strerror(rv));
                            goto next_ioc;
                        }
#endif
                        break;
                    }
                    default: {
                        fprintf(stderr, "ioc id %lu: could not parse ip value: %s\n", iptr->id, tvalue);
                        goto next_ioc;
                    }
                }
                break;
            }
            case SS_IOC_TYPE_DOMAIN: {
                // NOTE: convert names to canonical form (trailing '.')
                offset = strlcpy(tvalue, iptr->value, sizeof(tvalue));
                if (tvalue[offset] != '.') {
                    tvalue[offset] = '.';
                    tvalue[offset + 1] = '\0';
                }
                strlcpy(iptr->value, tvalue, sizeof(iptr->value));
                //fprintf(stderr, "ioc %lu extracted dns domain: %s\n", iptr->id, domain);
#ifdef SS_IOC_BACKEND_RAM
                HASH_FIND_STR(ss_conf->domain_table, iptr->value, hiptr);
                if (hiptr == NULL) {
                    HASH_ADD_STR(ss_conf->domain_table, value, iptr);
                }
                else {
                    fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, iptr->value);
                }
#elif SS_IOC_BACKEND_DISK
                key.mv_size   = strlen(iptr->value);
                key.mv_data   = iptr->value;
                value.mv_size = sizeof(*iptr);
                value.mv_data = iptr;
                rv = mdb_put(txn, ss_conf->domain_dbi, &key, &value, 0);
                if (rv) {
                    fprintf(stderr, "ioc id %lu: could not insert in domain_dbi: %s\n", iptr->id, mdb_strerror(rv));
                    goto next_ioc;
                }
#endif
                break;
            }
            case SS_IOC_TYPE_URL: {
                // insert in domain and url hashes
                // (for DNS and HTTP interception)
                header = strcasestr(iptr->value, SS_IOC_HTTP_URL);
                offset = strlen(SS_IOC_HTTP_URL);
                if (header == NULL || header != iptr->value) {
                    header = strcasestr(iptr->value, SS_IOC_HTTPS_URL);
                    offset = strlen(SS_IOC_HTTPS_URL);
                }
                
                if (header == NULL || header != iptr->value) {
                    fprintf(stderr, "ioc %lu has corrupt url: %s\n", iptr->id, iptr->value);
                    goto next_ioc;
                }
                // NOTE: convert names to canonical form (trailing '.')
                strlcpy(tvalue, iptr->value + offset, sizeof(tvalue) - 2);
                for (int i = 0; ; ++i) {
                    if (tvalue[i] == '/' || tvalue[i] == '\0') {
                        tvalue[i] = '.';
                        tvalue[i+1] = '\0';
                        break;
                    }
                }
                strlcpy(iptr->dns, tvalue, sizeof(iptr->dns));
                //fprintf(stderr, "ioc %lu extracted url domain: %s\n", iptr->id, tvalue);
#ifdef SS_IOC_BACKEND_RAM
                HASH_FIND_STR(ss_conf->domain_table, iptr->dns, hiptr);
                if (hiptr == NULL) {
                    HASH_ADD_STR(ss_conf->domain_table, dns, iptr);
                }
                else {
                    fprintf(stderr, "ioc id %lu: skipping duplicate dns: %s\n", iptr->id, iptr->dns);
                }
                HASH_FIND(hh_full, ss_conf->url_table, &iptr->value, strlen(iptr->value), hiptr);
                if (hiptr == NULL) {
                    HASH_ADD(hh_full, ss_conf->url_table, value, strlen(iptr->value), iptr);
                }
                else {
                    fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, iptr->value);
                }
#elif SS_IOC_BACKEND_DISK
                key.mv_size   = strlen(iptr->dns);
                key.mv_data   = iptr->dns;
                value.mv_size = sizeof(*iptr);
                value.mv_data = iptr;
                rv = mdb_put(txn, ss_conf->domain_dbi, &key, &value, 0);
                if (rv) {
                    fprintf(stderr, "ioc id %lu: could not insert in domain_dbi: %s\n", iptr->id, mdb_strerror(rv));
                    goto next_ioc;
                }
                key.mv_size   = strlen(iptr->value);
                key.mv_data   = iptr->value;
                value.mv_size = sizeof(*iptr);
                value.mv_data = iptr;
                rv = mdb_put(txn, ss_conf->url_dbi, &key, &value, 0);
                if (rv) {
                    fprintf(stderr, "ioc id %lu: could not insert in url_dbi: %s\n", iptr->id, mdb_strerror(rv));
                    goto next_ioc;
                }
#endif
                break;
            }
            case SS_IOC_TYPE_EMAIL: {
                // insert in domain and email hashes
                // (for DNS and SMTP interception)
                char* domain = strstr(iptr->value, "@");
                if (domain == NULL || domain + 0 == '\0' || domain + 1 == '\0') {
                    fprintf(stderr, "ioc %lu has corrupt email: %s\n", iptr->id, iptr->value);
                    goto next_ioc;
                }
                // move forward to first byte after first '@'
                domain += 1;
                // NOTE: convert names to canonical form (trailing '.')
                strlcpy(tvalue, domain, sizeof(tvalue) - 2);
                if (tvalue[offset] != '.') {
                    tvalue[offset] = '.';
                    tvalue[offset + 1] = '\0';
                }
                strlcpy(iptr->dns, tvalue, sizeof(iptr->dns));
                fprintf(stderr, "ioc %lu extracted email domain: %s\n", iptr->id, tvalue);
#ifdef SS_IOC_BACKEND_RAM
                HASH_FIND_STR(ss_conf->domain_table, iptr->dns, hiptr);
                if (hiptr == NULL) {
                    HASH_ADD_STR(ss_conf->domain_table, dns, iptr);
                }
                else {
                    fprintf(stderr, "ioc id %lu: skipping duplicate dns: %s\n", iptr->id, iptr->dns);
                }
                HASH_FIND(hh_full, ss_conf->email_table, &iptr->value, strlen(iptr->value), hiptr);
                if (hiptr == NULL) {
                    HASH_ADD(hh_full, ss_conf->email_table, value, strlen(iptr->value), iptr);
                }
                else {
                    fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, iptr->value);
                }
#elif SS_IOC_BACKEND_DISK
                key.mv_size   = strlen(iptr->dns);
                key.mv_data   = iptr->dns;
                value.mv_size = sizeof(*iptr);
                value.mv_data = iptr;
                rv = mdb_put(txn, ss_conf->domain_dbi, &key, &value, 0);
                if (rv) {
                    fprintf(stderr, "ioc id %lu: could not insert in domain_dbi: %s\n", iptr->id, mdb_strerror(rv));
                    goto next_ioc;
                }
                key.mv_size   = strlen(iptr->value);
                key.mv_data   = iptr->value;
                value.mv_size = sizeof(*iptr);
                value.mv_data = iptr;
                rv = mdb_put(txn, ss_conf->email_dbi, &key, &value, 0);
                if (rv) {
                    fprintf(stderr, "ioc id %lu: could not insert in email_dbi: %s\n", iptr->id, mdb_strerror(rv));
                    goto next_ioc;
                }
#endif
                break;
            }
            case SS_IOC_TYPE_MD5: {
                fprintf(stderr, "ioc %lu is unsupported md5 type\n", iptr->id);
                goto next_ioc;
            }
            case SS_IOC_TYPE_SHA256: {
                fprintf(stderr, "ioc %lu is unsupported sha256 type\n", iptr->id);
                goto next_ioc;
            }
            default: {
                fprintf(stderr, "ioc %lu is unknown type %d\n", iptr->id, iptr->type);
                goto next_ioc;
            }
        }
        ++indicators;
        if (indicators && indicators % 10000 == 0) {
            fprintf(stderr, "checkpoint IOC count %lu\n", indicators);
        }
    }
    
#ifdef SS_IOC_BACKEND_DISK
    rv = mdb_txn_commit(txn);
    if (rv) {
        fprintf(stderr, "could not commit ioc optimization mdb transaction: %s\n", mdb_strerror(rv));
        return -1;
    }
#endif
    
    fprintf(stderr, "optimized %lu IOCs\n", indicators);
    return 0;
}

ss_ioc_entry_t* ss_ioc_metadata_match(ss_metadata_t* md) {
    ss_ioc_entry_t* iptr = NULL;
    uint32_t ip;
#ifdef SS_IOC_BACKEND_DISK
    int   rv;
    MDB_txn* txn = NULL;
    MDB_val  key, value;
    
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rv) {
        fprintf(stderr, "could not begin ioc metadata mdb transaction: %s\n", mdb_strerror(rv));
        return NULL;
    }
#endif
    
    if (md->eth_type == ETHER_TYPE_IPV4) {
        ip = *(uint32_t*) &md->sip;
#ifdef SS_IOC_BACKEND_RAM
        HASH_FIND_INT(ss_conf->ip4_table, &ip, iptr);
        if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
        key.mv_size = sizeof(uint32_t);
        key.mv_data = (uint32_t*) &md->sip;
        rv = mdb_get(txn, ss_conf->ip4_dbi, &key, &value);
        if (rv != MDB_NOTFOUND) {
            iptr = (ss_ioc_entry_t*) value.mv_data;
            goto out;
        }
#endif
        
        ip = *(uint32_t*) &md->dip;
#ifdef SS_IOC_BACKEND_RAM
        HASH_FIND_INT(ss_conf->ip4_table, &ip, iptr);
        if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
        key.mv_size = sizeof(uint32_t);
        key.mv_data = (uint32_t*) &md->dip;
        rv = mdb_get(txn, ss_conf->ip4_dbi, &key, &value);
        if (rv != MDB_NOTFOUND) {
            iptr = (ss_ioc_entry_t*) value.mv_data;
            goto out;
        }
#endif
    }
    else if (md->eth_type == ETHER_TYPE_IPV6) {
#ifdef SS_IOC_BACKEND_RAM
        HASH_FIND(hh, ss_conf->ip6_table, &md->sip, sizeof(md->sip), iptr);
        if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
        key.mv_size = sizeof(md->sip);
        key.mv_data = &md->sip;
        rv = mdb_get(txn, ss_conf->ip6_dbi, &key, &value);
        if (rv != MDB_NOTFOUND) {
            iptr = (ss_ioc_entry_t*) value.mv_data;
            goto out;
        }
#endif
        
#ifdef SS_IOC_BACKEND_RAM
        HASH_FIND(hh, ss_conf->ip6_table, &md->dip, sizeof(md->dip), iptr);
        if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
        key.mv_size = sizeof(md->dip);
        key.mv_data = &md->dip;
        rv = mdb_get(txn, ss_conf->ip6_dbi, &key, &value);
        if (rv != MDB_NOTFOUND) {
            iptr = (ss_ioc_entry_t*) value.mv_data;
            goto out;
        }
#endif
    }
    
    out:
#ifdef SS_IOC_BACKEND_DISK
    if (txn) mdb_txn_abort(txn);
#endif
    return iptr;
}

ss_ioc_entry_t* ss_ioc_dns_match(ss_metadata_t* md) {
    ss_ioc_entry_t* iptr = NULL;
#ifdef SS_IOC_BACKEND_DISK
    int   rv;
    MDB_txn* txn = NULL;
    MDB_val  key, value;
    
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rv) {
        fprintf(stderr, "could not begin ioc dns match mdb transaction: %s\n", mdb_strerror(rv));
        return NULL;
    }
#endif

#ifdef SS_IOC_BACKEND_RAM
    HASH_FIND_STR(ss_conf->domain_table, (char*) md->dns_name, iptr);
    if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
    key.mv_size = strlen((char*)md->dns_name);
    key.mv_data = &md->dns_name;
    rv = mdb_get(txn, ss_conf->domain_dbi, &key, &value);
    if (rv != MDB_NOTFOUND) {
        iptr = (ss_ioc_entry_t*) value.mv_data;
        goto out;
    }
#endif
    
    for (int i = 0; i < SS_DNS_RESULT_MAX; ++i) {
        ss_answer_t* dns_answer = &md->dns_answers[i];
        switch (dns_answer->type) {
            case SS_TYPE_NAME: {
#ifdef SS_IOC_BACKEND_RAM
                HASH_FIND_STR(ss_conf->domain_table, (char*) dns_answer->payload, iptr);
                if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
                key.mv_size = strlen((char*)md->dns_name);
                key.mv_data = &md->dns_name;
                rv = mdb_get(txn, ss_conf->domain_dbi, &key, &value);
                if (rv != MDB_NOTFOUND) {
                    iptr = (ss_ioc_entry_t*) value.mv_data;
                    goto out;
                }
#endif
                break;
            }
            case SS_TYPE_IP: {
                iptr = ss_ioc_ip_match((ip_addr_t*) dns_answer->payload);
                if (iptr) goto out;
                break;
            }
            default: {
                // fprintf(stderr, "unknown ss_answer type %d\n", dns_answer->type);
                break;
            }
        }
    }
    
    out:
#ifdef SS_IOC_BACKEND_DISK
    if (txn) mdb_txn_abort(txn);
#endif
    return iptr;
}

// XXX: for URL and email, this should also try to match the domain
ss_ioc_entry_t* ss_ioc_syslog_match(const char* ioc, ss_ioc_type_t ioc_type) {
    int             rv;
    ss_ioc_entry_t* iptr = NULL;
    ip_addr_t       ip_addr;
    char            tdns[SS_DNS_NAME_MAX];
#ifdef SS_IOC_BACKEND_DISK
    MDB_txn* txn = NULL;
    MDB_val  key, value;
    
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rv) {
        fprintf(stderr, "could not begin ioc syslog match mdb transaction: %s\n", mdb_strerror(rv));
        return NULL;
    }
#endif
    
    switch (ioc_type) {
        case SS_IOC_TYPE_IP: {
            rv = ss_cidr_parse(ioc, &ip_addr);
            if (rv != 1) {
                fprintf(stderr, "could not extract ip from ioc %s\n", ioc);
            }
            else {
                iptr = ss_ioc_ip_match(&ip_addr);
            }
            break;
        }
        case SS_IOC_TYPE_DOMAIN: {
            // NOTE: convert names to canonical form (trailing '.')
            rv = strlcpy(tdns, ioc, sizeof(tdns) - 2);
            if (tdns[rv] != '.') {
                tdns[rv]         = '.';
                tdns[rv + 1]     = '\0';
            }
#ifdef SS_IOC_BACKEND_RAM
            HASH_FIND_STR(ss_conf->domain_table, tdns, iptr);
#elif SS_IOC_BACKEND_DISK
            key.mv_size   = strlen(tdns);
            key.mv_data   = tdns;
            rv = mdb_get(txn, ss_conf->domain_dbi, &key, &value);
            if (rv != MDB_NOTFOUND) {
                iptr = (ss_ioc_entry_t*) value.mv_data;
            }
#endif
            break;
        }
        case SS_IOC_TYPE_URL: {
#ifdef SS_IOC_BACKEND_RAM
            HASH_FIND(hh_full, ss_conf->url_table, ioc, strlen(ioc), iptr);
#elif SS_IOC_BACKEND_DISK
            key.mv_size   = strlen(ioc);
            key.mv_data   = (void*) ioc;
            rv = mdb_get(txn, ss_conf->url_dbi, &key, &value);
            if (rv != MDB_NOTFOUND) {
                iptr = (ss_ioc_entry_t*) value.mv_data;
            }
#endif
            break;
        }
        case SS_IOC_TYPE_EMAIL: {
#ifdef SS_IOC_BACKEND_RAM
            HASH_FIND(hh_full, ss_conf->email_table, ioc, strlen(ioc), iptr);
#elif SS_IOC_BACKEND_DISK
            key.mv_size   = strlen(ioc);
            key.mv_data   = (void*) ioc;
            rv = mdb_get(txn, ss_conf->email_dbi, &key, &value);
            if (rv != MDB_NOTFOUND) {
                iptr = (ss_ioc_entry_t*) value.mv_data;
            }
#endif
            break;
        }
        case SS_IOC_TYPE_MD5: {
            fprintf(stderr, "ioc %s is unsupported md5 type\n", ioc);
            break;
        }
        case SS_IOC_TYPE_SHA256: {
            fprintf(stderr, "ioc %s is unsupported sha256 type\n", ioc);
            break;
        }
        default: {
            fprintf(stderr, "ioc %s is unknown type %d\n", ioc, ioc_type);
            break;
        }
    }
    
    out:
#ifdef SS_IOC_BACKEND_DISK
    if (txn) mdb_txn_abort(txn);
#endif
    return iptr;
}

ss_ioc_entry_t* ss_ioc_ip_match(ip_addr_t* ip) {
    ss_ioc_entry_t* iptr = NULL;
#ifdef SS_IOC_BACKEND_DISK
    int   rv;
    MDB_txn* txn = NULL;
    MDB_val  key, value;
    
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rv) {
        fprintf(stderr, "could not begin ioc ip match mdb transaction: %s\n", mdb_strerror(rv));
        return NULL;
    }
#endif

    switch (ip->family) {
        case SS_AF_INET4: {
#ifdef SS_IOC_BACKEND_RAM
            HASH_FIND_INT(ss_conf->ip4_table, ip->ip4_addr, iptr);
            if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
            key.mv_size   = sizeof(uint32_t);
            key.mv_data   = (uint32_t*) &ip->ip4_addr;
            rv = mdb_get(txn, ss_conf->ip4_dbi, &key, &value);
            if (rv != MDB_NOTFOUND) {
                iptr = (ss_ioc_entry_t*) value.mv_data;
                goto out;
            }
#endif
            break;
        }
        case SS_AF_INET6: {
#ifdef SS_IOC_BACKEND_RAM
            HASH_FIND(hh, ss_conf->ip6_table, ip->ip6_addr, sizeof(ip->ip6_addr), iptr);
            if (iptr) goto out;
#elif SS_IOC_BACKEND_DISK
            key.mv_size   = sizeof(ip->ip6_addr);
            key.mv_data   = &ip->ip6_addr;
            rv = mdb_get(txn, ss_conf->ip6_dbi, &key, &value);
            if (rv != MDB_NOTFOUND) {
                iptr = (ss_ioc_entry_t*) value.mv_data;
                goto out;
            }
#endif
            break;
        }
        default: {
        }
    }
    
    out:
#ifdef SS_IOC_BACKEND_DISK
    if (txn) mdb_txn_abort(txn);
#endif
    return iptr;
}

ss_ioc_entry_t* ss_ioc_xaddr_match(struct xaddr* addr) {
    ss_ioc_entry_t* iptr = NULL;
    uint32_t ip;
#ifdef SS_IOC_BACKEND_DISK
    int   rv;
    MDB_txn* txn = NULL;
    MDB_val  key, value;
    
    rv = mdb_txn_begin(ss_conf->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rv) {
        fprintf(stderr, "could not begin ioc xaddr match mdb transaction: %s\n", mdb_strerror(rv));
        goto out;
    }
#endif
    
    if      (addr->af == SS_AF_INET4) {
        ip = *(uint32_t*) &addr->v4.s_addr;
#ifdef SS_IOC_BACKEND_RAM
        HASH_FIND_INT(ss_conf->ip4_table, &ip, iptr);
#elif SS_IOC_BACKEND_DISK
        key.mv_size   = sizeof(uint32_t);
        key.mv_data   = &ip;
        rv = mdb_get(txn, ss_conf->ip4_dbi, &key, &value);
        if (rv != MDB_NOTFOUND) {
            iptr = (ss_ioc_entry_t*) value.mv_data;
            goto out;
        }
#endif
    }
    else if (addr->af == SS_AF_INET6) {
#ifdef SS_IOC_BACKEND_RAM
        HASH_FIND(hh, ss_conf->ip6_table, addr->v6.s6_addr, sizeof(addr->v6.s6_addr), iptr);
#elif SS_IOC_BACKEND_DISK
        key.mv_size   = sizeof(addr->v6.s6_addr);
        key.mv_data   = addr->v6.s6_addr;
        rv = mdb_get(txn, ss_conf->ip6_dbi, &key, &value);
        if (rv != MDB_NOTFOUND) {
            iptr = (ss_ioc_entry_t*) value.mv_data;
            goto out;
        }
#endif
    }

    out:    
#ifdef SS_IOC_BACKEND_DISK
    if (txn) mdb_txn_abort(txn);
#endif
    return iptr;
}

ss_ioc_entry_t* ss_ioc_netflow_match(struct store_flow_complete* flow) {
    ss_ioc_entry_t* iptr = NULL;
    
    /* XXX: some day, check the src_as and dst_as */
    iptr = ss_ioc_xaddr_match(&flow->agent_addr);
    if (iptr) return iptr;
    iptr = ss_ioc_xaddr_match(&flow->src_addr);
    if (iptr) return iptr;
    iptr = ss_ioc_xaddr_match(&flow->dst_addr);
    if (iptr) return iptr;
    iptr = ss_ioc_xaddr_match(&flow->gateway_addr);
    if (iptr) return iptr;
    
    return iptr;
}
