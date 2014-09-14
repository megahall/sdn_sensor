#define _GNU_SOURCE /* strcasestr */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>

#include <bsd/string.h>
#include <bsd/sys/queue.h>

#include <json-c/json.h>

#include "ioc.h"

#include "common.h"
#include "ip_utils.h"
#include "json.h"
#include "sdn_sensor.h"

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
    if (ioc_file->path) free(ioc_file->path);
    if (ioc_fd)         fclose(ioc_fd);
    fprintf(stderr, "ioc_file %s could not be loaded\n", ioc_file->path);
    
    return rv;
}

int ss_ioc_chain_dump(uint64_t limit) {
    uint64_t counter = 0;
    ss_ioc_entry_t* iptr;
    ss_ioc_entry_t* itmp;
    
    fprintf(stderr, "dumping %lu entries from ioc_chain...\n", limit);
    TAILQ_FOREACH_SAFE(iptr, &ss_conf->ioc_chain.ioc_list, entry, itmp) {
        fprintf(stderr, "ioc chain entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter >= limit) break;
    }
    
    return 0;
}

int ss_ioc_tables_dump(uint64_t limit) {
    uint64_t counter = 0;
    ss_ioc_entry_t* iptr;
    ss_ioc_entry_t* itmp;
    
    fprintf(stderr, "dumping %lu entries from ip4_table...\n", limit);
    HASH_ITER(hh, ss_conf->ip4_table, iptr, itmp) {
        fprintf(stderr, "ip4_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter >= limit) break;
    }
    
    fprintf(stderr, "dumping %lu entries from ip6_table...\n", limit);
    HASH_ITER(hh, ss_conf->ip6_table, iptr, itmp) {
        fprintf(stderr, "ip6_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter >= limit) break;
    }
    
    fprintf(stderr, "dumping %lu entries from domain_table...\n", limit);
    HASH_ITER(hh, ss_conf->domain_table, iptr, itmp) {
        fprintf(stderr, "domain_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter >= limit) break;
    }
    
    fprintf(stderr, "dumping %lu entries from url_table...\n", limit);
    HASH_ITER(hh_full, ss_conf->url_table, iptr, itmp) {
        fprintf(stderr, "url_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter >= limit) break;
    }
    
    fprintf(stderr, "dumping %lu entries from email_table...\n", limit);
    HASH_ITER(hh_full, ss_conf->email_table, iptr, itmp) {
        fprintf(stderr, "email_table entry number %lu\n", counter);
        ss_ioc_entry_dump(iptr);
        counter++;
        if (limit && counter >= limit) break;
    }
    
    return 0;
}

ss_ioc_entry_t* ss_ioc_entry_create(ss_ioc_file_t* ioc_file, char* ioc_str) {
    ss_ioc_entry_t* ioc = NULL;
    char* sepptr  = strdup(ioc_str);
    char* freeptr = sepptr;
    char* field   = NULL;
    int rv = 0;
    
    //fprintf(stderr, "attempt to parse ioc: %s\n", ioc_str);
    
    ioc = calloc(1, sizeof(ss_ioc_entry_t));
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
    
    free(freeptr);
    return ioc;
    
    error_out:
    if (ioc) ss_ioc_entry_destroy(ioc);
    if (freeptr) free(freeptr);
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
    free(ioc_entry);
    return 0;
}

int ss_ioc_entry_dump(ss_ioc_entry_t* ioc) {
    char ip_str[SS_ADDR_STR_MAX];
    ss_inet_ntop(&ioc->ip, ip_str, sizeof(ip_str));
    fprintf(stderr, "ioc entry: id: %lu type: %s threat_type: %s ip: %s dns: %s value: %s\n",
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
    else                                 return -1;
}

const char* ss_ioc_type_dump(ss_ioc_type_t ioc_type) {
    switch (ioc_type) {
        case SS_IOC_TYPE_IP:     return "SS_IOC_TYPE_IP";
        case SS_IOC_TYPE_DOMAIN: return "SS_IOC_TYPE_DOMAIN";
        case SS_IOC_TYPE_URL:    return "SS_IOC_TYPE_URL";
        case SS_IOC_TYPE_EMAIL:  return "SS_IOC_TYPE_EMAIL";
        case SS_IOC_TYPE_MD5:    return "SS_IOC_TYPE_MD5";
        case SS_IOC_TYPE_SHA256: return "SS_IOC_TYPE_SHA256";
        default:                 return "SS_IOC_TYPE_UNKNOWN";
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
    ss_ioc_entry_t* hiptr;
    char* header;
    char  tvalue[SS_DNS_NAME_MAX];
    int   offset;
    
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
                        HASH_FIND_INT(ss_conf->ip4_table, &iptr->ip.ip4_addr, hiptr);
                        if (hiptr == NULL) {
                            HASH_ADD_INT(ss_conf->ip4_table, ip.ip4_addr, iptr);
                        }
                        else {
                            fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, result);
                        }
                        break;
                    }
                    case SS_AF_INET6: {
                        HASH_FIND(hh, ss_conf->ip6_table, &iptr->ip.ip6_addr, sizeof(iptr->ip.ip6_addr), hiptr);
                        if (hiptr == NULL) {
                            HASH_ADD(hh, ss_conf->ip6_table, ip.ip6_addr, sizeof(iptr->ip.ip6_addr), iptr);
                        }
                        else {
                            fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, result);
                        }
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
                HASH_FIND_STR(ss_conf->domain_table, iptr->value, hiptr);
                if (hiptr == NULL) {
                    HASH_ADD_STR(ss_conf->domain_table, value, iptr);
                }
                else {
                    fprintf(stderr, "ioc id %lu: skipping duplicate value: %s\n", iptr->id, iptr->value);
                }
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
                strlcpy(iptr->dns, tvalue, sizeof(iptr->dns));
                fprintf(stderr, "ioc %lu extracted email domain: %s\n", iptr->id, domain);
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
    
    fprintf(stderr, "optimized %lu IOCs\n", indicators);
    return 0;
}

ss_ioc_entry_t* ss_ioc_metadata_match(ss_metadata_t* md) {
    ss_ioc_entry_t* iptr;
    uint32_t ip;
    
    if (md->eth_type == ETHER_TYPE_IPV4) {
        ip = *(uint32_t*) &md->sip;
        HASH_FIND_INT(ss_conf->ip4_table, &ip, iptr);
        if (iptr) return iptr;
        
        ip = *(uint32_t*) &md->dip;
        HASH_FIND_INT(ss_conf->ip4_table, &ip, iptr);
        if (iptr) return iptr;
    }
    else if (md->eth_type == ETHER_TYPE_IPV6) {
        HASH_FIND(hh, ss_conf->ip6_table, &md->sip, sizeof(md->sip), iptr);
        if (iptr) return iptr;
        
        HASH_FIND(hh, ss_conf->ip6_table, &md->dip, sizeof(md->dip), iptr);
        if (iptr) return iptr;
    }
    
    HASH_FIND_STR(ss_conf->domain_table, (char*) md->dns_name, iptr);
    if (iptr) return iptr;
    
    for (int i = 0; i < SS_DNS_RESULT_MAX; ++i) {
        ss_answer_t* dns_answer = &md->dns_answers[i];
        switch (dns_answer->type) {
            case SS_TYPE_NAME: {
                HASH_FIND_STR(ss_conf->domain_table, (char*) dns_answer->payload, iptr);
                if (iptr) return iptr;
            }
            case SS_TYPE_IP: {
                HASH_FIND_INT(ss_conf->ip4_table, &ip, iptr);
                if (iptr) return iptr;
            }
            default: {
                // fprintf(stderr, "unknown ss_answer type %d\n", dns_answer->type);
                break;
            }
        }
        if (iptr) return iptr;
    }
    
    return NULL;
}
