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
#include "sdn_sensor.h"

#define SS_IOC_LINE_DELIMITER   '\n'
#define SS_IOC_FIELD_DELIMITERS ",\n"

int ss_ioc_chain_load(const char* ioc_path) {
    int rv = 0;
    FILE* ioc_file = NULL;
    
    fprintf(stderr, "begin loading IOC list from %s\n", ioc_path);
    
    ioc_file = fopen(ioc_path, "r");
    if (ioc_file == NULL) {
        fprintf(stderr, "could not load IOC list from %s: %s\n",
            ioc_path, strerror(errno));
        rv = -1;
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
        grv = getdelim(&ioc_str, &ioc_len, SS_IOC_LINE_DELIMITER, ioc_file);
        if (grv < 0 && errno) {
            fprintf(stderr, "could not read IOC file %s, line %lu: %s\n",
                ioc_path, line, strerror(errno));
            continue;
        }
        else if (grv < 0) {
            fprintf(stderr, "finished reading IOC file %s, line %lu\n",
                ioc_path, line);
            break;
        }
        
        ioc = ss_ioc_entry_create(ioc_str);
        if (ioc == NULL) {
            fprintf(stderr, "could not create IOC from file %s, line: %lu, payload: %s\n",
                ioc_path, line, ioc_str);
            continue;
        }
        
        ss_ioc_chain_add(ioc);
        ++indicators;
    }
    
    fprintf(stderr, "loaded %lu IOCs from %s\n", indicators, ioc_path);
    
    error_out:
    if (ioc_file) fclose(ioc_file);
    
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

ss_ioc_entry_t* ss_ioc_entry_create(char* ioc_str) {
    ss_ioc_entry_t* ioc = NULL;
    char* sepptr  = strdup(ioc_str);
    char* freeptr = sepptr;
    char* field   = NULL;
    int rv = 0;
    
    //fprintf(stderr, "attempt to parse ioc: %s\n", ioc_str);
    
    ioc = malloc(sizeof(ss_ioc_entry_t));
    if (ioc == NULL) {
        fprintf(stderr, "could not allocate ioc entry\n");
        goto error_out;
    }
    memset(ioc, 0, sizeof(ss_ioc_entry_t));
    
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
    rv = ss_parse_cidr(field, &ioc->ip);
    if (rv != 1) {
        fprintf(stderr, "ioc id: %lu: ip was corrupt: %s\n",
            ioc->id, field);
        goto error_out;
    }
    
    field = strsep(&sepptr, SS_IOC_FIELD_DELIMITERS);
    strlcpy(ioc->rdns, field, sizeof(ioc->rdns));
    
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
    ioc_entry->id   = -1;
    ioc_entry->type = -1;
    memset(&ioc_entry->threat_type, 0, sizeof(ioc_entry->threat_type));
    memset(&ioc_entry->ip, 0, sizeof(ioc_entry->ip));
    memset(&ioc_entry->rdns, 0, sizeof(ioc_entry->rdns));
    memset(&ioc_entry->value, 0, sizeof(ioc_entry->value));
    free(ioc_entry);
    return 0;
}

int ss_ioc_entry_dump(ss_ioc_entry_t* ioc) {
    char ip_str[SS_ADDR_STR_MAX];
    ss_inet_ntop(&ioc->ip, ip_str, sizeof(ip_str));
    fprintf(stderr, "ioc entry: id: %lu type: %s threat_type: %s ip: %s rdns: %s value: %s\n",
        ioc->id, ss_ioc_type_dump(ioc->type), ioc->threat_type, ip_str, ioc->rdns, ioc->value);
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
