#include <stdbool.h>

#include <bsd/sys/queue.h>

#include <pcre.h>

#include <jemalloc/jemalloc.h>

#include "json.h"
#include "re_utils.h"
#include "sdn_sensor.h"

int ss_pcre_init() {
    pcre_malloc       = &je_malloc;
    pcre_free         = &je_free;
    pcre_stack_malloc = &je_malloc;
    pcre_stack_free   = &je_free;
    return 0;
}

const char* ss_pcre_strerror(int pcre_errno) {
    switch (pcre_errno) {
        case PCRE_ERROR_NOMATCH:            return "PCRE_ERROR_NOMATCH";
        case PCRE_ERROR_NULL:               return "PCRE_ERROR_NULL";
        case PCRE_ERROR_BADOPTION:          return "PCRE_ERROR_BADOPTION";
        case PCRE_ERROR_BADMAGIC:           return "PCRE_ERROR_BADMAGIC";
        case PCRE_ERROR_UNKNOWN_OPCODE:     return "PCRE_ERROR_UNKNOWN_OPCODE_OR_NODE";
        case PCRE_ERROR_NOMEMORY:           return "PCRE_ERROR_NOMEMORY";
        case PCRE_ERROR_NOSUBSTRING:        return "PCRE_ERROR_NOSUBSTRING";
        case PCRE_ERROR_MATCHLIMIT:         return "PCRE_ERROR_MATCHLIMIT";
        case PCRE_ERROR_CALLOUT:            return "PCRE_ERROR_CALLOUT";
        case PCRE_ERROR_BADUTF8:            return "PCRE_ERROR_BADUTF";
        //case PCRE_ERROR_BADUTF32:           return "PCRE_ERROR_BADUTF32";
        case PCRE_ERROR_BADUTF8_OFFSET:     return "PCRE_ERROR_BADUTF_OFFSET";
        case PCRE_ERROR_PARTIAL:            return "PCRE_ERROR_PARTIAL";
        case PCRE_ERROR_BADPARTIAL:         return "PCRE_ERROR_BADPARTIAL";
        case PCRE_ERROR_INTERNAL:           return "PCRE_ERROR_INTERNAL";
        case PCRE_ERROR_BADCOUNT:           return "PCRE_ERROR_BADCOUNT";
        case PCRE_ERROR_DFA_UITEM:          return "PCRE_ERROR_DFA_UITEM";
        case PCRE_ERROR_DFA_UCOND:          return "PCRE_ERROR_DFA_UCOND";
        case PCRE_ERROR_DFA_UMLIMIT:        return "PCRE_ERROR_DFA_UMLIMIT";
        case PCRE_ERROR_DFA_WSSIZE:         return "PCRE_ERROR_DFA_WSSIZE";
        case PCRE_ERROR_DFA_RECURSE:        return "PCRE_ERROR_DFA_RECURSE";
        case PCRE_ERROR_RECURSIONLIMIT:     return "PCRE_ERROR_RECURSIONLIMIT";
        case PCRE_ERROR_NULLWSLIMIT:        return "PCRE_ERROR_NULLWSLIMIT";
        case PCRE_ERROR_BADNEWLINE:         return "PCRE_ERROR_BADNEWLINE";
        case PCRE_ERROR_BADOFFSET:          return "PCRE_ERROR_BADOFFSET";
        case PCRE_ERROR_SHORTUTF8:          return "PCRE_ERROR_SHORTUTF";
        case PCRE_ERROR_RECURSELOOP:        return "PCRE_ERROR_RECURSELOOP";
        case PCRE_ERROR_JIT_STACKLIMIT:     return "PCRE_ERROR_JIT_STACKLIMIT";
        case PCRE_ERROR_BADMODE:            return "PCRE_ERROR_BADMODE";
        case PCRE_ERROR_BADENDIANNESS:      return "PCRE_ERROR_BADENDIANNESS";
        case PCRE_ERROR_DFA_BADRESTART:     return "PCRE_ERROR_DFA_BADRESTART";
        //case PCRE_ERROR_JIT_BADOPTION:      return "PCRE_ERROR_JIT_BADOPTION";
        //case PCRE_ERROR_BADLENGTH:          return "PCRE_ERROR_BADLENGTH";
        //case PCRE_ERROR_UNSET:              return "PCRE_ERROR_UNSET";
        default:                            return "PCRE_ERROR_UNKNOWN";
    }
}

ss_re_type_t ss_re_type_load(const char* re_type) {
    if (!strcasecmp(re_type, "complete"))  return SS_RE_TYPE_COMPLETE;
    if (!strcasecmp(re_type, "substring")) return SS_RE_TYPE_SUBSTRING;
    return -1;
}

/* RE CHAIN */

int ss_re_chain_destroy() {
    ss_re_entry_t* rptr;
    ss_re_entry_t* rtmp;
    TAILQ_FOREACH_SAFE(rptr, &ss_conf->re_chain.re_list, entry, rtmp) {
        ss_re_entry_destroy(rptr);
        TAILQ_REMOVE(&ss_conf->re_chain.re_list, rptr, entry);
    }
    return 0;
}

ss_re_entry_t* ss_re_entry_create(json_object* re_json) {
    ss_re_entry_t* re_entry  = NULL;
    int rv                   = -1;
    const char* type_string  = NULL;
    const char* re_string    = NULL;
    const char* re_perror    = NULL;
    int re_offset            = 0;
    int re_flags             = 0;
    int re_flag              = 0;
    
    re_entry = je_calloc(1, sizeof(ss_re_entry_t));
    if (re_entry == NULL) {
        fprintf(stderr, "could not allocate re entry\n");
        goto error_out;
    }
    
    if (!re_json) {
        fprintf(stderr, "empty re configuration entry\n");
        goto error_out;
    }
    if (!json_object_is_type(re_json, json_type_object)) {
        fprintf(stderr, "re_json is not object\n");
        goto error_out;
    }
    
    re_entry->name = ss_json_string_get(re_json, "name");
    if (re_entry->name == NULL) {
        fprintf(stderr, "re_entry name is null\n");
        goto error_out;
    }
    
    re_string = ss_json_string_view(re_json, "re");
    if (re_string == NULL) {
        fprintf(stderr, "re_entry re is null\n");
        goto error_out;
    }
    
    type_string = ss_json_string_view(re_json, "type");
    if (type_string == NULL) {
        fprintf(stderr, "re_entry type is null\n");
        goto error_out;
    }
    re_entry->type = ss_re_type_load(type_string);
    if ((int) re_entry->type == -1) {
        fprintf(stderr, "re_entry type is invalid\n");
        goto error_out;
    }
    
    type_string = ss_json_string_view(re_json, "ioc_type");
    if (type_string == NULL) {
        fprintf(stderr, "re_entry ioc_type is null\n");
        goto error_out;
    }
    re_entry->ioc_type = ss_ioc_type_load(type_string);
    if ((int) re_entry->ioc_type == -1) {
        fprintf(stderr, "re_entry ioc_type is invalid\n");
        goto error_out;
    }
    
    rv = ss_nn_queue_create(re_json, &re_entry->nn_queue);
    if (rv) {
        fprintf(stderr, "could not allocate re nm_queue\n");
        goto error_out;
    }
    
    re_flags |= PCRE_NEWLINE_ANYCRLF;
    
    re_flag = ss_json_boolean_get(re_json, "nocase",   1);
    if (re_flag) re_flags |= PCRE_CASELESS;
    re_flag = ss_json_boolean_get(re_json, "utf8",     1);
    if (re_flag) re_flags |= PCRE_UTF8;
    
    re_entry->re = pcre_compile(re_string, re_flags, &re_perror, &re_offset, NULL);
    if (re_entry->re == NULL) {
        fprintf(stderr, "pcre_entry %s re is invalid: offset: %d: error: %s\n",
            re_entry->name, re_offset, re_perror);
        goto error_out;
    }
    
    re_flag = ss_json_boolean_get(re_json, "inverted", 0);
    re_entry->inverted = re_flag;
    
    re_entry->re_extra = pcre_study(re_entry->re, PCRE_STUDY_JIT_COMPILE, &re_perror);
    if (re_entry->re_extra == NULL) {
        fprintf(stderr, "pcre_entry %s JIT compile failed: error: %s\n",
            re_entry->name, re_perror);
        goto error_out;
    }
    
    fprintf(stderr, "created re entry [%s]\n", re_entry->name);
    return re_entry;
    
    error_out:
    ss_re_entry_destroy(re_entry); re_entry = NULL;
    return NULL;
}

int ss_re_entry_destroy(ss_re_entry_t* re_entry) {
    ss_nn_queue_destroy(&re_entry->nn_queue);
    re_entry->matches = -1;
    re_entry->inverted = -1;
    pcre_free_study(re_entry->re_extra);
    pcre_free(re_entry->re);
    if (re_entry->name) { je_free(re_entry->name); re_entry->name = NULL; }
    je_free(re_entry);
    return 0;
}

// XXX: can we move the re_chain match here or not???
int ss_re_chain_match(char* input) {
    return 0;
}

int ss_re_chain_add(ss_re_entry_t* re_entry) {
    TAILQ_INSERT_TAIL(&ss_conf->re_chain.re_list, re_entry, entry);
    return 0;
}
 
int ss_re_chain_remove_index(int index) {
    int counter = 0;
    ss_re_entry_t* pptr;
    ss_re_entry_t* ptmp;
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->re_chain.re_list, entry, ptmp) {
        if (counter == index) {
            TAILQ_REMOVE(&ss_conf->re_chain.re_list, pptr, entry);
            return 0;
        }
        ++counter;
    }  
    return -1;
}
 
int ss_re_chain_remove_name(char* name) {
    ss_re_entry_t* pptr;
    ss_re_entry_t* ptmp;
    TAILQ_FOREACH_SAFE(pptr, &ss_conf->re_chain.re_list, entry, ptmp) {
        if (!strcasecmp(name, pptr->name)) {
            TAILQ_REMOVE(&ss_conf->re_chain.re_list, pptr, entry);
            return 0;
        }
    }
    return -1;
}
