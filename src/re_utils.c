#include <stdbool.h>

#include <bsd/sys/queue.h>

#include <pcre.h>

#include <jemalloc/jemalloc.h>

#include "re_utils.h"

#include "json.h"
#include "metadata.h"
#include "sdn_sensor.h"

int ss_re_init() {
    pcre_malloc       = &je_malloc;
    pcre_free         = &je_free;
    pcre_stack_malloc = &je_malloc;
    pcre_stack_free   = &je_free;
    return 0;
}

/* UTILITIES */

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

ss_re_backend_t ss_re_backend_load(const char* backend_type) {
    if (!strcasecmp(backend_type, "pcre")) return SS_RE_BACKEND_PCRE;
    if (!strcasecmp(backend_type, "re2"))  return SS_RE_BACKEND_RE2;
    return -1;
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

ss_re_entry_t* ss_re_entry_create(json_object* re_json) {
    ss_re_entry_t* re_entry = NULL;
    int rv                  = -1;
    const char* tmp_string  = NULL;
    
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
    
    tmp_string = ss_json_string_view(re_json, "backend");
    if (tmp_string == NULL) {
        fprintf(stderr, "re_entry re_type is null\n");
        goto error_out;
    }
    re_entry->backend = ss_re_backend_load(tmp_string);
    if ((int) re_entry->backend == -1) {
        fprintf(stderr, "re_entry re_type is invalid\n");
        goto error_out;
    }
    
    tmp_string = ss_json_string_view(re_json, "type");
    if (tmp_string == NULL) {
        fprintf(stderr, "re_entry type is null\n");
        goto error_out;
    }
    re_entry->type = ss_re_type_load(tmp_string);
    if ((int) re_entry->type == -1) {
        fprintf(stderr, "re_entry type is invalid\n");
        goto error_out;
    }
    
    tmp_string = ss_json_string_view(re_json, "ioc_type");
    if (tmp_string == NULL) {
        fprintf(stderr, "re_entry ioc_type is null\n");
        goto error_out;
    }
    re_entry->ioc_type = ss_ioc_type_load(tmp_string);
    if ((int) re_entry->ioc_type == -1) {
        fprintf(stderr, "re_entry ioc_type is invalid\n");
        goto error_out;
    }
    
    rv = ss_nn_queue_create(re_json, &re_entry->nn_queue);
    if (rv) {
        fprintf(stderr, "could not allocate re nm_queue\n");
        goto error_out;
    }
    
    if (re_entry->backend == SS_RE_BACKEND_PCRE) {
        rv = ss_re_entry_prepare_pcre(re_json, re_entry);
        if (rv) {
            fprintf(stderr, "could not prepare pcre\n");
            goto error_out;
        }
    }
    else if (re_entry->backend == SS_RE_BACKEND_RE2) {
        rv = ss_re_entry_prepare_re2(re_json, re_entry);
        if (rv) {
            fprintf(stderr, "could not prepare re2\n");
            goto error_out;
        }
    }
    
    fprintf(stderr, "created re entry [%s]\n", re_entry->name);
    return re_entry;
    
    error_out:
    ss_re_entry_destroy(re_entry); re_entry = NULL;
    return NULL;
}

int ss_re_entry_destroy(ss_re_entry_t* re_entry) {
    if (!re_entry) return 0;
    
    ss_nn_queue_destroy(&re_entry->nn_queue);
    
    re_entry->matches  = -1;
    re_entry->inverted = -1;
    re_entry->backend  = SS_RE_BACKEND_EMPTY;
    re_entry->type     = SS_RE_TYPE_EMPTY;
    re_entry->ioc_type = SS_IOC_TYPE_EMPTY;
    
    if (re_entry->pcre_re_extra) { pcre_free_study(re_entry->pcre_re_extra); re_entry->pcre_re_extra = NULL; }
    if (re_entry->pcre_re)       { pcre_free(re_entry->pcre_re);             re_entry->pcre_re = NULL;       }
    if (re_entry->re2_re)        { cre2_delete(re_entry->re2_re);            re_entry->re2_re = NULL;        }
    if (re_entry->name)          { je_free(re_entry->name);                  re_entry->name = NULL;          }
    
    je_free(re_entry);
    
    return 0;
}

/* RE MATCH INTERFACE */

int ss_re_chain_match(ss_re_match_t* re_match, uint8_t* l4_offset, uint16_t l4_length) {
    int rv = 0;
    ss_re_entry_t* rptr;
    ss_re_entry_t* rtmp;

    TAILQ_FOREACH_SAFE(rptr, &ss_conf->re_chain.re_list, entry, rtmp) {
        RTE_LOG(DEBUG, EXTRACTOR, "attempt re backend %d match type %d against syslog rule %s\n",
            rptr->backend, rptr->type, rptr->name);
        if (rptr->backend == SS_RE_BACKEND_PCRE) {
            rv = ss_re_chain_match_pcre(re_match, rptr, l4_offset, l4_length);
        }
        else if (rptr->backend == SS_RE_BACKEND_RE2) {
            rv = ss_re_chain_match_re2(re_match, rptr, l4_offset, l4_length);
        }
        
        if (rv) {
            RTE_LOG(DEBUG, EXTRACTOR, "finish re match type %d against syslog rule %s with result %d\n",
                rptr->type, rptr->name, rv);
            re_match->re_entry = rptr;
            return rv;
        }
    }

    return 0;
}

/* PCRE BACKEND */

int ss_re_entry_prepare_pcre(json_object* re_json, ss_re_entry_t* re_entry) {
    const char* re_string    = NULL;
    const char* re_perror    = NULL;
    int re_offset            = 0;
    int re_flags             = 0;
    int re_flag              = 0;

    re_string = ss_json_string_view(re_json, "re");
    if (re_string == NULL) {
        fprintf(stderr, "re_entry re is null\n");
        return -1;
    }
    
    re_flags |= PCRE_NEWLINE_ANYCRLF;
    
    re_flag = ss_json_boolean_get(re_json, "nocase",   1);
    if (re_flag) re_flags |= PCRE_CASELESS;
    re_flag = ss_json_boolean_get(re_json, "utf8",     1);
    if (re_flag) re_flags |= PCRE_UTF8;
    
    re_entry->pcre_re = pcre_compile(re_string, re_flags, &re_perror, &re_offset, NULL);
    if (re_entry->pcre_re == NULL) {
        fprintf(stderr, "re_entry %s re is invalid: offset: %d: error: %s\n",
            re_entry->name, re_offset, re_perror);
        return -1;
    }
    
    re_flag = ss_json_boolean_get(re_json, "inverted", 0);
    re_entry->inverted = re_flag;
    
    re_entry->pcre_re_extra = pcre_study(re_entry->pcre_re, PCRE_STUDY_JIT_COMPILE, &re_perror);
    if (re_entry->pcre_re_extra == NULL) {
        fprintf(stderr, "re_entry %s JIT compile failed: error: %s\n",
            re_entry->name, re_perror);
        return -1;
    }
    
    return 0;
}

int ss_re_chain_match_pcre(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length) {
    if (re_entry->type == SS_RE_TYPE_COMPLETE) {
        return ss_re_chain_match_pcre_complete(re_match, re_entry, l4_offset, l4_length);
    }
    else if (re_entry->type == SS_RE_TYPE_SUBSTRING) {
        return ss_re_chain_match_pcre_substring(re_match, re_entry, l4_offset, l4_length);
    }
    else {
        RTE_LOG(ERR, EXTRACTOR, "unknown pcre re_type %d\n", re_entry->type);
        return -1;
    }
}

int ss_re_chain_match_pcre_complete(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length) {
    int match_count;
    int match_vector[(0 + 1) * 3];
    
    match_count = pcre_exec(re_entry->pcre_re, re_entry->pcre_re_extra,
                            (char*) l4_offset, l4_length,
                            0, PCRE_NEWLINE_ANYCRLF,
                            match_vector, (0 + 1) * 3);
    
    // flip around match logic if invert flag is set
    if (re_entry->inverted) {
        if      (match_count > 0)                   match_count = PCRE_ERROR_NOMATCH;
        else if (match_count == PCRE_ERROR_NOMATCH) match_count = 1;
    }
    
    if (match_count < 0 && match_count != PCRE_ERROR_NOMATCH) {
        RTE_LOG(ERR, EXTRACTOR, "failed complete match error %s against syslog rule %s\n",
            ss_pcre_strerror(match_count), re_entry->name);
        return -1;
    }
    else if (match_count == PCRE_ERROR_NOMATCH) {
        RTE_LOG(DEBUG, EXTRACTOR, "no complete match against syslog rule %s\n", re_entry->name);
        return 0;
    }
    else {
        RTE_LOG(NOTICE, EXTRACTOR, "successful complete match for syslog rule %s\n", re_entry->name);
        return 1;
    }
}

int ss_re_chain_match_pcre_substring(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length) {
    int             match_count;
    int             start_point = 0;
    int             have_match  = 0;
    int             match_vector[(0 + 1) * 3];
    uint8_t*        match_string;
    ss_ioc_entry_t* iptr;
    
    // XXX: this is buggy because it will not be a true per-thread stack
    pcre_assign_jit_stack(re_entry->pcre_re_extra, NULL, NULL);
    
    do {
        match_count = pcre_exec(re_entry->pcre_re, re_entry->pcre_re_extra,
                                (char*) l4_offset, l4_length,
                                start_point, PCRE_NEWLINE_ANYCRLF,
                                match_vector, (0 + 1) * 3);
        
        if (match_count == 0 || match_count == PCRE_ERROR_NOMATCH) {
            goto end_loop;
        }
        else if (match_count < 0) {
            RTE_LOG(ERR, EXTRACTOR, "failed substring match error %s against syslog rule %s\n",
                ss_pcre_strerror(match_count), re_entry->name);
            return -1;
        }
        
        if (pcre_get_substring((char*) l4_offset,
                               match_vector, match_count,
                               0, (const char**) &match_string) >= 0) {
            RTE_LOG(DEBUG, EXTRACTOR, "attempt ioc match against substring %s\n",
                match_string);
            iptr = ss_ioc_syslog_match((char*) match_string, re_entry->ioc_type);
            if (iptr) {
                RTE_LOG(NOTICE, EXTRACTOR, "successful ioc match for syslog rule %s against substring %s\n",
                    re_entry->name, match_string);
                have_match = 1;
                re_match->ioc_entry = iptr;
            }
            pcre_free_substring((char*) match_string);
        }
        
        start_point = match_vector[1];
    } while (match_count > 0 && start_point < l4_length && !have_match);
    
    end_loop:
    if (have_match) {
        RTE_LOG(NOTICE, EXTRACTOR, "successful substring ioc match for syslog rule %s\n", re_entry->name);
        return 1;
    }
    else {
        // no match
        RTE_LOG(DEBUG, EXTRACTOR, "failed match against syslog rule %s\n", re_entry->name);
        return 0;
    }
}

/* RE2 BACKEND */

int ss_re_entry_prepare_re2(json_object* re_json, ss_re_entry_t* re_entry) {
    int             re_error    = 0;
    const char*     re_string   = NULL;
    const char*     re_perror   = NULL;
    cre2_options_t* re2_options = NULL;
    cre2_string_t   re_serror;
    int re_flag                 = 0;
    
    re2_options = cre2_opt_new();
    if (!re2_options) {
        fprintf(stderr, "could not allocate re2_options\n");
        goto error_out;
    }
    
    re_string = ss_json_string_view(re_json, "re");
    if (re_string == NULL) {
        fprintf(stderr, "re_entry re is null\n");
        goto error_out;
    }
    
    re_flag = ss_json_boolean_get(re_json, "nocase", 1);
    cre2_opt_set_case_sensitive(re2_options, !re_flag);
    
    re_flag = ss_json_boolean_get(re_json, "utf8",     1);
    if (re_flag) {
        cre2_opt_set_encoding(re2_options, CRE2_UTF8);
    }
    else {
        cre2_opt_set_encoding(re2_options, CRE2_Latin1);
    }
    
    re_flag = ss_json_boolean_get(re_json, "verbose", 1);
    cre2_opt_set_log_errors(re2_options, 1);
    
    re_entry->re2_re = cre2_new(re_string, strlen(re_string), re2_options);
    if (re_entry->re2_re == NULL) {
        fprintf(stderr, "could not allocate re_entry re2_re\n");
        goto error_out;
    }
    
    re_error  = cre2_error_code(re_entry->re2_re);
    re_perror = cre2_error_string(re_entry->re2_re);
    if (re_error) {
        cre2_error_arg(re_entry->re2_re, &re_serror);
        fprintf(stderr, "re_entry %s re is invalid: location: %s error: %s\n",
            re_entry->name, re_serror.data, re_perror);
        return -1;
    }
    
    re_flag = ss_json_boolean_get(re_json, "inverted", 0);
    re_entry->inverted = re_flag;
    
    return 0;
    
    error_out:
    if (re2_options)      { cre2_opt_delete(re2_options); re2_options = NULL; }
    
    return -1;
}

int ss_re_chain_match_re2(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length) {
    if (re_entry->type == SS_RE_TYPE_COMPLETE) {
        return ss_re_chain_match_re2_complete(re_match, re_entry, l4_offset, l4_length);
    }
    else if (re_entry->type == SS_RE_TYPE_SUBSTRING) {
        return ss_re_chain_match_re2_substring(re_match, re_entry, l4_offset, l4_length);
    }
    else {
        RTE_LOG(ERR, EXTRACTOR, "unknown re2 re_type %d\n", re_entry->type);
        return -1;
    }
}

int ss_re_chain_match_re2_complete(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length) {
    int rv;
    
    rv = cre2_match(re_entry->re2_re, (char*) l4_offset, l4_length, 0, l4_length, CRE2_UNANCHORED, NULL, 0);
    if (re_entry->inverted) {
        rv = !rv;
    }
    
    if (rv) {
        RTE_LOG(NOTICE, EXTRACTOR, "successful complete match for syslog rule %s\n", re_entry->name);
        return 1;
    }
    else {
        RTE_LOG(DEBUG, EXTRACTOR, "no complete match against syslog rule %s\n", re_entry->name);
        return 0;
    }
}

int ss_re_chain_match_re2_substring(ss_re_match_t* re_match, ss_re_entry_t* re_entry, uint8_t* l4_offset, uint16_t l4_length) {
    int             match_flag;
    int             match_length;
    int             start_point;
    int             have_match  = 0;
    ss_ioc_entry_t* iptr;
    cre2_string_t   match[1];
    char            substring[SS_IOC_DNS_SIZE + 1];
    
    match[0].data   = (char*) l4_offset;
    match[0].length = 0;
    
    do {
        start_point = (char*) match[0].data + match[0].length - (char*) l4_offset;
        match_flag = cre2_match(re_entry->re2_re,
            (char*) l4_offset, l4_length,
            start_point, l4_length,
            CRE2_UNANCHORED, match, 1);
        
        if (match_flag == 0) {
            goto end_loop;
        }
        
        // extract substring 0 (full content of match)
        match_length = match[0].length;
        memcpy(substring, match[0].data, match_length > SS_IOC_DNS_SIZE? SS_IOC_DNS_SIZE : match_length);
        substring[match_length] = '\0';
        
        RTE_LOG(DEBUG, EXTRACTOR, "attempt ioc match against substring %s\n",
            substring);
        
        iptr = ss_ioc_syslog_match(substring, re_entry->ioc_type);
        if (iptr) {
            RTE_LOG(NOTICE, EXTRACTOR, "successful ioc match for syslog rule %s against substring %s\n",
                re_entry->name, substring);
            have_match = 1;
            re_match->ioc_entry = iptr;
            return 1;
        }
    } while (match_flag > 0 && !have_match);
    
    end_loop:
    if (have_match) {
        RTE_LOG(NOTICE, EXTRACTOR, "successful substring ioc match against syslog rule %s\n", re_entry->name);
        return 1;
    }
    else {
        // no match
        RTE_LOG(DEBUG, EXTRACTOR, "no substring match against syslog rule %s\n", re_entry->name);
        return 0;
    }
}
