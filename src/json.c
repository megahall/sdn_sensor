#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <json-c/json.h>
#include <json-c/json_object_private.h>

#include "je_utils.h"

const char* ss_json_string_view(json_object* items, const char* key) {
    json_object* item;
    const char* value = NULL;
    
    item = json_object_object_get(items, key);
    if (item == NULL) {
        fprintf(stderr, "key %s not present\n", key);
        goto out;
    }
    if (!json_object_is_type(item, json_type_string)) {
        fprintf(stderr, "value for %s is not string\n", key);
        goto out;
    }
    value = json_object_get_string(item);
    if (value == NULL) {
        fprintf(stderr, "value for %s is null\n", key);
        goto out;
    }
    
    out:
    return value;
}

char* ss_json_string_get(json_object* items, const char* key) {
    const char* value;
    char* rv = NULL;
    
    value = ss_json_string_view(items, key);
    if (value == NULL) {
        fprintf(stderr, "value for %s is null\n", key);
        goto out;
    }
    rv = je_strdup(value);
    if (rv == NULL) {
        fprintf(stderr, "could not allocate return value for %s\n", key);
        goto out;
    }
    
    out:
    return rv;
}

int ss_json_boolean_get(json_object* items, const char* key, int vdefault) {
    json_object* item;
    int rv = vdefault;
    
    item = json_object_object_get(items, key);
    if (item == NULL) {
        fprintf(stderr, "note: key %s not present, use default %d\n", key, vdefault);
        goto out;
    }
    if (!json_object_is_type(item, json_type_boolean)) {
        fprintf(stderr, "value for %s is not boolean\n", key);
        goto out;
    }
    rv = json_object_get_boolean(item);
    
    out:
    return rv;
}
