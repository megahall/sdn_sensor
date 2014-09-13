#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <json-c/json.h>

char* ss_json_string_get(json_object* items, const char* key) {
    json_object* item;
    const char* value;
    char* rv;
    
    item = json_object_object_get(items, key);
    if (item == NULL) {
        fprintf(stderr, "key %s not present\n", key);
        return NULL;
    }
    if (!json_object_is_type(item, json_type_string)) {
        fprintf(stderr, "value for %s is not object\n", key);
        return NULL;
    }
    value = json_object_get_string(item);
    if (value == NULL) {
        fprintf(stderr, "value for %s is null\n", key);
        return NULL;
    }
    rv = strdup(value);
    if (rv == NULL) {
        fprintf(stderr, "could not allocate return value for %s\n", key);
        return NULL;
    }
    return rv;
}
