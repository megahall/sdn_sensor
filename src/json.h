#ifndef __JSON_H__
#define __JSON_H__

#include <json-c/json.h>
#include <json-c/json_object_private.h>

/* BEGIN PROTOTYPES */

const char* ss_json_string_view(json_object* items, const char* key);
char* ss_json_string_get(json_object* items, const char* key);
int ss_json_boolean_get(json_object* items, const char* key, int vdefault);

/* END PROTOTYPES */

#endif /* __JSON_H__ */
