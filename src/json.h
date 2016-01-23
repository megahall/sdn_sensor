#pragma once

#include <json-c/json.h>
#include <json-c/json_object_private.h>

/* BEGIN PROTOTYPES */

struct json_object* ss_json_object_get(json_object* items, const char* key);
const char* ss_json_string_view(json_object* items, const char* key);
char* ss_json_string_get(json_object* items, const char* key);
int ss_json_boolean_get(json_object* items, const char* key, int vdefault);

/* END PROTOTYPES */
