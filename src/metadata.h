#ifndef __METADATA_H__
#define __METADATA_H__

#include <json-c/json.h>

#include "common.h"
#include "ioc.h"
#include "nn_queue.h"

/* BEGIN PROTOTYPES */

uint8_t* ss_nn_queue_prepare_metadata(const char* source, nn_queue_t* nn_queue, ss_frame_t* fbuf, ss_ioc_entry_t* iptr);
json_object* ss_ioc_prepare_metadata(const char* source, nn_queue_t* nn_queue, ss_ioc_entry_t* iptr, json_object* json);

/* END PROTOTYPES */

#endif /* __METADATA_H__ */
