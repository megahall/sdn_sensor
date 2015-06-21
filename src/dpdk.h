#pragma once

#include <stdint.h>

#include "sdn_sensor.h"

/* BEGIN PROTOTYPES */

void ss_port_stats_print(ss_port_statistics_t* port_statistics, unsigned int port_limit);
void ss_port_link_status_check_all(uint8_t port_limit);

/* END PROTOTYPES */
