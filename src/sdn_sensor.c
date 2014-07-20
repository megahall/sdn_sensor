#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <log4c.h>

#include "sensor_configuration.h"

int main(int argc, char* argv[]) {
    ss_conf_t* ss_conf = ss_conf_file_parse();
    
    return 0;
}
