#!/bin/bash

# start with g* for OS X
# then switch to without for Linux if needed
os=$(uname -s)
if [[ $os == "Darwin" ]]; then
    readlink_path=$(which greadlink)
else
    readlink_path=$(which readlink)
fi

script_directory=$(dirname $(${readlink_path} -f $BASH_SOURCE))

source "${script_directory}/analytics-rc"

cd "${script_directory}"
mvn package
java -Danalytics.local -jar "${script_directory}/target/sdn-sensor-analytics.one-jar.jar"
