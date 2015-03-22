#!/bin/bash

set -e -x

script_directory="$(dirname $(readlink -f ${BASH_SOURCE}))"
source "${script_directory}/../sdn_sensor_rc"

cd "${build_directory}/external/jnano"
./setup-jnano.bash

cd "${build_directory}/external/patricia-trie"
./setup-patricia-trie.bash

mvn dependency:sources
mvn dependency:resolve -Dclassifier=javadoc

cd "${script_directory}/src/main/resources"
wget --timestamping http://www.spamhaus.org/drop/drop.txt
wget --timestamping http://www.spamhaus.org/drop/edrop.txt
wget --timestamping https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
wget --timestamping https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
wget --timestamping http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
unzip -o top-1m.csv.zip

mvn compile
mvn package
