#!/bin/bash

set -e -x

mvn package

read -d '' mvn_options << EOF || true
install:install-file
-DlocalRepositoryPath=../../analytics/repo
-DcreateChecksum=true
-Dpackaging=jar
-DgroupId=org.ardverk
-Dversion=0.7-SNAPSHOT
EOF

mvn ${mvn_options} -Dfile=target/patricia-trie-0.7-SNAPSHOT.jar -DartifactId=patricia-trie
