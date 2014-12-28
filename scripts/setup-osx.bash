#!/bin/bash

set -e -x

brew install gd libyaml

cpan CPAN::SQLite Module::Signature Term::ReadLine
cpan JSON JSON::PP JSON::XS YAML::XS
cpan NanoMsg::Raw GD 
