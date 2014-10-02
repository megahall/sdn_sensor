#!/bin/bash

set -e -x

sloccount --follow --personcost 130000 --addlang makefile external/dpdk-helpers scripts src
