#!/bin/bash

set -x

#################################################
# Store arguments values
# verify, log, cleanup actions gets first two arguments

action=$1           #action: [setup, run, verify, cleanup]
node=$2             #node: [0 - dut1 node, 1 - dut2 node]
ifname=$3           #dut1 interface name when node is 0 /dut2 interface name when node is 1
dut1_if_ip=$4       #dut1 interface ip
dut2_if_ip=$5       #dut2 interface ip

#################################################
# Get path details

RUN_DIR=`dirname $(readlink -f $0)`
CSIT_SCRIPT_DIR=$RUN_DIR/..
ROOTDIR=$CSIT_SCRIPT_DIR/../../../
APP_DIR=${ROOTDIR}/dmm/config/app_test
LIB_PATH=${ROOTDIR}/dmm/release/lib64
DMM_SCRIPT_DIR=$ROOTDIR/dmm/scripts
LOG_PATH=/var/log

source $DMM_SCRIPT_DIR/csit/common.sh
#################################################
# Setup preparation

if [ "x$action" == "xsetup" ]; then
  setup_preparation vtcp_fork_server
fi

#################################################
# Execution
#execution "sudo LD_LIBRARY_PATH=${LIB_PATH} ./ktcp_fork_server -a 10000 -s ${dut1_if_ip} -t 50000"
#  "sudo LD_LIBRARY_PATH=${LIB_PATH} ./ktcp_client -p 10000 -d ${dut1_if_ip} -a 10000 -s ${dut2_if_ip} -t 50000"
if [ "x$action" == "xrun" ]; then
  execution "sudo LD_LIBRARY_PATH=${LIB_PATH} NSTACK_LOG_FILE_FLAG=1 ./vtcp_fork_server -a 10000 -s ${dut1_if_ip} -t 50000" \
    "sudo LD_LIBRARY_PATH=${LIB_PATH} NSTACK_LOG_FILE_FLAG=1 ./vtcp_client -p 10000 -d ${dut1_if_ip} -a 10000 -s ${dut2_if_ip} -t 50000"
fi

#################################################
# Verification

if [ "x$action" == "xverify" ]; then
  if [ "x$node" == "x1" ]; then
    verification "sudo cat $RUN_DIR/log_$(basename $0).txt | grep \"Success\""
  elif [ "x$node" == "x0" ]; then
    verification
  fi
fi

#################################################
# Print Log

if [ "x$action" == "xlog" ]; then
 print_log vtcp_fork_server vtcp_client
fi

#################################################
# Cleanup

if [ "x$action" == "xcleanup"  ]; then
  cleanup vtcp_fork_server vtcp_client
fi

exit 0
