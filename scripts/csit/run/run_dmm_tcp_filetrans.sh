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
  setup_preparation vc_serv_file
fi

#################################################
# Execution

if [ "x$action" == "xrun" ]; then
  execution "cp -f $DMM_SCRIPT_DIR/csit/file.txt . ;sudo LD_LIBRARY_PATH=${LIB_PATH} NSTACK_LOG_FILE_FLAG=1 ./vc_serv_file tcp ${dut1_if_ip} 1234" \
    "cp -f $DMM_SCRIPT_DIR/csit/file.txt . ;sudo LD_LIBRARY_PATH=${LIB_PATH} NSTACK_LOG_FILE_FLAG=1 ./vc_cli_file tcp ${dut1_if_ip} 1234 file.txt ${dut2_if_ip}"
fi

#################################################
# Verification

if [ "x$action" == "xverify" ]; then
  if [ "x$node" == "x0" ]; then
    verification "diff $APP_DIR/file.txt $APP_DIR/receive_file.txt >/dev/null"
  elif [ "x$node" == "x1" ]; then
    verification
  fi
fi

#################################################
# Print Log

if [ "x$action" == "xlog" ]; then
  print_log vc_serv_file vc_cli_file
fi

#################################################
# Cleanup

if [ "x$action" == "xcleanup"  ]; then
  cleanup vc_serv_file vc_cli_file
fi

exit 0