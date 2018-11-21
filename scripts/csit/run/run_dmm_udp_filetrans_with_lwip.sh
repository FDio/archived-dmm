#!/bin/bash

set -x

#################################################
# Store arguments values
# verify, log, cleanup actions gets first two arguments[action, node]

action=$1           #action: [setup, run, verify, cleanup]
node=$2             #node: [0 - dut1 node, 1 - dut2 node]
ifname=$3           #dut1 interface name(when node is 0)/dut2 interface name(when node is 1)
dut1_if_ip=$4       #dut1 interface ip
dut2_if_ip=$5       #dut2 interface ip

#################################################
# Get path details

RUN_DIR=`dirname $(readlink -f $0)`
CSIT_SCRIPT_DIR=$RUN_DIR/..
ROOTDIR=$CSIT_SCRIPT_DIR/../../../
APP_DIR=${ROOTDIR}/dmm/stacks/lwip_stack/app_test/
LIB_PATH=${APP_DIR}/../release/lib64/
VAG_DIR=${ROOTDIR}/dmm/stacks/lwip_stack/vagrant
LOG_PATH=/var/log/nStack
DMM_SCRIPT_DIR=$ROOTDIR/dmm/scripts

source $DMM_SCRIPT_DIR/csit/common.sh
#################################################
# Setup preparation

if [ "x$action" == "xsetup" ]; then
  setup_preparation_lwip vc_serv_file
  sudo sed -i '23s/kernel/lwip/' $APP_DIR/rd_config.json
fi

#################################################
# Execution

if [ "x$action" == "xrun" ]; then
  execution "sudo cp -f $DMM_SCRIPT_DIR/csit/file.txt . ;sudo LD_LIBRARY_PATH=${LIB_PATH} ./vc_serv_file udp ${dut1_if_ip} 1236 file.txt 256" \
    "sudo cp -f $DMM_SCRIPT_DIR/csit/file.txt . ;sudo LD_LIBRARY_PATH=${LIB_PATH} ./vc_cli_file udp ${dut1_if_ip} 1236 ${dut2_if_ip} file.txt receive_file.txt 256"
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
  cat $LOG_PATH/running.log
fi

#################################################
# Cleanup

if [ "x$action" == "xcleanup"  ]; then
  cleanup_lwip vc_serv_file
fi

exit 0
