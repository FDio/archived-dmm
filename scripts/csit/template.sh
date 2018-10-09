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

#################################################
# Setup preparation

if [ "x$action" == "xsetup" ]; then
   #Handle setup preparation here
   echo "performing setup"
fi

#################################################
# Execution

if [ "x$action" == "xrun" ]; then
    # Call your executables here to run the test case
    if [ "x$node" == "x0" ]; then
    #call server executable
    echo "server execution "
    elif [ "x$node" == "x1" ]; then
    #call client executable
    echo "client execution"
    fi
fi

#################################################
# Verification

if [ "x$action" == "xverify" ]; then
  if [ "x$node" == "x1" ]; then
    #Handle client verification
    if [ $? == 0 ]; then
      echo "DMM_CSIT_TEST_PASSED" #must echo this
    else
      echo "DMM_CSIT_TEST_FAILED"
    fi
  elif [ "x$node" == "x0" ]; then
    #Handle server verification
    if [ $? == 0 ]; then
      echo "DMM_CSIT_TEST_PASSED" #must echo this
    else
      echo "DMM_CSIT_TEST_FAILED"
    fi
  fi
fi

#################################################
# Print Log

if [ "x$action" == "xlog" ]; then
 #Handle print log
 echo "DMM logs"
fi

#################################################
# Cleanup

if [ "x$action" == "xcleanup"  ]; then
  #Handle cleanup
  echo "performing cleanup"
fi

exit 0