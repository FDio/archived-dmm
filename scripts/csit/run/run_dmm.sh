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
  ip addr
  lspci -nn
  lsmod | grep uio
  bash $CSIT_SCRIPT_DIR/kill_given_proc.sh vs_epoll
  bash $CSIT_SCRIPT_DIR/setup_hugepage.sh

  cp -f $DMM_SCRIPT_DIR/prep_app_test.sh $DMM_SCRIPT_DIR/prep_app_test_csit.sh
  sed -i 's!.*check_hugepage.sh!#skip hugepage check!1' $DMM_SCRIPT_DIR/prep_app_test_csit.sh
  sed -i 's!enp0s8!'$ifname'!1' $DMM_SCRIPT_DIR/prep_app_test_csit.sh
  bash -x $DMM_SCRIPT_DIR/prep_app_test_csit.sh
fi

#################################################
# Execution

if [ "x$action" == "xrun" ]; then
  cd $APP_DIR
  ls -l
  #only for kernal stack
  if [ "x$node" == "x0" ]; then
  sudo LD_LIBRARY_PATH=${LIB_PATH} ./vs_epoll -p 20000 -d ${dut2_if_ip} -a 10000 -s ${dut1_if_ip} -l 200 -t 50000 -i 0 -f 1 -r 20000 -n 1 -w 10 -u 10000 -e 10 -x 1
  else
  sudo LD_LIBRARY_PATH=${LIB_PATH} ./vc_common -p 20000 -d ${dut1_if_ip} -a 10000 -s ${dut2_if_ip} -l 200 -t 50000 -i 0 -f 1 -r 20000 -n 1 -w 10 -u 10000 -e 10 -x 1
  fi
fi

#################################################
# Verification

if [ "x$action" == "xverify" ]; then
  if [ "x$node" == "x1" ]; then
    sudo cat $RUN_DIR/log_$(basename $0).txt | grep "send 50000"
    if [ $? == 0 ]; then
      echo "DMM_CSIT_TEST_PASSED"
    else
      echo "DMM_CSIT_TEST_FAILED"
    fi
  elif [ "x$node" == "x0" ]; then
    echo "DMM_CSIT_TEST_PASSED"
  fi
fi

#################################################
# Print Log

if [ "x$action" == "xlog" ]; then
  echo "print log"
fi

#################################################
# Cleanup

if [ "x$action" == "xcleanup"  ]; then
  if [ "x$node" == "x0" ]; then
    bash $CSIT_SCRIPT_DIR/kill_given_proc.sh vs_epoll
  fi
fi

exit 0