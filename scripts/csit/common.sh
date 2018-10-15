#!/bin/bash

set -x
setup_preparation(){
  ip addr
  lspci -nn
  lsmod | grep uio
  bash $CSIT_SCRIPT_DIR/kill_given_proc.sh $1
  bash $CSIT_SCRIPT_DIR/setup_hugepage.sh

  cp -f $DMM_SCRIPT_DIR/prep_app_test.sh $DMM_SCRIPT_DIR/prep_app_test_csit.sh
  sed -i 's!.*check_hugepage.sh!#skip hugepage check!1' $DMM_SCRIPT_DIR/prep_app_test_csit.sh
  sed -i 's!enp0s8!'$ifname'!1' $DMM_SCRIPT_DIR/prep_app_test_csit.sh
  bash -x $DMM_SCRIPT_DIR/prep_app_test_csit.sh
}

setup_preparation_lwip(){
  bash $CSIT_SCRIPT_DIR/kill_given_proc.sh $1
  bash $CSIT_SCRIPT_DIR/setup_hugepage.sh
  cat /proc/meminfo
  cp -f $VAG_DIR/start_nstackMain.sh $VAG_DIR/start_nstackMain_csit.sh
  sed -i 's!.*check_hugepage.sh!#skip hugepage check!1' $VAG_DIR/start_nstackMain_csit.sh
  sed -i 's!ifname=.*!ifname='$ifname'!1' $VAG_DIR/start_nstackMain_csit.sh
  sudo  LD_LIBRARY_PATH=${LIB_PATH} bash $VAG_DIR/start_nstackMain_csit.sh  || exit 1
  sleep 5

  #after nstackmain
  echo "after nstackmain"
  ip addr
  lspci -nn
  lsmod | grep uio
  cat /proc/meminfo | grep Huge
  /tmp/dpdk/dpdk-18.02/usertools/dpdk-devbind.py --status
}


execution(){
  cd $APP_DIR
  ls -l
  if [ "x$node" == "x0" ]; then
  eval $1
  else
  eval $2
  fi
}

verification(){
  flag=0
  for var in "$@"
  do
    eval $var
    if [ $? != 0 ]; then
      flag=1
      break
    fi
  done
  if [ "x$flag" == "x0" ]; then
    echo "DMM_CSIT_TEST_PASSED"
  else
    echo "DMM_CSIT_TEST_FAILED"
  fi
}

print_log(){
  if [ "x$node" == "x0" ]; then
    cat $LOG_PATH/app_$1*.log
  elif [ "x$node" == "x1" ]; then
    cat $LOG_PATH/app_$2*.log
  fi
}

cleanup(){
  if [ "x$node" == "x0" ]; then
    bash $CSIT_SCRIPT_DIR/kill_given_proc.sh $1
    rm $LOG_PATH/app_$1*.log
  elif [ "x$node" == "x1" ]; then
    rm $LOG_PATH/app_$2*.log
  fi
}

cleanup_lwip(){
  if [ "x$node" == "x0" ]; then
    bash $CSIT_SCRIPT_DIR/kill_given_proc.sh $1
  fi
  sudo bash $APP_DIR/../release/stop_nstack.sh
  sudo rm $LOG_PATH/running.log
}
