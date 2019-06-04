#!/bin/bash

DIR=`S=\`readlink "$0"\`; [ -z "$S" ] && S=$0; dirname $S`
cd $DIR

. ./nstack_var.sh
. ./nstack_fun.sh

########################################################
# check parameter

log $LINENO "dir=$DIR"

########################################################
# init netrork:unbind->/* modprobe uio->insmod igb_uio */->bind
init_network

########################################################
# start nstack main
CORE_MASK=1
log $LINENO "start run nstackmain"
log $LINENO "COREMASK=$CORE_MASK, HUGE_DIR=$1, MEM_SIZE=$2, RTP_CORE_MASK=$RTP_CORE_MASK, SLEEP_INTERVAL=$SLEEP_INTERVAL, BIND_CPU=$BIND_CPU"
log $LINENO "VDEV=$VDEV, NO_PCI=$NO_PCI"

run_nStackMain $CORE_MASK $1 $2 $RTP_CORE_MASK $SLEEP_INTERVAL $BIND_CPU $3 $4

exit 0
