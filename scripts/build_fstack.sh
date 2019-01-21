#!/bin/bash -x

#build F-stack dependencies
sudo apt-get -y install libnuma-dev
sudo apt-get -y install libssl-dev

#build F-stack
DMM_DIR=`dirname $(readlink -f $0)`/../
BUILD_DIR=${DMM_DIR}/build

cd ${BUILD_DIR}
sudo make dmm_fstack
if [ $? -eq 0 ]; then
    echo "fstack build has SUCCESS"
else
    echo "fstack build has FAILED"
    exit 1
fi
echo "fstack build finished"
