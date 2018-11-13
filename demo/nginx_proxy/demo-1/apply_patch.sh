#!/bin/bash -x
sudo  apt-get install patch -y
cd /DMM/src/
sudo patch -p2 -i /DMM/demo/nginx_proxy/demo-1/demo_2stack.patch
if [ $? -ne 0 ]; then
    echo "Patch Apply failed. Downlaod correct commit. Check README for details."
    exit -1
fi
cd -
