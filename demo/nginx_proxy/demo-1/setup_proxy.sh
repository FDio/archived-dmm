#########################################################################
# Copyright (c) 2018 Huawei Technologies Co.,Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#########################################################################
#!/bin/bash -x

set -x
sudo su
# Clean up build NGINX
cd /DMM/build/

#Download and compile NGINX
make NGINX
#Download and compile vpp-stack
make vpp-stack

#cp vpp libs
cp -r /DMM/stacks/vpp/vpp/build-root/install-vpp_debug-native/vpp/lib64/vpp_plugins /usr/lib/
mkdir -p /etc/vpp/
cp /DMM/demo/nginx_proxy/demo-1/startup.conf /etc/vpp/
cp /DMM/demo/nginx_proxy/demo-1/vpp_config /etc/vpp/
cd /DMM/stacks/vpp/vpp/build-root/install-vpp_debug-native/vpp/bin
#run vpp
sudo ifconfig enp0s9 down
./vpp -c /etc/vpp/startup.conf 

#cp nginx libs
cd /DMM/thirdparty/apps/nginx/release

# Move the conf file.
cp /DMM/demo/nginx_proxy/demo-1/module_config.json /DMM/thirdparty/apps/nginx/release/
cp /DMM/stacks/lwip_stack/app_conf/nStackConfig.json /DMM/thirdparty/apps/nginx/release/
cp /DMM/demo/nginx_proxy/demo-1/proxy_nginx.conf /DMM/thirdparty/apps/nginx/release/
cp /DMM/demo/nginx_proxy/demo-1/rd_config.json /DMM/thirdparty/apps/nginx/release/
mv /DMM/thirdparty/apps/nginx/release/proxy_nginx.conf /DMM/thirdparty/apps/nginx/release/nginx.conf

sleep 5

# Run nginx
cp /DMM/stacks/vpp/vpp/build-root/install-vpp_debug-native/vpp/lib64/libdmm_vcl.so /DMM/thirdparty/apps/nginx/release/
echo "export LD_LIBRARY_PATH=/DMM/stacks/lwip_stack/release/lib64"
echo "./nginx"

exit 0
