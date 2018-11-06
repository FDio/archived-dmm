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

# Download nginx
cd /NGINX
wget http://nginx.org/download/nginx-1.14.0.tar.gz
tar -zxf  nginx-1.14.0.tar.gz

#install supportive softwares
apt-get install -yq libpcre3 libpcre3-dev zlibc zlib1g zlib1g-dev

# Compile nginx
cd nginx-1.14.0
./configure
make
make install

# Move the conf file.
cd /usr/local/nginx/sbin
cp -r * /usr/local/sbin
cp /NGINX/upstream_nginx.conf /usr/local/nginx/conf/
mv /usr/local/nginx/conf/upstream_nginx.conf /usr/local/nginx/conf/nginx.conf

# Run nginx

cd /usr/local/sbin
./nginx
echo "hi"
exit 0

