#########################################################################
#
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
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -fPIC -m64 -mssse3 -std=gnu89")

LINK_DIRECTORIES(${LIB_PATH_SHARED} ${LIB_PATH_STATIC})

ADD_EXECUTABLE(vtcp_fork_server tcpserver.c)
TARGET_LINK_LIBRARIES(vtcp_fork_server libnStackAPI.so -lpthread -lrt)

ADD_EXECUTABLE(vtcp_client tcpclient.c)
TARGET_LINK_LIBRARIES(vtcp_client libnStackAPI.so -lpthread -lrt)

ADD_EXECUTABLE(ktcp_fork_server tcpserver.c)
TARGET_LINK_LIBRARIES(ktcp_fork_server pthread)

ADD_EXECUTABLE(ktcp_client tcpclient.c)
TARGET_LINK_LIBRARIES(ktcp_client pthread)
