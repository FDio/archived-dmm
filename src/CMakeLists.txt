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

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_LIST_DIR}/framework/include
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_SOURCE_DIR}/platform/SecureC/include/
    ${CMAKE_SOURCE_DIR}/thirdparty/glog/glog-0.3.5/src/
)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -fPIC -m64 -mssse3 -std=gnu89")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wshadow -Wfloat-equal -Wformat=2")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,relro,-z,now -Wl,--disable-new-dtags")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack -mcmodel=medium")

SET(COMPLE_CONFIG ${CMAKE_SOURCE_DIR}/src/framework/include/common/compile_config.h)
ADD_DEFINITIONS(-include ${COMPLE_CONFIG})
ADD_DEFINITIONS(-D_GNU_SOURCE -D_FORTIFY_SOURCE=2)
LINK_DIRECTORIES(${LIB_PATH_SHARED} ${LIB_PATH_STATIC})
LINK_LIBRARIES(pthread dl)

ADD_SUBDIRECTORY(framework)
ADD_SUBDIRECTORY(nSocket)
