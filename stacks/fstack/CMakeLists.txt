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

SET(fstack_dir f-stack-1.12)
SET(dpdk_target x86_64-native-linuxapp-gcc)
SET(dmm_inc_dir ${DMM_REL_INC_DIR})


SET(fstack_url https://github.com/F-Stack/f-stack/archive/v1.12.tar.gz)

INCLUDE(ExternalProject)
ExternalProject_Add(
    fstack
    URL                 ${fstack_url}
    TLS_VERIFY          false
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/${fstack_dir}
    DOWNLOAD_DIR        ${CMAKE_CURRENT_LIST_DIR}
    BUILD_IN_SOURCE     1
    PATCH_COMMAND       patch -p1 -i ../fstack.patch
    CONFIGURE_COMMAND   make -C dpdk config T=${dpdk_target}
                            build O=${dpdk_target} EXTRA_CFLAGS=-fPIC
    BUILD_COMMAND       make -C lib "CONF_CFLAGS=-fPIC -g"
    INSTALL_COMMAND     ""
)
set_target_properties(fstack PROPERTIES EXCLUDE_FROM_ALL TRUE)

#####################################################################

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -fPIC -m64 -pthread")

LINK_DIRECTORIES(${fstack_dir}/lib ${fstack_dir}/dpdk/${dpdk_target}/lib)
ADD_LIBRARY(dmm_fstack  SHARED src/fstack_adpt.c)

ADD_DEFINITIONS(-D_GNU_SOURCE)

INCLUDE_DIRECTORIES(${DMM_REL_INC_DIR})
INCLUDE_DIRECTORIES(${fstack_dir}/lib)

TARGET_LINK_LIBRARIES(dmm_fstack
    -Wl,--whole-archive     -lfstack -ldpdk
    -Wl,--no-whole-archive  -lrt -lm -ldl -lcrypto -pthread -lnuma
)

ADD_DEPENDENCIES(dmm_fstack fstack post-compile)

set_target_properties(dmm_fstack PROPERTIES EXCLUDE_FROM_ALL TRUE)
