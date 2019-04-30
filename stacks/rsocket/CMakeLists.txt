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
CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
#PROJECT(nStack)
SET(CMAKE_SKIP_RPATH TRUE)
SET(CMAKE_C_COMPILER "gcc")
SET(OS_RELEASE "" CACHE STRING "User-specified OS release.")
SET(EXECUTABLE_PATH ${CMAKE_CURRENT_LIST_DIR}/../../release/bin)
SET(LIB_PATH_STATIC ${CMAKE_SOURCE_DIR}/build)
SET(LIB_PATH_SHARED ${CMAKE_CURRENT_LIST_DIR}/../../release/lib64)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_PATH_STATIC})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_PATH})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_PATH_SHARED})

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -fPIE -pie -fPIC -m64 -mssse3 -std=gnu89")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wshadow -Wfloat-equal -Wformat=2")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector -fstack-protector-all")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,relro,-z,now -Wl,--disable-new-dtags")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack -mcmodel=medium")


SET(rdmacm_dir librdmacm-1.1.0)
SET(dmm_inc_dir ${CMAKE_CURRENT_LIST_DIR}/../../release/include/)
SET(DMM_REL_INC_DIR ${dmm_inc_dir})
SET(dmm_src_inc_dir ${CMAKE_SOURCE_DIR}/src/include/)
SET(RSOCKET_DEBUG 1)

########################
SET(rdmacm_url https://github.com/ofiwg/librdmacm/archive/v1.1.0.tar.gz)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/v1.1.0.tar.gz")
    SET(RDMA_DOWNLOAD_CMD tar -xvf ${CMAKE_CURRENT_LIST_DIR}/v1.1.0.tar.gz)
else()
    SET(RDMA_DOWNLOAD_CMD wget --no-check-certificate ${rdmacm_url} && tar -xvf ${CMAKE_CURRENT_LIST_DIR}/v1.1.0.tar.gz)
endif()
INCLUDE(ExternalProject)
ExternalProject_Add(
    rdmacm
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/${rdmacm_dir}
    DOWNLOAD_DIR        ${CMAKE_CURRENT_LIST_DIR}
    DOWNLOAD_COMMAND    ${RDMA_DOWNLOAD_CMD}
    PATCH_COMMAND       patch -p1 -i ../rsocket.patch
    CONFIGURE_COMMAND   ./autogen.sh && ./configure dmm_inc_dir=${DMM_REL_INC_DIR} RSOCKET_DEBUG=${RSOCKET_DEBUG}
    BUILD_IN_SOURCE     1
    BUILD_COMMAND       make
    INSTALL_COMMAND     cp -f libdmm_rdmacm.a ${LIB_PATH_STATIC}/
)

########################

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -fPIC -m64 -pthread")

ADD_LIBRARY(dmm_rsocket  SHARED src/rsocket_adpt.c)

ADD_DEFINITIONS(-D_GNU_SOURCE -DRSOCKET_DEBUG=${RSOCKET_DEBUG})

INCLUDE_DIRECTORIES(
    ${DMM_REL_INC_DIR} ${dmm_src_inc_dir}
)
INCLUDE_DIRECTORIES(./src ${rdmacm_dir} ${rdmacm_dir}/include ${rdmacm_dir}/src)

TARGET_LINK_LIBRARIES(dmm_rsocket
    -Wl,--whole-archive
    ${LIB_PATH_STATIC}/libdmm_rdmacm.a
    -Wl,--no-whole-archive
    ibverbs pthread dl rt
)

ADD_DEPENDENCIES(dmm_rsocket rdmacm)
