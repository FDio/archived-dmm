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

FILE(GLOB_RECURSE COMMON common/*.c)
FILE(GLOB INIT init/*.c)
FILE(GLOB_RECURSE IPC ipc/*.c)
FILE(GLOB LOG log/*.c)
FILE(GLOB SNAPSHOT snapshot/*.c)
FILE(GLOB MAINTAIN maintain/*.c)
FILE(GLOB EVENT event/epoll/*.c)
FILE(GLOB HAL hal/*.c)
FILE(GLOB RD  rd/*.c)
FILE(GLOB RES res/*.c)
FILE(GLOB_RECURSE MEM mem/*.c)
FILE(GLOB RING ring/*.c)
FILE(GLOB DFX dfx/*.c)
INCLUDE_DIRECTORIES(
    nStackFw
    PRIVATE
    ${JSON_C_SRC}
    ${GLOG_SRC}
	${CMAKE_SOURCE_DIR}/src/include
    ${CMAKE_SOURCE_DIR}/src/nSocket/nstack
    ${CMAKE_SOURCE_DIR}/src/nSocket/include
    ${CMAKE_CURRENT_LIST_DIR}/ipc/mgr_com
    ${CMAKE_CURRENT_LIST_DIR}/include/common/
    ${CMAKE_CURRENT_LIST_DIR}/include/common/generic
    ${CMAKE_CURRENT_LIST_DIR}/common/base/liblinuxapi
	${CMAKE_CURRENT_LIST_DIR}/dfx
    ${CMAKE_CURRENT_LIST_DIR}/mem/basic_mem
	${CMAKE_SOURCE_DIR}/src/framework/event/epoll
)
ADD_LIBRARY(nStackFw STATIC ${COMMON} ${INIT} ${IPC} ${LOG} ${SNAPSHOT} ${MAINTAIN} ${TRACEING} ${EVENT} ${RES} ${RD} ${HAL} ${MEM} ${RING} ${DFX})
ADD_DEPENDENCIES(nStackFw JSON GLOG DPDK)
