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

if(WITH_HAL_LIB)
else()
    SET(PAL_H_DIRECTORIES "/usr/include/dpdk/")
endif()


FILE(GLOB SBR *.c)
ADD_LIBRARY(lwip_dpdk SHARED ${SBR})
TARGET_LINK_LIBRARIES(lwip_dpdk -Wl,--whole-archive socket nsfw_mem -Wl,--no-whole-archive rte_eal rte_mempool rte_ring rte_mbuf)
ADD_DEPENDENCIES(lwip_dpdk socket DPDK)
INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${PAL_H_DIRECTORIES}
    ${CMAKE_CURRENT_LIST_DIR}/../../../../src/include/
    ${CMAKE_CURRENT_LIST_DIR}/../../../../src/framework/include/common/
    ${CMAKE_CURRENT_LIST_DIR}/../../../../src/framework/include/
    ${CMAKE_CURRENT_LIST_DIR}/../../../../stacks/lwip_stack/src/mem/include/
    ${CMAKE_CURRENT_LIST_DIR}/../../../../src/framework/include/common/generic/
    ${CMAKE_CURRENT_LIST_DIR}/../mem/nsfw_shmem/
    ${CMAKE_CURRENT_LIST_DIR}/../mem/nsfw_nshmem/
)
