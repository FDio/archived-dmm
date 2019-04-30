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
PROJECT(nStack)
SET(CMAKE_SKIP_RPATH TRUE)
SET(CMAKE_C_COMPILER "gcc")
SET(OS_RELEASE "" CACHE STRING "User-specified OS release.")

SET(EXECUTABLE_PATH ${CMAKE_CURRENT_LIST_DIR}/release/bin)
SET(LIB_PATH_STATIC ${PROJECT_BINARY_DIR})
SET(LIB_PATH_SHARED ${CMAKE_CURRENT_LIST_DIR}/../../release/lib64)

SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_PATH_STATIC})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_PATH})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_PATH_SHARED})
ADD_SUBDIRECTORY(perf-test)
ADD_SUBDIRECTORY(func-test)
