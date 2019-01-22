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
#PROJECT(leibniz)

#SET(CMAKE_C_COMPILER "gcc")
INCLUDE_DIRECTORIES(lb)
ADD_DEFINITIONS(-O2 -g -fPIC -m64 -pthread -Werror)
ADD_DEFINITIONS(-D_GNU_SOURCE -U_FORTIFY_SOURCE -DDEBUG)
LINK_LIBRARIES(-pthread -lrt -g -m64)
LINK_LIBRARIES(-L../../../../build -llb)
LINK_LIBRARIES(-L../../../../release/lib64 -lnStackAPI)

FILE(GLOB lb_src lb/*.c)
ADD_LIBRARY(lb STATIC ${lb_src})

#SET(BINS lp bps cps ip6 te)
LIST(APPEND BINS "lp")
LIST(APPEND BINS "bps")
LIST(APPEND BINS "cps")
LIST(APPEND BINS "ip6")
LIST(APPEND BINS "te")
MESSAGE(STATUS "" ${BINS})
FOREACH(one ${BINS})
	FILE(GLOB ${one}_src ${one}/*.c)
	ADD_EXECUTABLE(${one} ${${one}_src})
	ADD_DEPENDENCIES(${one} lb)
	ADD_DEPENDENCIES(${one} nStackAPI)
ENDFOREACH(one)

ADD_EXECUTABLE(ft ft.c)
ADD_DEPENDENCIES(ft lb)
ADD_DEPENDENCIES(ft nStackAPI)
IF(EXISTS ${nslib})
  MESSAGE(STATUS "! set nstack lib directory ${NSLIb}")
  LINK_LIBRARIES(-Wl, --whole-archive -L${NSLIB} -lnStackAPI -lrtp_mem -lsecurec -Wl,--no-whole-archive)
  FOREACH(one ${BINS})
  	ADD_EXECUTABLE(ns${one} ${${one}_src})
  	ADD_DEPENDENCIES(ns${one} lb)
  ENDFOREACH(one)
ENDIF()
