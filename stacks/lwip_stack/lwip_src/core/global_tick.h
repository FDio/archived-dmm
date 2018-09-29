/*
*
* Copyright (c) 2018 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#ifndef _GLOBAL_TICK_H_
#define _GLOBAL_TICK_H_

#define DFX_TMR_INTERVAL 60000  /*60 seconds */
typedef struct nstack_tick_info
{
  uint64_t *tick_ptr;           // tick from shared memory
  uint64_t interval;            // tick interval, only used in stack process
  /* tick reference, updated periodically and read in tcpip_thread only */
  struct timeval ref_time;      // ref tick time
  uint64_t ref_tick;            // ref tick
} nstack_tick_info_t;

#endif
