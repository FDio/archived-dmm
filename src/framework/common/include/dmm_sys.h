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
#ifndef _DMM_SYS_H_
#define _DMM_SYS_H_

#include <sys/types.h>
#include <unistd.h>

#define SYS_HOST_INITIAL_PID 1

pid_t sys_get_hostpid_from_file (pid_t pid);
pid_t get_hostpid_from_file (pid_t pid);
void get_exec_name_by_pid (pid_t pid, char *task_name, int task_name_len);

pid_t sys_get_hostpid_from_file (pid_t pid);

static inline pid_t
get_sys_pid ()
{
  extern pid_t g_sys_host_pid;
  if (SYS_HOST_INITIAL_PID == g_sys_host_pid)
    (void) sys_get_hostpid_from_file (getpid ());
  return g_sys_host_pid;
}

pid_t updata_sys_pid ();

#define dmm_spin_lock_pid(spinlock) dmm_spin_lock_with((spinlock), get_sys_pid())
#define dmm_spin_trylock_pid(spinlock) dmm_spin_trylock_with((spinlock), get_sys_pid())

#endif
