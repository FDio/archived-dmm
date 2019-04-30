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

#ifndef _DMM_SPINLOCK_H_
#define _DMM_SPINLOCK_H_

#include "dmm_pause.h"
#include "pid_common.h"
#include "nsfw_branch_prediction.h"
#include "nstack_log.h"

#define DMM_SPINLOCK_MALLOC(sys_sem,count) \
{ \
    dmm_spin_init(&(sys_sem)); \
    /*not problem*/\
    if (!(count)) \
    /*not problem*/\
    { \
        dmm_spin_lock(&(sys_sem)); \
    } \
}

typedef struct
{
    volatile int lock;
} dmm_spinlock_t;

inline static void dmm_spin_init(dmm_spinlock_t * spinlock)
{
    spinlock->lock = 0;
}

static inline int dmm_spin_trylock_with(dmm_spinlock_t * spinlock, int value)
{
    return __sync_bool_compare_and_swap(&spinlock->lock, 0, value);
}

static inline void dmm_spin_lock_with(dmm_spinlock_t * spinlock, int value)
{
    while (!dmm_spin_trylock_with(spinlock, value))
    {
        DMM_PAUSE_WHILE(spinlock->lock);
    }
}

inline static void dmm_spin_lock(dmm_spinlock_t * spinlock)
{
    dmm_spin_lock_with(spinlock, 1);
}

inline static int dmm_spin_trylock(dmm_spinlock_t * spinlock)
{
    return dmm_spin_trylock_with(spinlock, 1);
}

//replace sys_sem_s_signal
inline static void dmm_spin_unlock(dmm_spinlock_t * spinlock)
{
    __sync_lock_release(&spinlock->lock);
}

//replace sys_arch_trylock_with_pid
static inline int dmm_spin_trylock_with_pid(dmm_spinlock_t * sem, int t_us)
{
    if (unlikely(SYS_HOST_INITIAL_PID == g_sys_host_pid))
        (void) sys_get_hostpid_from_file(getpid());

    if (dmm_spin_trylock_with(sem, g_sys_host_pid))
    {
        return 0;
    }

    while (t_us > 0)
    {
        --t_us;
        sys_sleep_ns(0, 1000);
        if (dmm_spin_trylock_with(sem, g_sys_host_pid))
        {
            return 0;
        }
    }

    return -1;
}

//replace sys_arch_sem_trywait_s_v2
static inline int dmm_spinlock_trylock(dmm_spinlock_t * sl)
{
    int lockval = 1;

    asm volatile ("xchg %[locked], %[lockval]":[locked] "=m"(sl->lock),
                  [lockval] "=q"(lockval):"[lockval]"(lockval):"memory");

    return lockval == 0;
}

static inline u32_t dmm_spin_lock_with_pid(dmm_spinlock_t * sem)
{
    if (SYS_HOST_INITIAL_PID == g_sys_host_pid)
    {
        (void) sys_get_hostpid_from_file(getpid());
    }
    dmm_spin_lock_with(sem, g_sys_host_pid);
    return 0;
}
#endif /* #ifndef _DMM_SPINLOCK_H_ */
