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

#ifndef _FW_MT_CONFIG_H
#define _FW_MT_CONFIG_H

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#include "nsfw_maintain_api.h"

/* socket num config */
#define SOCKET_NUM_PER_THREAD       1024        /* socket number per thread */

#define APP_POOL_NUM                 32

#define DEF_HAL_RX_RING_SIZE        2048

/* stackx recv ring size config */
#define DEF_SPL_MAX_RING_SIZE      1024

/* pcb number config */
#define DEF_TCP_PCB_NUM              4096       /* tcp pcb number, per thread */
#define DEF_UDP_PCB_NUM              512        /* udp pcb number, per thread */
#define DEF_RAW_PCB_NUM              600        /* raw pcb number, per thread */

#define DEF_ARP_QUEUE_NUM           300

/* tx mbuf pool size config */
#define DEF_TX_MBUF_POOL_SIZE      (4*POOL_RING_BASE_SIZE)

/* rx mbuf pool size config */
#define DEF_RX_MBUF_POOL_SIZE      (8*POOL_RING_BASE_SIZE)      /* rx mbuf pool size */

/* stackx internal msg number config */
#define DEF_TX_MSG_POOL_SIZE        (DEF_TX_MBUF_POOL_SIZE*APP_POOL_NUM + MAX_VF_NUM*DEF_RX_MBUF_POOL_SIZE + DEF_RING_BASE_SIZE)

/* mbox ring size config */
#define DEF_MBOX_RING_SIZE          (DEF_RING_BASE_SIZE/4)

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
