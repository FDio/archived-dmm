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

#include "stackx_epoll_api.h"
#include "stackx_spl_share.h"
#include "common_pal_bitwide_adjust.h"
#include "nstack_dmm_adpt.h"
#include "nstack_epoll_api.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif /* _cplusplus */

void epoll_triggle_event_from_api(sbr_socket_t * sock, int op)
{
    struct spl_netconn *conn = sbr_get_conn(sock);
    void *epInfo = ADDR_SHTOL(conn->epInfo);
    //NSPOL_LOGDBG(SOCKETS_DEBUG, "enter]fd=%d,op=%d", sock, op);
    switch (op)
    {
        case EPOLL_API_OP_RECV:
            break;
        case EPOLL_API_OP_SEND:
            if (conn->epoll_flag && epInfo)
            {
                NSTACK_EPOLL_EVENT_ADD(epInfo, EPOLLOUT, EVENT_INFORM_APP);
            }
            break;
        case EPOLL_API_OP_STACK_RECV:
            if (conn->epoll_flag && epInfo)
            {
                NSTACK_EPOLL_EVENT_ADD(epInfo, EPOLLIN, EVENT_INFORM_APP);
            }
            break;
        default:
            break;
    }
    return;
}

/*
 *    This function will be registed to application
 *    The context will be in the application
 */
void *stackx_eventpoll_triggle(sbr_socket_t * sock, int triggle_ops,
                               void *pdata, void *event)
{
    struct spl_netconn *conn = sbr_get_conn(sock);
    unsigned int events = 0;
    if (!conn)
    {
        NSPOL_LOGINF(SOCKETS_DEBUG, "get socket failed]fd=%d", sock->fd);
        return NULL;
    }

    NSPOL_LOGINF(SOCKETS_DEBUG,
                 "]fd=%d,triggle_ops=%d conn=%p pdata=%p", sock->fd,
                 triggle_ops, conn, pdata);
    /*
     *  sock->epoll_flag must be set before sock->rcvevent check.
     *  Consider this Scenario : 1) network stack has got one packet, but event_callback not called yet
     *                           2) Do epoll ctl add, then stackx triggle will check event, it will get 0
     *                           3) network stack call event_callback , it will check epoll_flag
     *  So, if epoll_flag not set before sock->rcvent check, neither of network stack and stackx triggle
     *  will add this event to epoll. because : for network stack, event_callback check epoll_flag fail
     *  for stackx triggle, event check fail.
     */
    if (nstack_ep_triggle_add == triggle_ops)
    {
        /*log info */
        conn->epInfo = pdata;
        __sync_fetch_and_add(&conn->epoll_flag, 1);
    }

    if ((!((conn->rcvevent == 0) && (sbr_get_fd_share(sock)->lastdata == 0)
           && (sbr_get_fd_share(sock)->lastoffset == 0))))
        events |= EPOLLIN;
    if (conn->sendevent)
        events |= EPOLLOUT;
    if (conn->errevent)
        events |= conn->errevent;

    switch (triggle_ops)
    {
        case nstack_ep_triggle_add:
        case nstack_ep_triggle_mod:
            *(int *) event = events;
            break;
        case nstack_ep_triggle_del:
            if (conn->epoll_flag > 0)
            {
                __sync_fetch_and_sub(&conn->epoll_flag, 1);
            }
            events = 0;
            break;
        default:
            return NULL;
    }
    return conn;
}

/*
 *    This function will be registed to application
 *    The context will be in the application
 *    RETURN VALUE : Event exists in current protocol
 */
int stackx_eventpoll_getEvt(sbr_socket_t * sock)
{
    struct spl_netconn *conn = sbr_get_conn(sock);
    int tevent = 0;
    if (!((conn->rcvevent == 0) && (sbr_get_fd_share(sock)->lastdata == 0)
          && (sbr_get_fd_share(sock)->lastoffset == 0)))
    {
        tevent |= EPOLLIN;
    }

    if (conn->sendevent)
    {
        tevent |= EPOLLOUT;
    }
    return tevent;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* _cplusplus */
