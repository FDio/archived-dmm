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

#define __NSTACK_RD_IP6_H

int nstack_rd_ip6_data_cpy(void *destdata, void *srcdata);
int nstack_rd_ip6_item_insert(nstack_rd_list * hlist, void *rditem);
int nstack_rd_ip6_item_find(nstack_rd_list * hlist, void *rdkey,
                            void *outitem);
int nstack_rd_ip6_item_age(nstack_rd_list * hlist);
void nstack_rd_ip6_item_clean(nstack_rd_list * hlist);
int nstack_rd_ip6_spec(void *rdkey);
