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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>          /* sys/types.h */
#include <sys/stat.h>           /* sys/stat.h  */
#include <fcntl.h>              /* fcntl.h     */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>              /* errno.h     */
#include "json.h"
#include "nsfw_base_linux_api.h"
#include "nstack_info_parse.h"
#include "nstack_rd_api.h"
#include "nstack_rd_priv.h"

/*get string value*/
#define NSTACK_JSON_PARSE_STRING(obj, name, lent, result, index) do { \
     struct json_object* temp_obj1 = NULL; \
     (void)json_object_object_get_ex((obj), (name), &temp_obj1);  \
     if (temp_obj1)  \
     {  \
        const char *temp_value1 = json_object_get_string(temp_obj1); \
        if (!temp_value1) \
        { \
            NSSOC_LOGERR("can't get value from %s index:%d", name, (index));  \
            goto RETURN_ERROR; \
        }  \
        (void)strncpy_s((result), (lent), temp_value1, (lent)-1);  \
     }  \
     else \
     {  \
        NSSOC_LOGERR("can't get obj from %s index:%d", name, (index));  \
        goto RETURN_ERROR; \
     }  \
} while ( 0 );

/*get int value*/
#define NSTACK_JSON_PARSE_INT(obj, name, lent, result, index) do { \
     struct json_object* temp_obj1 = NULL; \
     (void)json_object_object_get_ex((obj), (name), &temp_obj1);  \
     if (temp_obj1)  \
     {  \
        const char *temp_value1 = json_object_get_string(temp_obj1); \
        if (!temp_value1) \
        { \
            NSSOC_LOGERR("can't get value from %s index:%d", name, (index));  \
            goto RETURN_ERROR; \
        }  \
        (result) = atoi(temp_value1);  \
     }  \
     else \
     {  \
	if (strcmp(name, "deploytype") == 0 || strcmp(name, "stackid") == 0)  \
        { \
           NSSOC_LOGERR("can't get obj from %s index:%d", name, (index));  \
        }  \
        else\
        { \
           NSSOC_LOGWAR("can't get obj from %s index:%d", name, (index));  \
        }  \
     }  \
} while ( 0 );

/* load default config */
static int load_default_module()
{
    if (EOK !=
        strcpy_s(g_nstack_module_desc[0].modName, NSTACK_MODULE_NAME_MAX,
                 RD_KERNEL_NAME))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NSTACK_RETURN_FAIL;
    }
    if (EOK !=
        strcpy_s(g_nstack_module_desc[0].register_fn_name,
                 NSTACK_MODULE_NAME_MAX, "kernel_stack_register"))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NSTACK_RETURN_FAIL;
    }
    if (EOK !=
        strcpy_s(g_nstack_module_desc[0].libPath, NSTACK_MODULE_NAME_MAX,
                 "./"))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NSTACK_RETURN_FAIL;
    }
    g_nstack_module_desc[0].deploytype = NSTACK_MODEL_TYPE1;
    g_nstack_module_desc[0].libtype = NSTACK_LIB_LOAD_STATIC;
    g_nstack_module_desc[0].default_stack = 1;
    g_nstack_module_desc[0].priority = 0;
    g_nstack_module_desc[0].maxfdid = 8191;
    g_nstack_module_desc[0].minfdid = 0;
    g_nstack_module_desc[0].modInx = 0;

    if (EOK !=
        strcpy_s(g_nstack_module_desc[1].modName, NSTACK_MODULE_NAME_MAX,
                 "stackpool"))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NSTACK_RETURN_FAIL;
    }
    if (EOK !=
        strcpy_s(g_nstack_module_desc[1].register_fn_name,
                 NSTACK_MODULE_NAME_MAX, "nstack_stack_register"))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NSTACK_RETURN_FAIL;
    }
    if (EOK !=
        strcpy_s(g_nstack_module_desc[1].libPath, NSTACK_MODULE_NAME_MAX,
                 "libnstack.so"))
    {
        NSSOC_LOGERR("strcpy_s failed!");
        return NSTACK_RETURN_FAIL;
    }
    g_nstack_module_desc[1].deploytype = NSTACK_MODEL_TYPE3;
    g_nstack_module_desc[1].libtype = NSTACK_LIB_LOAD_DYN;
    g_nstack_module_desc[1].default_stack = 0;
    g_nstack_module_desc[1].priority = 0;
    g_nstack_module_desc[1].maxfdid = 8192;
    g_nstack_module_desc[1].minfdid = 0;
    g_nstack_module_desc[1].modInx = 1;

    g_module_num = 2;
    return NSTACK_RETURN_OK;
}

/*parse module cfg*/
static int parse_module_cfg(char *param)
{
    struct json_object *obj = json_tokener_parse(param);
    struct json_object *module_list_obj = NULL;
    struct json_object *module_obj = NULL;
    struct json_object *temp_obj = NULL;
    const char *default_name = NULL;
    const char *temp_value = NULL;
    int module_num = 0;
    int ret = NSTACK_RETURN_FAIL;
    int index = 0;              /* local variable:index */
    int icnt = 0;

    if (!obj)
    {
        NSSOC_LOGERR("json parse fail");
        return NSTACK_RETURN_FAIL;
    }

    (void) memset_s(&g_nstack_module_desc[0], sizeof(g_nstack_module_desc),
                    0, sizeof(g_nstack_module_desc));

    (void) json_object_object_get_ex(obj, "default_stack_name", &temp_obj);
    if (!temp_obj)
    {
        NSSOC_LOGERR("can't get module_list");
        goto RETURN_ERROR;
    }

    default_name = json_object_get_string(temp_obj);

    (void) json_object_object_get_ex(obj, "module_list", &module_list_obj);
    if (!module_list_obj)
    {
        NSSOC_LOGERR("can't get module_list");
        goto RETURN_ERROR;
    }
    module_num = json_object_array_length(module_list_obj);
    if ((module_num <= 0) || (module_num >= NSTACK_MAX_MODULE_NUM))
    {
        NSSOC_LOGERR("get module number:%d fail", module_num);
        goto RETURN_ERROR;
    }

    for (index = 0; index < module_num; index++)
    {
        module_obj = json_object_array_get_idx(module_list_obj, index);
        if (module_obj)
        {
            NSTACK_JSON_PARSE_STRING(module_obj, "stack_name",
                                     NSTACK_MODULE_NAME_MAX,
                                     &(g_nstack_module_desc[icnt].modName
                                       [0]), index);
            NSTACK_JSON_PARSE_STRING(module_obj, "function_name",
                                     NSTACK_MODULE_NAME_MAX,
                                     &(g_nstack_module_desc
                                       [icnt].register_fn_name[0]), index);
            NSTACK_JSON_PARSE_STRING(module_obj, "libname",
                                     NSTACK_MODULE_NAME_MAX,
                                     &(g_nstack_module_desc[icnt].libPath
                                       [0]), index);

            (void) json_object_object_get_ex(module_obj, "loadtype",
                                             &temp_obj);
            if (temp_obj)
            {
                temp_value = json_object_get_string(temp_obj);
                if (temp_value && (strcmp(temp_value, "static") == 0))
                {
                    g_nstack_module_desc[icnt].libtype =
                        NSTACK_LIB_LOAD_STATIC;
                }
                else
                {
                    g_nstack_module_desc[icnt].libtype = NSTACK_LIB_LOAD_DYN;
                }
            }
            else
            {
                if (strcmp
                    (g_nstack_module_desc[icnt].modName, RD_KERNEL_NAME) == 0)
                {
                    g_nstack_module_desc[icnt].libtype =
                        NSTACK_LIB_LOAD_STATIC;
                }
                else
                {
                    g_nstack_module_desc[icnt].libtype = NSTACK_LIB_LOAD_DYN;
                }
                NSSOC_LOGWAR("can't get the value of loadtype for module:%s",
                             g_nstack_module_desc[icnt].modName);
            }
            NSTACK_JSON_PARSE_INT(module_obj, "deploytype",
                                  NSTACK_MODULE_NAME_MAX,
                                  g_nstack_module_desc[icnt].deploytype,
                                  index);
            g_nstack_module_desc[icnt].maxfdid = 8191;
            NSTACK_JSON_PARSE_INT(module_obj, "maxfd",
                                  NSTACK_MODULE_NAME_MAX,
                                  g_nstack_module_desc[icnt].maxfdid, index);
            g_nstack_module_desc[icnt].minfdid = 0;
            NSTACK_JSON_PARSE_INT(module_obj, "minfd",
                                  NSTACK_MODULE_NAME_MAX,
                                  g_nstack_module_desc[icnt].minfdid, index);
            NSTACK_JSON_PARSE_INT(module_obj, "priorty",
                                  NSTACK_MODULE_NAME_MAX,
                                  g_nstack_module_desc[icnt].priority, index);
            NSTACK_JSON_PARSE_INT(module_obj, "stackid",
                                  NSTACK_MODULE_NAME_MAX,
                                  g_nstack_module_desc[icnt].modInx, index);
            if (icnt != g_nstack_module_desc[icnt].modInx)
            {
                NSSOC_LOGERR
                    ("stackid mismatch, expected:%d, actually given:%d", icnt,
                     g_nstack_module_desc[icnt].modInx);
                goto RETURN_ERROR;
            }
            if (0 == strcmp(g_nstack_module_desc[icnt].modName, default_name))
            {
                g_nstack_module_desc[icnt].default_stack = 1;
            }
            icnt++;
            g_module_num = icnt;
        }
    }
    ret = NSTACK_RETURN_OK;

  RETURN_ERROR:
    json_object_put(obj);
    return ret;
}

static int rd_do_parse(struct json_object *obj, const char *name, void *table)
{
    struct json_object *ip = NULL;
    struct json_object *proto = NULL;
    struct json_object *type = NULL;
    struct json_object *temp = NULL;
    struct json_object *o = NULL;
    int index = 0;              /* local variable:index */
    int ip_list_num = 0, type_list_num = 0, proto_list_num = 0;
    const char *ip_addr;
    char *sub = NULL;
    char addr[32];

    rd_ip_data ip_data;
    rd_type_data type_data;
    rd_proto_data proto_data;

    (void) json_object_object_get_ex(obj, "ip_route", &ip);
    (void) json_object_object_get_ex(obj, "protocol_route", &proto);
    (void) json_object_object_get_ex(obj, "type_route", &type);
    if (!ip && !proto && !type)
    {
        NSSOC_LOGERR("Error: no rd policies found!");
        return -1;
    }

    if (ip)
    {
        ip_list_num = json_object_array_length(ip);
    }
    if (type)
    {
        type_list_num = json_object_array_length(type);
    }
    if (proto)
    {
        proto_list_num = json_object_array_length(proto);
    }

    for (index = 0; index < ip_list_num; index++)
    {
        temp = json_object_array_get_idx(ip, index);
        if (temp)
        {
            ip_addr = json_object_get_string(temp);
            if (!ip_addr)
            {
                NSSOC_LOGERR("cannot get ip address at index:%d", index);
                return -1;
            }
            sub = strstr(ip_addr, "/");
            if (!sub)
            {
                NSSOC_LOGERR("cannot get masklen from %s", ip_addr);
                return -1;
            }
            if (EOK != memset_s(addr, sizeof(addr), 0, sizeof(addr)))
            {
                NSSOC_LOGERR("memset_s failed!");
                return -1;
            }
            if (EOK !=
                strncpy_s(addr, sizeof(addr), ip_addr,
                          (size_t) (sub - ip_addr)))
            {
                NSSOC_LOGERR("strncpy_s failed!");
                return -1;
            }
            ip_data.addr = inet_addr(addr);
            ip_data.masklen = atoi(sub + 1);    /* not deprecated */
            ip_data.resev[0] = 0;
            ip_data.resev[1] = 0;
            nstack_rd_ip_node_insert(name, &ip_data, table);
        }
    }

    for (index = 0; index < type_list_num; index++)
    {
        temp = json_object_array_get_idx(type, index);
        if (temp)
        {
            (void) json_object_object_get_ex(temp, "value", &o);
            if (!o)
            {
                NSSOC_LOGERR("no value specified of type_route index:%d",
                             index);
                return -1;
            }
            type_data.value = json_object_get_int(o);
            o = NULL;
            (void) json_object_object_get_ex(temp, "attr", &o);
            if (!o)
            {
                NSSOC_LOGERR("no attr specified of type_route index:%d",
                             index);
                return -1;
            }
            type_data.attr = json_object_get_int(o);
            type_data.reserved[0] = 0;
            type_data.reserved[1] = 0;
            type_data.reserved[2] = 0;
            type_data.reserved[3] = 0;
            nstack_rd_type_node_insert(name, &type_data, table);
            o = NULL;
        }
    }

    for (index = 0; index < proto_list_num; index++)
    {
        temp = json_object_array_get_idx(proto, index);
        if (temp)
        {
            (void) json_object_object_get_ex(temp, "value", &o);
            if (!o)
            {
                NSSOC_LOGERR("no value specified of protocol_route index:%d",
                             index);
                return -1;
            }
            proto_data.value = json_object_get_int(o);
            o = NULL;
            (void) json_object_object_get_ex(temp, "attr", &o);
            if (!o)
            {
                NSSOC_LOGERR("no attr specified of protocol_route index:%d",
                             index);
                return -1;
            }
            proto_data.attr = json_object_get_int(o);
            nstack_rd_proto_node_insert(name, &proto_data, table);
            o = NULL;
        }
    }

    return 0;
}

/*parse rd cfg*/
static int parse_rd_cfg(char *param, const char *name, void *table)
{
    struct json_object *obj = json_tokener_parse(param);
    struct json_object *module_obj = NULL;
    struct json_object *temp_obj = NULL;
    struct json_object *modules = NULL;
    const char *module_name;
    int total = 0;
    int i = 0;

    if ((!name) || (!obj))
    {
        NSSOC_LOGERR("json parse fail");
        return NSTACK_RETURN_FAIL;
    }

    (void) json_object_object_get_ex(obj, "modules", &modules);
    if (!modules)
    {
        NSSOC_LOGERR("can't get modules");
        goto RETURN_ERROR;
    }

    total = json_object_array_length(modules);
    if (total > NSTACK_MAX_MODULE_NUM)
    {
        NSSOC_LOGERR("too many modules specified!");
        goto RETURN_ERROR;
    }
    for (i = 0; i < total; i++)
    {
        module_obj = json_object_array_get_idx(modules, i);
        if (module_obj)
        {
            (void) json_object_object_get_ex(module_obj, "name", &temp_obj);
            if (temp_obj)
            {
                module_name = json_object_get_string(temp_obj);
                if (!module_name)
                {
                    NSSOC_LOGERR("cannot get module name at index:%d", i);
                    goto RETURN_ERROR;
                }
                if (strcmp(module_name, name) == 0)     // this is what we are looking for
                {
                    if (rd_do_parse(module_obj, module_name, table))
                    {
                        NSSOC_LOGERR("parse failed at index:%d", i);
                        goto RETURN_ERROR;
                    }
                    break;
                }
            }
        }
    }
    json_object_put(obj);
    return NSTACK_RETURN_OK;
  RETURN_ERROR:
    json_object_put(obj);
    return -1;
}

/*read json file, and return a buf, if return success, the caller need to free **buf*/
static int read_json_file(char *filename, char **buf)
{
    char *cfg_buf = NULL;
    int fp = 0;
    off_t file_len = 0;
    off_t buff_len = 0;
    int ret = NSTACK_RETURN_FAIL;

    if ((!filename) || (!buf))
    {
        return NSTACK_RETURN_FAIL;
    }

    fp = open(filename, O_RDONLY);
    if (fp < 0)
    {
        NSSOC_LOGERR("open %s fail, error:%d!", filename, errno);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    file_len = lseek(fp, 0, SEEK_END);
    if (file_len <= 0)
    {
        NSSOC_LOGERR("failed to get file len]file name=%s", filename);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    if (file_len > NSTACK_CFG_FILELEN_MAX)
    {
        NSSOC_LOGERR
            ("file len is too big]file len=%ld, max len=%d, file name=%s",
             file_len, NSTACK_CFG_FILELEN_MAX, filename);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    ret = lseek(fp, 0, SEEK_SET);
    if (ret < 0)
    {
        NSSOC_LOGERR("seek to start failed]file name=%s", filename);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    buff_len = file_len + 1;
    cfg_buf = (char *) malloc(buff_len);
    if (!cfg_buf)
    {
        NSSOC_LOGERR("malloc buff failed]buff_len=%ld", buff_len);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    ret = memset_s(cfg_buf, buff_len, 0, buff_len);
    if (NSTACK_RETURN_OK != ret)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d.", ret);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    ret = nsfw_base_read(fp, cfg_buf, buff_len - 1);
    if (ret <= 0)
    {
        NSSOC_LOGERR("read failed]ret=%d, errno:%d", ret, errno);
        ret = NSTACK_RETURN_FAIL;
        goto RETURN_RELEASE;
    }

    *buf = cfg_buf;
    nsfw_base_close(fp);
    return NSTACK_RETURN_OK;
  RETURN_RELEASE:
    if (fp >= 0)
    {
        nsfw_base_close(fp);
    }
    if (cfg_buf)
    {
        free(cfg_buf);
    }
    return ret;
}

/*parse module cfg file*/
int nstack_module_parse()
{
    char *modulecfg = NULL;
    char *tmp_config_path = NULL;
    char *cfg_buf = NULL;
    int ret = NSTACK_RETURN_FAIL;

    modulecfg = getenv(NSTACK_MOD_CFG_FILE);

    if (modulecfg)
    {
        tmp_config_path = realpath(modulecfg, NULL);
    }
    else
    {
        tmp_config_path = realpath(DEFALT_MODULE_CFG_FILE, NULL);
    }

    if (!tmp_config_path)
    {
        NSSOC_LOGWAR
            ("nstack module file:%s get real path failed! Load default instead.",
             modulecfg ? modulecfg : DEFALT_MODULE_CFG_FILE);
        return load_default_module();
    }

    ret = read_json_file(tmp_config_path, &cfg_buf);
    if (NSTACK_RETURN_OK == ret)
    {
        ret = parse_module_cfg(cfg_buf);
        free(cfg_buf);
    }

    free(tmp_config_path);
    return ret;
}

int nstack_rd_parse(const char *name, void *table)
{
    char *modulecfg = NULL;
    char *tmp_config_path = NULL;
    char *cfg_buf = NULL;
    int ret = NSTACK_RETURN_FAIL;

    modulecfg = getenv(NSTACK_MOD_CFG_RD);

    if (modulecfg)
    {
        tmp_config_path = realpath(modulecfg, NULL);
    }
    else
    {
        tmp_config_path = realpath(DEFALT_RD_CFG_FILE, NULL);
    }

    if (!tmp_config_path)
    {
        NSSOC_LOGWAR("nstack rd file:%s get real path failed!",
                     modulecfg ? modulecfg : DEFALT_MODULE_CFG_FILE);
        return NSTACK_RETURN_FAIL;
    }

    ret = read_json_file(tmp_config_path, &cfg_buf);
    if (NSTACK_RETURN_OK == ret)
    {
        ret = parse_rd_cfg(cfg_buf, name, table);
        free(cfg_buf);
    }

    free(tmp_config_path);
    return ret;
}
