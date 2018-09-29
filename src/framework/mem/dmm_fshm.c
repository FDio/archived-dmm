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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#include "nstack_log.h"
#include "nsfw_base_linux_api.h"

#include "dmm_config.h"
#include "dmm_share.h"
#include "dmm_fs.h"

#define DMM_FSHM_FMT "%s/dmm-fshm-%d"   /* VAR_DIR pid */

inline static void
set_fshm_path (char path[DMM_SHARE_PATH_MAX], pid_t pid)
{
  (void) snprintf (path, DMM_SHARE_PATH_MAX, DMM_FSHM_FMT, DMM_VAR_DIR, pid);

  path[DMM_SHARE_PATH_MAX - 1] = 0;
}

/*
input: share->path, share->size, share->pid
output: share->base
*/
int
dmm_fshm_create (struct dmm_share *share)
{
  int fd, ret;
  void *base, *hint = (void *) DMM_MAIN_SHARE_BASE;

  if (share->type != DMM_SHARE_FSHM)
    {
      NSFW_LOGERR ("type error, type:%d", share->type);
      return -1;
    }

  set_fshm_path (share->path, share->pid);

  NSFW_LOGINF ("Start create share memory, path:'%s' size:%lu",
               share->path, share->size);

  fd = open (share->path, O_RDWR | O_CREAT, 0666);
  if (fd < 0)
    {
      NSFW_LOGERR ("Open file failed, path:'%s', errno=%d",
                   share->path, errno);
      return -1;
    }

  ret = ftruncate (fd, share->size);
  if (ret < 0)
    {
      NSFW_LOGERR ("Set file size failed, path:'%s', errno=%d",
                   share->path, errno);
      (void) nsfw_base_close (fd);
      return -1;
    }

  base = mmap (hint, share->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED)
    {
      NSFW_LOGERR ("Map failed, path:'%s' size:%lu, errno=%d",
                   share->path, share->size, errno);
      (void) nsfw_base_close (fd);
      return -1;
    }
  else if (hint && hint != MAP_FAILED && base != hint)
    {
      NSFW_LOGERR ("Map address failed, path:'%s' hint:%p size:%lu, base:%p",
                   share->path, hint, share->size, base);
      (void) munmap (base, share->size);
      (void) nsfw_base_close (fd);
      return -1;
    }

  share->base = base;

  NSFW_LOGINF ("Share memory created, size:%lu, base=%p", share->size, base);

  (void) nsfw_base_close (fd);
  return 0;
}

int
dmm_fshm_delete (struct dmm_share *share)
{
  (void) munmap (share->base, share->size);
  (void) unlink (share->path);

  return 0;
}

/*
input: share->path, share->size, share->base(OPT)
output: share->base(if-null)
*/
int
dmm_fshm_attach (struct dmm_share *share)
{
  int fd;
  void *base;

  NSFW_LOGINF ("Start attach, share:%p"
               " {type:%d pid:%d base:%p size:%lu path:'%s'}",
               share, share->type, share->pid,
               share->base, share->size, share->path);

  if (share->type != DMM_SHARE_FSHM)
    {
      NSFW_LOGERR ("type error, type:%d", share->type);
      return -1;
    }

  fd = open (share->path, O_RDWR);
  if (fd < 0)
    {
      NSFW_LOGERR ("Open file failed, path:'%s', errno=%d",
                   share->path, errno);
      return -1;
    }

  if (share->size <= 0)
    {
      share->size = dmm_file_size (fd);
      if (share->size == 0)
        {
          NSFW_LOGERR ("No file size '%s'", share->path);
          (void) nsfw_base_close (fd);
          return -1;
        }
    }

  base = mmap (share->base, share->size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
  if (base == MAP_FAILED)
    {
      NSFW_LOGERR ("Map failed, path:'%s' base:%p size:%lu, errno=%d",
                   share->path, share->base, share->size, errno);
      (void) nsfw_base_close (fd);
      return -1;
    }

  if (NULL == share->base)
    {
      share->base = base;
    }
  else if (base != share->base)
    {
      NSFW_LOGERR ("Map address error, path:'%s' share->base:%p, base:%p",
                   share->path, share->base, base);
      (void) munmap (base, share->size);
      (void) nsfw_base_close (fd);
      return -1;
    }

  NSFW_LOGINF ("Memory attached, base=%p", base);

  (void) nsfw_base_close (fd);
  return 0;
}

int
dmm_fshm_detach (struct dmm_share *share)
{
  (void) munmap (share->base, share->size);

  return 0;
}
