
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <fts.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/avc.h>
#include <openssl/sha.h>
#ifndef __ANDROID_VNDK__
#include <private/android_filesystem_config.h>
#endif
#include <log/log.h>
#include "policy.h"
#include "callbacks.h"
#include "selinux_internal.h"
#include "label_internal.h"
#include <fnmatch.h>
#include <limits.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <libgen.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define FC_DIGEST_SIZE SHA_DIGEST_LENGTH
