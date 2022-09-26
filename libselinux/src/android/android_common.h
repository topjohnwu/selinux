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
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/android.h>
#include <selinux/label.h>
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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define FC_DIGEST_SIZE SHA_DIGEST_LENGTH

// Context files (file_contexts, service_contexts, etc) may be spread over
// multiple partitions: system, apex, system_ext, product, vendor and/or odm.
#define MAX_CONTEXT_PATHS 6
// The maximum number of alternatives for a file on one partition.
#define MAX_ALT_CONTEXT_PATHS 2
