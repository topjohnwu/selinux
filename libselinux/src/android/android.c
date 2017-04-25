#include "android_common.h"

static const struct selinux_opt seopts_file_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_file_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_file_contexts" }
};

static const struct selinux_opt seopts_file_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_file_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_file_contexts" }
};

static const char *const sepolicy_file = "/sepolicy";

static const struct selinux_opt seopts_prop_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_property_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_property_contexts"}
};

static const struct selinux_opt seopts_prop_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_property_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_property_contexts"}
};

static const struct selinux_opt seopts_service_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_service_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_service_contexts" }
};

static const struct selinux_opt seopts_service_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_service_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_service_contexts" }
};

static const struct selinux_opt seopts_hwservice_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_hwservice_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_hwservice_contexts" }
};

static const struct selinux_opt seopts_hwservice_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_hwservice_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_hwservice_contexts" }
};

static const struct selinux_opt seopts_vndservice =
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/vndservice_contexts" };

static const struct selinux_opt seopts_vndservice_rootfs =
    { SELABEL_OPT_PATH, "/vndservice_contexts" };

uint8_t fc_digest[FC_DIGEST_SIZE];

static bool compute_file_contexts_hash(uint8_t c_digest[], const struct selinux_opt *opts, unsigned nopts)
{
    int fd = -1;
    void *map = MAP_FAILED;
    bool ret = false;
    uint8_t *fc_data = NULL;
    size_t total_size = 0;
    struct stat sb;
    size_t i;

    for (i = 0; i < nopts; i++) {
        fd = open(opts[i].value, O_CLOEXEC | O_RDONLY);
        if (fd < 0) {
            selinux_log(SELINUX_ERROR, "SELinux:  Could not open %s:  %s\n",
                    opts[i].value, strerror(errno));
            goto cleanup;
        }

        if (fstat(fd, &sb) < 0) {
            selinux_log(SELINUX_ERROR, "SELinux:  Could not stat %s:  %s\n",
                    opts[i].value, strerror(errno));
            goto cleanup;
        }

        map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            selinux_log(SELINUX_ERROR, "SELinux:  Could not map %s:  %s\n",
                    opts[i].value, strerror(errno));
            goto cleanup;
        }

        fc_data = realloc(fc_data, total_size + sb.st_size);
        if (!fc_data) {
            selinux_log(SELINUX_ERROR, "SELinux: Count not re-alloc for %s:  %s\n",
                     opts[i].value, strerror(errno));
            goto cleanup;
        }

        memcpy(fc_data + total_size, map, sb.st_size);
        total_size += sb.st_size;

        /* reset everything for next file */
        munmap(map, sb.st_size);
        close(fd);
        map = MAP_FAILED;
        fd = -1;
    }

    SHA1(fc_data, total_size, c_digest);
    ret = true;

cleanup:
    if (map != MAP_FAILED)
        munmap(map, sb.st_size);
    if (fd >= 0)
        close(fd);
    free(fc_data);

    return ret;
}

static struct selabel_handle* selinux_android_file_context(const struct selinux_opt *opts,
                                                    unsigned nopts)
{
    struct selabel_handle *sehandle;
    struct selinux_opt fc_opts[nopts + 1];

    memcpy(fc_opts, opts, nopts*sizeof(struct selinux_opt));
    fc_opts[nopts].type = SELABEL_OPT_BASEONLY;
    fc_opts[nopts].value = (char *)1;

    sehandle = selabel_open(SELABEL_CTX_FILE, fc_opts, ARRAY_SIZE(fc_opts));
    if (!sehandle) {
        selinux_log(SELINUX_ERROR, "%s: Error getting file context handle (%s)\n",
                __FUNCTION__, strerror(errno));
        return NULL;
    }
    if (!compute_file_contexts_hash(fc_digest, opts, nopts)) {
        selabel_close(sehandle);
        return NULL;
    }

    selinux_log(SELINUX_INFO, "SELinux: Loaded file_contexts\n");

    return sehandle;
}

static bool selinux_android_opts_file_exists(const struct selinux_opt *opt)
{
    return (access(opt[0].value, R_OK) != -1);
}

struct selabel_handle* selinux_android_file_context_handle(void)
{
    if (selinux_android_opts_file_exists(seopts_file_split)) {
        return selinux_android_file_context(seopts_file_split,
                                            ARRAY_SIZE(seopts_file_split));
    } else {
        return selinux_android_file_context(seopts_file_rootfs,
                                            ARRAY_SIZE(seopts_file_rootfs));
    }
}
struct selabel_handle* selinux_android_prop_context_handle(void)
{
    struct selabel_handle* sehandle;
    const struct selinux_opt* seopts_prop;

    // Prefer files from /system & /vendor, fall back to files from /
    if (access(seopts_prop_split[0].value, R_OK) != -1) {
        seopts_prop = seopts_prop_split;
    } else {
        seopts_prop = seopts_prop_rootfs;
    }

    sehandle = selabel_open(SELABEL_CTX_ANDROID_PROP,
            seopts_prop, 2);
    if (!sehandle) {
        selinux_log(SELINUX_ERROR, "%s: Error getting property context handle (%s)\n",
                __FUNCTION__, strerror(errno));
        return NULL;
    }
    selinux_log(SELINUX_INFO, "SELinux: Loaded property_contexts from %s & %s.\n",
            seopts_prop[0].value, seopts_prop[1].value);

    return sehandle;
}

struct selabel_handle* selinux_android_service_open_context_handle(const struct selinux_opt* seopts_service,
                                                                   unsigned nopts)
{
    struct selabel_handle* sehandle;

    sehandle = selabel_open(SELABEL_CTX_ANDROID_SERVICE,
            seopts_service, nopts);

    if (!sehandle) {
        selinux_log(SELINUX_ERROR, "%s: Error getting service context handle (%s)\n",
                __FUNCTION__, strerror(errno));
        return NULL;
    }
    selinux_log(SELINUX_INFO, "SELinux: Loaded service_contexts from:\n");
    for (unsigned i = 0; i < nopts; i++) {
        selinux_log(SELINUX_INFO, "    %s\n", seopts_service[i].value);
    }
    return sehandle;
}

struct selabel_handle* selinux_android_service_context_handle(void)
{
    const struct selinux_opt* seopts_service;

    // Prefer files from /system & /vendor, fall back to files from /
    if (access(seopts_service_split[0].value, R_OK) != -1) {
        seopts_service = seopts_service_split;
    } else {
        seopts_service = seopts_service_rootfs;
    }

    // TODO(b/36866029) full treble devices can't load non-plat
    return selinux_android_service_open_context_handle(seopts_service, 2);
}

struct selabel_handle* selinux_android_hw_service_context_handle(void)
{
    const struct selinux_opt* seopts_service;
    if (access(seopts_hwservice_split[0].value, R_OK) != -1) {
        seopts_service = seopts_hwservice_split;
    } else {
        seopts_service = seopts_hwservice_rootfs;
    }

    return selinux_android_service_open_context_handle(seopts_service, 2);
}

struct selabel_handle* selinux_android_vendor_service_context_handle(void)
{
    const struct selinux_opt* seopts_service;
    if (access(seopts_vndservice.value, R_OK) != -1) {
        seopts_service = &seopts_vndservice;
    } else {
        seopts_service = &seopts_vndservice_rootfs;
    }

    return selinux_android_service_open_context_handle(seopts_service, 1);
}

int selinux_android_load_policy()
{
	int fd = -1;

	fd = open(sepolicy_file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not open %s:  %s\n",
				sepolicy_file, strerror(errno));
		return -1;
	}
	int ret = selinux_android_load_policy_from_fd(fd, sepolicy_file);
	close(fd);
	return ret;
}

int selinux_android_load_policy_from_fd(int fd, const char *description)
{
	int rc;
	struct stat sb;
	void *map = NULL;
	static int load_successful = 0;

	/*
	 * Since updating policy at runtime has been abolished
	 * we just check whether a policy has been loaded before
	 * and return if this is the case.
	 * There is no point in reloading policy.
	 */
	if (load_successful){
	  selinux_log(SELINUX_WARNING, "SELinux: Attempted reload of SELinux policy!/n");
	  return 0;
	}

	set_selinuxmnt(SELINUXMNT);
	if (fstat(fd, &sb) < 0) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not stat %s:  %s\n",
				description, strerror(errno));
		return -1;
	}
	map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not map %s:  %s\n",
				description, strerror(errno));
		return -1;
	}

	rc = security_load_policy(map, sb.st_size);
	if (rc < 0) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not load policy:  %s\n",
				strerror(errno));
		munmap(map, sb.st_size);
		return -1;
	}

	munmap(map, sb.st_size);
	selinux_log(SELINUX_INFO, "SELinux: Loaded policy from %s\n", description);
	load_successful = 1;
	return 0;
}

int selinux_log_callback(int type, const char *fmt, ...)
{
    va_list ap;
    int priority;
    char *strp;

    switch(type) {
    case SELINUX_WARNING:
        priority = ANDROID_LOG_WARN;
        break;
    case SELINUX_INFO:
        priority = ANDROID_LOG_INFO;
        break;
    default:
        priority = ANDROID_LOG_ERROR;
        break;
    }

    va_start(ap, fmt);
    if (vasprintf(&strp, fmt, ap) != -1) {
        LOG_PRI(priority, "SELinux", "%s", strp);
        LOG_EVENT_STRING(AUDITD_LOG_TAG, strp);
        free(strp);
    }
    va_end(ap);
    return 0;
}
