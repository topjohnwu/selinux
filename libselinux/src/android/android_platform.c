#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <fts.h>
#include <libgen.h>
#include <limits.h>
#include <linux/magic.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <log/log.h>
#include <packagelistparser/packagelistparser.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <selinux/context.h>
#include <selinux/selinux.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include "android_internal.h"
#include "callbacks.h"
#include "label_internal.h"
#include "selinux_internal.h"

/* Locations for the file_contexts files. For each partition, only the first
 * existing entry will be used (for example, if
 * /system/etc/selinux/plat_file_contexts exists, /plat_file_contexts will be
 * ignored).
 */
static const char* const file_context_paths[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS] = {
	{
		"/system/etc/selinux/plat_file_contexts",
		"/plat_file_contexts"
	},
	{
		"/dev/selinux/apex_file_contexts",
	},
	{
		"/system_ext/etc/selinux/system_ext_file_contexts",
		"/system_ext_file_contexts"
	},
	{
		"/product/etc/selinux/product_file_contexts",
		"/product_file_contexts"
	},
	{
		"/vendor/etc/selinux/vendor_file_contexts",
		"/vendor_file_contexts"
	},
	{
		"/odm/etc/selinux/odm_file_contexts",
		"/odm_file_contexts"
	}
};

/* Locations for the seapp_contexts files. For each partition, only the first
 * existing entry will be used (for example, if
 * /system/etc/selinux/plat_seapp_contexts exists, /plat_seapp_contexts will be
 * ignored).
 */
static const char* const seapp_context_paths[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS] = {
	{
		"/system/etc/selinux/plat_seapp_contexts",
		"/plat_seapp_contexts"
	},
	{
		"/dev/selinux/apex_seapp_contexts",
	},
	{
		"/system_ext/etc/selinux/system_ext_seapp_contexts",
		"/system_ext_seapp_contexts"
	},
	{
		"/product/etc/selinux/product_seapp_contexts",
		"/product_seapp_contexts"
	},
	{
		"/vendor/etc/selinux/vendor_seapp_contexts",
		"/vendor_seapp_contexts"
	},
	{
		"/odm/etc/selinux/odm_seapp_contexts",
		"/odm_seapp_contexts"
	}
};

/* Returns a handle for the file contexts backend, initialized with the Android
 * configuration */
struct selabel_handle* selinux_android_file_context_handle(void)
{
	const char* file_contexts[MAX_CONTEXT_PATHS];
	struct selinux_opt opts[MAX_CONTEXT_PATHS + 1];
	int npaths, nopts;

	npaths = find_existing_files(file_context_paths, file_contexts);
	paths_to_opts(file_contexts, npaths, opts);

	opts[npaths].type = SELABEL_OPT_BASEONLY;
	opts[npaths].value = (char *) 1;
	nopts = npaths + 1;

	return initialize_backend(SELABEL_CTX_FILE, "file", opts, nopts);
}

/* Which categories should be associated to the process */
enum levelFrom {
	/* None */
	LEVELFROM_NONE,
	/* The categories of the application */
	LEVELFROM_APP,
	/* The categories of the end-user */
	LEVELFROM_USER,
	/* Application and end-user */
	LEVELFROM_ALL
};

#if DEBUG
static char const * const levelFromName[] = {
	"none",
	"app",
	"user",
	"all"
};
#endif

struct prefix_str {
	size_t len;
	char *str;
	char is_prefix;
};

static void free_prefix_str(struct prefix_str *p)
{
	if (!p)
		return;
	free(p->str);
}

/* For a set of selectors, represents the contexts that should be applied to an
 * app and its data. Each instance is based on a line in a seapp_contexts file.
 * */
struct seapp_context {
	/* input selectors */
	bool isSystemServer;
	bool isEphemeralAppSet;
	bool isEphemeralApp;
	struct prefix_str user;
	char *seinfo;
	struct prefix_str name;
	bool isPrivAppSet;
	bool isPrivApp;
	int32_t minTargetSdkVersion;
	bool fromRunAs;
	/* outputs */
	char *domain;
	char *type;
	char *level;
	enum levelFrom levelFrom;
};

static void free_seapp_context(struct seapp_context *s)
{
	if (!s)
		return;

	free_prefix_str(&s->user);
	free(s->seinfo);
	free_prefix_str(&s->name);
	free(s->domain);
	free(s->type);
	free(s->level);
}

/* If any duplicate was found while sorting the entries */
static bool seapp_contexts_dup = false;

/* Compare two seapp_context. Used to sort all the entries found. */
static int seapp_context_cmp(const void *A, const void *B)
{
	const struct seapp_context *const *sp1 = (const struct seapp_context *const *) A;
	const struct seapp_context *const *sp2 = (const struct seapp_context *const *) B;
	const struct seapp_context *s1 = *sp1, *s2 = *sp2;
	bool dup;

	/* Give precedence to isSystemServer=true. */
	if (s1->isSystemServer != s2->isSystemServer)
		return (s1->isSystemServer ? -1 : 1);

	/* Give precedence to a specified isEphemeral= over an
	 * unspecified isEphemeral=. */
	if (s1->isEphemeralAppSet != s2->isEphemeralAppSet)
		return (s1->isEphemeralAppSet ? -1 : 1);

	/* Give precedence to a specified user= over an unspecified user=. */
	if (s1->user.str && !s2->user.str)
		return -1;
	if (!s1->user.str && s2->user.str)
		return 1;

	if (s1->user.str) {
		/* Give precedence to a fixed user= string over a prefix. */
		if (s1->user.is_prefix != s2->user.is_prefix)
			return (s2->user.is_prefix ? -1 : 1);

		/* Give precedence to a longer prefix over a shorter prefix. */
		if (s1->user.is_prefix && s1->user.len != s2->user.len)
			return (s1->user.len > s2->user.len) ? -1 : 1;
	}

	/* Give precedence to a specified seinfo= over an unspecified seinfo=. */
	if (s1->seinfo && !s2->seinfo)
		return -1;
	if (!s1->seinfo && s2->seinfo)
		return 1;

	/* Give precedence to a specified name= over an unspecified name=. */
	if (s1->name.str && !s2->name.str)
		return -1;
	if (!s1->name.str && s2->name.str)
		return 1;

	if (s1->name.str) {
		/* Give precedence to a fixed name= string over a prefix. */
		if (s1->name.is_prefix != s2->name.is_prefix)
			return (s2->name.is_prefix ? -1 : 1);

		/* Give precedence to a longer prefix over a shorter prefix. */
		if (s1->name.is_prefix && s1->name.len != s2->name.len)
			return (s1->name.len > s2->name.len) ? -1 : 1;
	}

	/* Give precedence to a specified isPrivApp= over an unspecified isPrivApp=. */
	if (s1->isPrivAppSet != s2->isPrivAppSet)
		return (s1->isPrivAppSet ? -1 : 1);

	/* Give precedence to a higher minTargetSdkVersion= over a lower minTargetSdkVersion=.
	 * If unspecified, minTargetSdkVersion has a default value of 0.
	 */
	if (s1->minTargetSdkVersion > s2->minTargetSdkVersion)
		return -1;
	else if (s1->minTargetSdkVersion < s2->minTargetSdkVersion)
		return 1;

	/* Give precedence to fromRunAs=true. */
	if (s1->fromRunAs != s2->fromRunAs)
		return (s1->fromRunAs ? -1 : 1);

	/*
	 * Check for a duplicated entry on the input selectors.
	 * We already compared isSystemServer above.
	 * We also have already checked that both entries specify the same
	 * string fields, so if s1 has a non-NULL string, then so does s2.
	 */
	dup = (!s1->user.str || !strcmp(s1->user.str, s2->user.str)) &&
		(!s1->seinfo || !strcmp(s1->seinfo, s2->seinfo)) &&
		(!s1->name.str || !strcmp(s1->name.str, s2->name.str)) &&
		(s1->isPrivAppSet && s1->isPrivApp == s2->isPrivApp) &&
		(s1->isSystemServer && s1->isSystemServer == s2->isSystemServer) &&
		(s1->isEphemeralAppSet && s1->isEphemeralApp == s2->isEphemeralApp);

	if (dup) {
		seapp_contexts_dup = true;
		selinux_log(SELINUX_ERROR, "seapp_contexts:  Duplicated entry\n");
		if (s1->user.str)
			selinux_log(SELINUX_ERROR, " user=%s\n", s1->user.str);
		if (s1->seinfo)
			selinux_log(SELINUX_ERROR, " seinfo=%s\n", s1->seinfo);
		if (s1->name.str)
			selinux_log(SELINUX_ERROR, " name=%s\n", s1->name.str);
	}

	/* Anything else has equal precedence. */
	return 0;
}

/* Array of all the seapp_context entries configured. */
static struct seapp_context **seapp_contexts = NULL;
/* Size of seapp_contexts */
static int nspec = 0;

static void free_seapp_contexts(void)
{
	int n;

	if (!seapp_contexts)
		return;

	for (n = 0; n < nspec; n++)
		free_seapp_context(seapp_contexts[n]);

	free(seapp_contexts);
	seapp_contexts = NULL;
	nspec = 0;
}

static int32_t get_minTargetSdkVersion(const char *value)
{
	char *endptr;
	long minTargetSdkVersion;
	minTargetSdkVersion = strtol(value, &endptr, 10);
	if (('\0' != *endptr) || (minTargetSdkVersion < 0) || (minTargetSdkVersion > INT32_MAX)) {
		return -1; /* error parsing minTargetSdkVersion */
	} else {
		return (int32_t) minTargetSdkVersion;
	}
}

int selinux_android_seapp_context_reload(void)
{
	FILE *fp = NULL;
	char line_buf[BUFSIZ];
	char *token;
	unsigned lineno;
	struct seapp_context *cur;
	char *p, *name = NULL, *value = NULL, *saveptr;
	size_t i, len, files_len = 0;
	int ret;
	const char* seapp_contexts_files[MAX_CONTEXT_PATHS];

	files_len = find_existing_files(seapp_context_paths, seapp_contexts_files);

	/* Reset the current entries */
	free_seapp_contexts();

	nspec = 0;
	for (i = 0; i < files_len; i++) {
		fp = fopen(seapp_contexts_files[i], "re");
		if (!fp) {
			selinux_log(SELINUX_ERROR, "%s:  could not open seapp_contexts file: %s",
				    __FUNCTION__, seapp_contexts_files[i]);
			return -1;
		}
		while (fgets(line_buf, sizeof line_buf - 1, fp)) {
			p = line_buf;
			while (isspace(*p))
				p++;
			if (*p == '#' || *p == 0)
				continue;
			nspec++;
		}
		fclose(fp);
	}

	seapp_contexts = (struct seapp_context **) calloc(nspec, sizeof(struct seapp_context *));
	if (!seapp_contexts)
		goto oom;

	nspec = 0;
	for (i = 0; i < files_len; i++) {
		lineno = 1;
		fp = fopen(seapp_contexts_files[i], "re");
		if (!fp) {
			selinux_log(SELINUX_ERROR, "%s:  could not open seapp_contexts file: %s",
				    __FUNCTION__, seapp_contexts_files[i]);
			free_seapp_contexts();
			return -1;
		}
		while (fgets(line_buf, sizeof line_buf - 1, fp)) {
			len = strlen(line_buf);
			if (len == 0) {
				// line contains a NUL byte as its first entry
				goto err;
			}
			if (line_buf[len - 1] == '\n')
				line_buf[len - 1] = 0;
			p = line_buf;
			while (isspace(*p))
				p++;
			if (*p == '#' || *p == 0)
				continue;

			cur = (struct seapp_context *) calloc(1, sizeof(struct seapp_context));
			if (!cur)
				goto oom;

			token = strtok_r(p, " \t", &saveptr);
			if (!token) {
				free_seapp_context(cur);
				goto err;
			}

			while (1) {
				name = token;
				value = strchr(name, '=');
				if (!value) {
					free_seapp_context(cur);
					goto err;
				}
				*value++ = 0;

				if (!strcasecmp(name, "isSystemServer")) {
					if (!strcasecmp(value, "true"))
						cur->isSystemServer = true;
					else if (!strcasecmp(value, "false"))
						cur->isSystemServer = false;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "isEphemeralApp")) {
					cur->isEphemeralAppSet = true;
					if (!strcasecmp(value, "true"))
						cur->isEphemeralApp = true;
					else if (!strcasecmp(value, "false"))
						cur->isEphemeralApp = false;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "user")) {
					if (cur->user.str) {
						free_seapp_context(cur);
						goto err;
					}
					cur->user.str = strdup(value);
					if (!cur->user.str) {
						free_seapp_context(cur);
						goto oom;
					}
					cur->user.len = strlen(cur->user.str);
					if (cur->user.str[cur->user.len-1] == '*')
						cur->user.is_prefix = 1;
				} else if (!strcasecmp(name, "seinfo")) {
					if (cur->seinfo) {
						free_seapp_context(cur);
						goto err;
					}
					cur->seinfo = strdup(value);
					if (!cur->seinfo) {
						free_seapp_context(cur);
						goto oom;
					}
					if (strstr(value, ":")) {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "name")) {
					if (cur->name.str) {
						free_seapp_context(cur);
						goto err;
					}
					cur->name.str = strdup(value);
					if (!cur->name.str) {
						free_seapp_context(cur);
						goto oom;
					}
					cur->name.len = strlen(cur->name.str);
					if (cur->name.str[cur->name.len-1] == '*')
						cur->name.is_prefix = 1;
				} else if (!strcasecmp(name, "domain")) {
					if (cur->domain) {
						free_seapp_context(cur);
						goto err;
					}
					cur->domain = strdup(value);
					if (!cur->domain) {
						free_seapp_context(cur);
						goto oom;
					}
				} else if (!strcasecmp(name, "type")) {
					if (cur->type) {
						free_seapp_context(cur);
						goto err;
					}
					cur->type = strdup(value);
					if (!cur->type) {
						free_seapp_context(cur);
						goto oom;
					}
				} else if (!strcasecmp(name, "levelFromUid")) {
					if (cur->levelFrom) {
						free_seapp_context(cur);
						goto err;
					}
					if (!strcasecmp(value, "true"))
						cur->levelFrom = LEVELFROM_APP;
					else if (!strcasecmp(value, "false"))
						cur->levelFrom = LEVELFROM_NONE;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "levelFrom")) {
					if (cur->levelFrom) {
						free_seapp_context(cur);
						goto err;
					}
					if (!strcasecmp(value, "none"))
						cur->levelFrom = LEVELFROM_NONE;
					else if (!strcasecmp(value, "app"))
						cur->levelFrom = LEVELFROM_APP;
					else if (!strcasecmp(value, "user"))
						cur->levelFrom = LEVELFROM_USER;
					else if (!strcasecmp(value, "all"))
						cur->levelFrom = LEVELFROM_ALL;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "level")) {
					if (cur->level) {
						free_seapp_context(cur);
						goto err;
					}
					cur->level = strdup(value);
					if (!cur->level) {
						free_seapp_context(cur);
						goto oom;
					}
				} else if (!strcasecmp(name, "isPrivApp")) {
					cur->isPrivAppSet = true;
					if (!strcasecmp(value, "true"))
						cur->isPrivApp = true;
					else if (!strcasecmp(value, "false"))
						cur->isPrivApp = false;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "minTargetSdkVersion")) {
					cur->minTargetSdkVersion = get_minTargetSdkVersion(value);
					if (cur->minTargetSdkVersion < 0) {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "fromRunAs")) {
					if (!strcasecmp(value, "true"))
						cur->fromRunAs = true;
					else if (!strcasecmp(value, "false"))
						cur->fromRunAs = false;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else {
					free_seapp_context(cur);
					goto err;
				}

				token = strtok_r(NULL, " \t", &saveptr);
				if (!token)
					break;
			}

			if (!cur->isPrivApp && cur->name.str &&
			    (!cur->seinfo || !strcmp(cur->seinfo, "default"))) {
				selinux_log(SELINUX_ERROR, "%s:  No specific seinfo value specified with name=\"%s\", on line %u:  insecure configuration!\n",
					    seapp_contexts_files[i], cur->name.str, lineno);
				free_seapp_context(cur);
				goto err;
			}

			seapp_contexts[nspec] = cur;
			nspec++;
			lineno++;
		}
		fclose(fp);
		fp = NULL;
	}

	qsort(seapp_contexts, nspec, sizeof(struct seapp_context *),
	      seapp_context_cmp);

	if (seapp_contexts_dup)
		goto err_no_log;

#if DEBUG
	{
		int i;
		for (i = 0; i < nspec; i++) {
			cur = seapp_contexts[i];
			selinux_log(SELINUX_INFO, "%s:  isSystemServer=%s  isEphemeralApp=%s user=%s seinfo=%s "
					"name=%s isPrivApp=%s minTargetSdkVersion=%d fromRunAs=%s -> domain=%s type=%s level=%s levelFrom=%s",
				__FUNCTION__,
				cur->isSystemServer ? "true" : "false",
				cur->isEphemeralAppSet ? (cur->isEphemeralApp ? "true" : "false") : "null",
				cur->user.str,
				cur->seinfo, cur->name.str,
				cur->isPrivAppSet ? (cur->isPrivApp ? "true" : "false") : "null",
				cur->minTargetSdkVersion,
				cur->fromRunAs ? "true" : "false",
				cur->domain, cur->type, cur->level,
				levelFromName[cur->levelFrom]);
		}
	}
#endif

	ret = 0;

out:
	if (fp) {
		fclose(fp);
	}
	return ret;

err:
	selinux_log(SELINUX_ERROR, "%s:  Invalid entry on line %u\n",
		    seapp_contexts_files[i], lineno);
err_no_log:
	free_seapp_contexts();
	ret = -1;
	goto out;
oom:
	selinux_log(SELINUX_ERROR,
		    "%s:  Out of memory\n", __FUNCTION__);
	free_seapp_contexts();
	ret = -1;
	goto out;
}

/* indirection to support pthread_once */
static void seapp_context_init(void)
{
	selinux_android_seapp_context_reload();
}

static pthread_once_t seapp_once = PTHREAD_ONCE_INIT;

void selinux_android_seapp_context_init(void) {
	__selinux_once(seapp_once, seapp_context_init);
}

/*
 * Max id that can be mapped to category set uniquely
 * using the current scheme.
 */
#define CAT_MAPPING_MAX_ID (0x1<<16)

/* The kind of request when looking up an seapp_context. */
enum seapp_kind {
	/* Returns the SELinux type for the app data directory */
	SEAPP_TYPE,
	/* Returns the SELinux type for the app process */
	SEAPP_DOMAIN
};

#define PRIVILEGED_APP_STR ":privapp"
#define EPHEMERAL_APP_STR ":ephemeralapp"
#define TARGETSDKVERSION_STR ":targetSdkVersion="
#define FROM_RUNAS_STR ":fromRunAs"
static int32_t get_app_targetSdkVersion(const char *seinfo)
{
	char *substr = strstr(seinfo, TARGETSDKVERSION_STR);
	long targetSdkVersion;
	char *endptr;
	if (substr != NULL) {
		substr = substr + strlen(TARGETSDKVERSION_STR);
		if (substr != NULL) {
			targetSdkVersion = strtol(substr, &endptr, 10);
			if (('\0' != *endptr && ':' != *endptr)
					|| (targetSdkVersion < 0) || (targetSdkVersion > INT32_MAX)) {
				return -1; /* malformed targetSdkVersion value in seinfo */
			} else {
				return (int32_t) targetSdkVersion;
			}
		}
	}
	return 0; /* default to 0 when targetSdkVersion= is not present in seinfo */
}

static int seinfo_parse(char *dest, const char *src, size_t size)
{
	size_t len;
	char *p;

	if ((p = strchr(src, ':')) != NULL)
		len = p - src;
	else
		len = strlen(src);

	if (len > size - 1)
		return -1;

	strncpy(dest, src, len);
	dest[len] = '\0';

	return 0;
}

/* Sets the categories of ctx based on the level request */
static int set_range_from_level(context_t ctx, enum levelFrom levelFrom, uid_t userid, uid_t appid)
{
	char level[255];
	switch (levelFrom) {
	case LEVELFROM_NONE:
        	strlcpy(level, "s0", sizeof level);
		break;
	case LEVELFROM_APP:
		snprintf(level, sizeof level, "s0:c%u,c%u",
			 appid & 0xff,
			 256 + (appid>>8 & 0xff));
		break;
	case LEVELFROM_USER:
		snprintf(level, sizeof level, "s0:c%u,c%u",
			 512 + (userid & 0xff),
			 768 + (userid>>8 & 0xff));
		break;
	case LEVELFROM_ALL:
		snprintf(level, sizeof level, "s0:c%u,c%u,c%u,c%u",
			 appid & 0xff,
			 256 + (appid>>8 & 0xff),
			 512 + (userid & 0xff),
			 768 + (userid>>8 & 0xff));
		break;
	default:
		return -1;
	}
	if (context_range_set(ctx, level)) {
		return -2;
	}
	return 0;
}

/* Search an app (or its data) based on its name and information within the list
 * of known seapp_contexts. If found, sets the type and categories of ctx and
 * returns 0. Returns -1 in case of error; -2 for out of memory */
static int seapp_context_lookup(enum seapp_kind kind,
				uid_t uid,
				bool isSystemServer,
				const char *seinfo,
				const char *pkgname,
				context_t ctx)
{
	struct passwd *pwd;
	const char *username = NULL;
	struct seapp_context *cur = NULL;
	int i;
	uid_t userid;
	uid_t appid;
	bool isPrivApp = false;
	bool isEphemeralApp = false;
	int32_t targetSdkVersion = 0;
	bool fromRunAs = false;
	char parsedseinfo[BUFSIZ];

	selinux_android_seapp_context_init();

	if (seinfo) {
		if (seinfo_parse(parsedseinfo, seinfo, BUFSIZ))
			goto err;
		isPrivApp = strstr(seinfo, PRIVILEGED_APP_STR) ? true : false;
		isEphemeralApp = strstr(seinfo, EPHEMERAL_APP_STR) ? true : false;
		fromRunAs = strstr(seinfo, FROM_RUNAS_STR) ? true : false;
		targetSdkVersion = get_app_targetSdkVersion(seinfo);
		if (targetSdkVersion < 0) {
			selinux_log(SELINUX_ERROR,
					"%s:  Invalid targetSdkVersion passed for app with uid %d, seinfo %s, name %s\n",
					__FUNCTION__, uid, seinfo, pkgname);
			goto err;
		}
		seinfo = parsedseinfo;
	}

	userid = uid / AID_USER_OFFSET;
	appid = uid % AID_USER_OFFSET;
	if (appid < AID_APP_START) {
            /*
             * This code is Android specific, bionic guarantees that
             * calls to non-reentrant getpwuid() are thread safe.
             */
#ifndef __BIONIC__
#warning "This code assumes that getpwuid is thread safe, only true with Bionic!"
#endif
		pwd = getpwuid(appid);
		if (!pwd)
			goto err;

		username = pwd->pw_name;

	} else if (appid < AID_SDK_SANDBOX_PROCESS_START) {
		username = "_app";
		appid -= AID_APP_START;
	} else if (appid < AID_ISOLATED_START) {
		username = "_sdksandbox";
		appid -= AID_SDK_SANDBOX_PROCESS_START;
	} else {
		username = "_isolated";
		appid -= AID_ISOLATED_START;
	}

	if (appid >= CAT_MAPPING_MAX_ID || userid >= CAT_MAPPING_MAX_ID)
		goto err;

	for (i = 0; i < nspec; i++) {
		cur = seapp_contexts[i];

		if (cur->isSystemServer != isSystemServer)
			continue;

		if (cur->isEphemeralAppSet && cur->isEphemeralApp != isEphemeralApp)
			continue;

		if (cur->user.str) {
			if (cur->user.is_prefix) {
				if (strncasecmp(username, cur->user.str, cur->user.len-1))
					continue;
			} else {
				if (strcasecmp(username, cur->user.str))
					continue;
			}
		}

		if (cur->seinfo) {
			if (!seinfo || strcasecmp(seinfo, cur->seinfo))
				continue;
		}

		if (cur->name.str) {
			if(!pkgname)
				continue;

			if (cur->name.is_prefix) {
				if (strncasecmp(pkgname, cur->name.str, cur->name.len-1))
					continue;
			} else {
				if (strcasecmp(pkgname, cur->name.str))
					continue;
			}
		}

		if (cur->isPrivAppSet && cur->isPrivApp != isPrivApp)
			continue;

		if (cur->minTargetSdkVersion > targetSdkVersion)
			continue;

		if (cur->fromRunAs != fromRunAs)
			continue;

		if (kind == SEAPP_TYPE && !cur->type)
			continue;
		else if (kind == SEAPP_DOMAIN && !cur->domain)
			continue;

		if (kind == SEAPP_TYPE) {
			if (context_type_set(ctx, cur->type))
				goto oom;
		} else if (kind == SEAPP_DOMAIN) {
			if (context_type_set(ctx, cur->domain))
				goto oom;
		}

		if (cur->levelFrom != LEVELFROM_NONE) {
			int res = set_range_from_level(ctx, cur->levelFrom, userid, appid);
			if (res != 0) {
				return res;
			}
		} else if (cur->level) {
			if (context_range_set(ctx, cur->level))
				goto oom;
		}

		break;
	}

	if (kind == SEAPP_DOMAIN && i == nspec) {
		/*
		 * No match.
		 * Fail to prevent staying in the zygote's context.
		 */
		selinux_log(SELINUX_ERROR,
			    "%s:  No match for app with uid %d, seinfo %s, name %s\n",
			    __FUNCTION__, uid, seinfo, pkgname);

		if (security_getenforce() == 1)
			goto err;
	}

	return 0;
err:
	return -1;
oom:
	return -2;
}

int selinux_android_context_with_level(const char * context,
				       char ** newContext,
				       uid_t userid,
				       uid_t appid)
{
	int rc = -2;

	enum levelFrom levelFrom;
	if (userid == (uid_t) -1) {
		levelFrom = (appid == (uid_t) -1) ? LEVELFROM_NONE : LEVELFROM_APP;
	} else {
		levelFrom = (appid == (uid_t) -1) ? LEVELFROM_USER : LEVELFROM_ALL;
	}

	context_t ctx = context_new(context);
	if (!ctx) {
		goto out;
	}

	int res = set_range_from_level(ctx, levelFrom, userid, appid);
	if (res != 0) {
		rc = res;
		goto out;
	}

	char * newString = context_str(ctx);
	if (!newString) {
		goto out;
	}

	char * newCopied = strdup(newString);
	if (!newCopied) {
		goto out;
	}

	*newContext = newCopied;
	rc = 0;

out:
	context_free(ctx);
	return rc;
}

int selinux_android_setcon(const char *con)
{
	int ret = setcon(con);
	if (ret)
		return ret;
	/*
	  System properties must be reinitialized after setcon() otherwise the
	  previous property files will be leaked since mmap()'ed regions are not
	  closed as a result of setcon().
	*/
	return __system_properties_init();
}

int selinux_android_setcontext(uid_t uid,
			       bool isSystemServer,
			       const char *seinfo,
			       const char *pkgname)
{
	char *orig_ctx_str = NULL, *ctx_str;
	context_t ctx = NULL;
	int rc = -1;

	if (is_selinux_enabled() <= 0)
		return 0;

	rc = getcon(&ctx_str);
	if (rc)
		goto err;

	ctx = context_new(ctx_str);
	orig_ctx_str = ctx_str;
	if (!ctx)
		goto oom;

	rc = seapp_context_lookup(SEAPP_DOMAIN, uid, isSystemServer, seinfo, pkgname, ctx);
	if (rc == -1)
		goto err;
	else if (rc == -2)
		goto oom;

	ctx_str = context_str(ctx);
	if (!ctx_str)
		goto oom;

	rc = security_check_context(ctx_str);
	if (rc < 0)
		goto err;

	if (strcmp(ctx_str, orig_ctx_str)) {
		rc = selinux_android_setcon(ctx_str);
		if (rc < 0)
			goto err;
	}

	rc = 0;
out:
	freecon(orig_ctx_str);
	context_free(ctx);
	return rc;
err:
	if (isSystemServer)
		selinux_log(SELINUX_ERROR,
				"%s:  Error setting context for system server: %s\n",
				__FUNCTION__, strerror(errno));
	else
		selinux_log(SELINUX_ERROR,
				"%s:  Error setting context for app with uid %d, seinfo %s: %s\n",
				__FUNCTION__, uid, seinfo, strerror(errno));

	rc = -1;
	goto out;
oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __FUNCTION__);
	rc = -1;
	goto out;
}

static struct selabel_handle *fc_sehandle = NULL;

static void file_context_init(void)
{
    if (!fc_sehandle)
        fc_sehandle = selinux_android_file_context_handle();
}

static pthread_once_t fc_once = PTHREAD_ONCE_INIT;

#define PKGTAB_SIZE 256
/* Hash table for pkg_info. It uses the package name as key. In case of
 * collision, the next entry is the private_data attribute */
static struct pkg_info *pkgTab[PKGTAB_SIZE];

/* Returns a hash based on the package name */
static unsigned int pkghash(const char *pkgname)
{
    unsigned int h = 7;
    for (; *pkgname; pkgname++) {
        h = h * 31 + *pkgname;
    }
    return h & (PKGTAB_SIZE - 1);
}

/* Adds the pkg_info entry to the hash table */
static bool pkg_parse_callback(pkg_info *info, void *userdata) {

    (void) userdata;

    unsigned int hash = pkghash(info->name);
    if (pkgTab[hash])
        /* Collision. Prepend the entry. */
        info->private_data = pkgTab[hash];
    pkgTab[hash] = info;
    return true;
}

/* Initialize the pkg_info hash table */
static void package_info_init(void)
{

    bool rc = packagelist_parse(pkg_parse_callback, NULL);
    if (!rc) {
        selinux_log(SELINUX_ERROR, "SELinux: Could NOT parse package list\n");
        return;
    }

#if DEBUG
    {
        unsigned int hash, buckets, entries, chainlen, longestchain;
        struct pkg_info *info = NULL;

        buckets = entries = longestchain = 0;
        for (hash = 0; hash < PKGTAB_SIZE; hash++) {
            if (pkgTab[hash]) {
                buckets++;
                chainlen = 0;
                for (info = pkgTab[hash]; info; info = (pkg_info *)info->private_data) {
                    chainlen++;
                    selinux_log(SELINUX_INFO, "%s:  name=%s uid=%u debuggable=%s dataDir=%s seinfo=%s\n",
                                __FUNCTION__,
                                info->name, info->uid, info->debuggable ? "true" : "false", info->data_dir, info->seinfo);
                }
                entries += chainlen;
                if (longestchain < chainlen)
                    longestchain = chainlen;
            }
        }
        selinux_log(SELINUX_INFO, "SELinux:  %d pkg entries and %d/%d buckets used, longest chain %d\n", entries, buckets, PKGTAB_SIZE, longestchain);
    }
#endif

}

static pthread_once_t pkg_once = PTHREAD_ONCE_INIT;

/* Returns the pkg_info for a package with a specific name */
struct pkg_info *package_info_lookup(const char *name)
{
    struct pkg_info *info;
    unsigned int hash;

    __selinux_once(pkg_once, package_info_init);

    hash = pkghash(name);
    for (info = pkgTab[hash]; info; info = (pkg_info *)info->private_data) {
        if (!strcmp(name, info->name))
            return info;
    }
    return NULL;
}

/* The contents of these paths are encrypted on FBE devices until user
 * credentials are presented (filenames inside are mangled), so we need
 * to delay restorecon of those until vold explicitly requests it. */
// NOTE: these paths need to be kept in sync with vold
#define DATA_SYSTEM_CE_PATH "/data/system_ce"
#define DATA_VENDOR_CE_PATH "/data/vendor_ce"
#define DATA_MISC_CE_PATH "/data/misc_ce"
#define DATA_MISC_DE_PATH "/data/misc_de"

/* The path prefixes of package data directories. */
#define DATA_DATA_PATH "/data/data"
#define DATA_USER_PATH "/data/user"
#define DATA_USER_DE_PATH "/data/user_de"
#define USER_PROFILE_PATH "/data/misc/profiles/cur/*"
#define SDK_SANDBOX_DATA_CE_PATH "/data/misc_ce/*/sdksandbox"
#define SDK_SANDBOX_DATA_DE_PATH "/data/misc_de/*/sdksandbox"

#define EXPAND_MNT_PATH "/mnt/expand/\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?"
#define EXPAND_USER_PATH EXPAND_MNT_PATH "/user"
#define EXPAND_USER_DE_PATH EXPAND_MNT_PATH "/user_de"
#define EXPAND_SDK_CE_PATH EXPAND_MNT_PATH "/misc_ce/*/sdksandbox"
#define EXPAND_SDK_DE_PATH EXPAND_MNT_PATH "/misc_de/*/sdksandbox"

#define DATA_DATA_PREFIX DATA_DATA_PATH "/"
#define DATA_USER_PREFIX DATA_USER_PATH "/"
#define DATA_USER_DE_PREFIX DATA_USER_DE_PATH "/"
#define DATA_MISC_CE_PREFIX DATA_MISC_CE_PATH "/"
#define DATA_MISC_DE_PREFIX DATA_MISC_DE_PATH "/"
#define EXPAND_MNT_PATH_PREFIX EXPAND_MNT_PATH "/"

/*
 * This method helps in identifying paths that refer to users' app data. Labeling for app data is
 * based on seapp_contexts and seinfo assignments rather than file_contexts and is managed by
 * installd rather than by init.
 */
static bool is_app_data_path(const char *pathname) {
    int flags = FNM_LEADING_DIR|FNM_PATHNAME;
    return (!strncmp(pathname, DATA_DATA_PREFIX, sizeof(DATA_DATA_PREFIX)-1) ||
        !strncmp(pathname, DATA_USER_PREFIX, sizeof(DATA_USER_PREFIX)-1) ||
        !strncmp(pathname, DATA_USER_DE_PREFIX, sizeof(DATA_USER_DE_PREFIX)-1) ||
        !fnmatch(EXPAND_USER_PATH, pathname, flags) ||
        !fnmatch(EXPAND_USER_DE_PATH, pathname, flags) ||
        !fnmatch(SDK_SANDBOX_DATA_CE_PATH, pathname, flags) ||
        !fnmatch(SDK_SANDBOX_DATA_DE_PATH, pathname, flags) ||
        !fnmatch(EXPAND_SDK_CE_PATH, pathname, flags) ||
        !fnmatch(EXPAND_SDK_DE_PATH, pathname, flags));
}

/*
 * Extract the userid from a path.
 * On success, pathname is updated past the userid.
 * Returns 0 on success, -1 on error
 */
static int extract_userid(const char **pathname, unsigned int *userid)
{
    char *end = NULL;

    errno = 0;
    *userid = strtoul(*pathname, &end, 10);
    if (errno) {
        selinux_log(SELINUX_ERROR, "SELinux: Could not parse userid %s: %s.\n",
            *pathname, strerror(errno));
        return -1;
    }
    if (*pathname == end) {
        return -1;
    }
    if (*userid > 1000) {
        return -1;
    }
    *pathname = end;
    return 0;
}

/* Extract the pkgname and userid from a path.
 * On success, the caller is responsible for free'ing pkgname.
 * Returns 0 on success, -1 on invalid path, -2 on error.
 */
static int extract_pkgname_and_userid(const char *pathname, char **pkgname, unsigned int *userid)
{
    char *end = NULL;

    if (pkgname == NULL || *pkgname != NULL || userid == NULL) {
      errno = EINVAL;
      return -2;
    }

    /* Skip directory prefix before package name. */
    if (!strncmp(pathname, DATA_DATA_PREFIX, sizeof(DATA_DATA_PREFIX)-1)) {
        pathname += sizeof(DATA_DATA_PREFIX) - 1;
    } else if (!strncmp(pathname, DATA_USER_PREFIX, sizeof(DATA_USER_PREFIX)-1)) {
        pathname += sizeof(DATA_USER_PREFIX) - 1;
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (*pathname == '/')
            pathname++;
        else
            return -1;
    } else if (!strncmp(pathname, DATA_USER_DE_PREFIX, sizeof(DATA_USER_DE_PREFIX)-1)) {
        pathname += sizeof(DATA_USER_DE_PREFIX) - 1;
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (*pathname == '/')
            pathname++;
        else
            return -1;
    } else if (!fnmatch(EXPAND_USER_PATH, pathname, FNM_LEADING_DIR|FNM_PATHNAME)) {
        pathname += sizeof(EXPAND_USER_PATH);
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (*pathname == '/')
            pathname++;
        else
            return -1;
    } else if (!fnmatch(EXPAND_USER_DE_PATH, pathname, FNM_LEADING_DIR|FNM_PATHNAME)) {
        pathname += sizeof(EXPAND_USER_DE_PATH);
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (*pathname == '/')
            pathname++;
        else
            return -1;
    } else if (!strncmp(pathname, DATA_MISC_CE_PREFIX, sizeof(DATA_MISC_CE_PREFIX)-1)) {
        pathname += sizeof(DATA_MISC_CE_PREFIX) - 1;
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (!strncmp(pathname, "/sdksandbox/", sizeof("/sdksandbox/")-1))
            pathname += sizeof("/sdksandbox/") - 1;
        else
            return -1;
    } else if (!strncmp(pathname, DATA_MISC_DE_PREFIX, sizeof(DATA_MISC_DE_PREFIX)-1)) {
        pathname += sizeof(DATA_MISC_DE_PREFIX) - 1;
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (!strncmp(pathname, "/sdksandbox/", sizeof("/sdksandbox/")-1))
            pathname += sizeof("/sdksandbox/") - 1;
        else
            return -1;
    } else if (!fnmatch(EXPAND_SDK_CE_PATH, pathname, FNM_LEADING_DIR|FNM_PATHNAME)) {
        pathname += sizeof(EXPAND_MNT_PATH_PREFIX) - 1;
        pathname += sizeof("misc_ce/") - 1;
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (!strncmp(pathname, "/sdksandbox/", sizeof("/sdksandbox/")-1))
            pathname += sizeof("/sdksandbox/") - 1;
        else
            return -1;
    } else if (!fnmatch(EXPAND_SDK_DE_PATH, pathname, FNM_LEADING_DIR|FNM_PATHNAME)) {
        pathname += sizeof(EXPAND_MNT_PATH_PREFIX) - 1;
        pathname += sizeof("misc_de/") - 1;
        int rc = extract_userid(&pathname, userid);
        if (rc)
            return -1;
        if (!strncmp(pathname, "/sdksandbox/", sizeof("/sdksandbox/")-1))
            pathname += sizeof("/sdksandbox/") - 1;
        else
            return -1;
    } else
        return -1;

    if (!(*pathname))
        return -1;

    *pkgname = strdup(pathname);
    if (!(*pkgname))
        return -2;

    // Trim pkgname.
    for (end = *pkgname; *end && *end != '/'; end++);
    *end = '\0';

    return 0;
}

static int pkgdir_selabel_lookup(const char *pathname,
                                 const char *seinfo,
                                 uid_t uid,
                                 char **secontextp)
{
    char *pkgname = NULL;
    struct pkg_info *info = NULL;
    char *secontext = *secontextp;
    context_t ctx = NULL;
    int rc = 0;
    unsigned int userid_from_path = 0;

    rc = extract_pkgname_and_userid(pathname, &pkgname, &userid_from_path);
    if (rc) {
      /* Invalid path, we skip it */
      if (rc == -1) {
        return 0;
      }
      return rc;
    }

    if (!seinfo) {
        info = package_info_lookup(pkgname);
        if (!info) {
            selinux_log(SELINUX_WARNING, "SELinux:  Could not look up information for package %s, cannot restorecon %s.\n",
                        pkgname, pathname);
            free(pkgname);
            return -1;
        }
        // info->uid only contains the appid and not the userid.
        info->uid += userid_from_path * AID_USER_OFFSET;
    }

    ctx = context_new(secontext);
    if (!ctx)
        goto err;

    rc = seapp_context_lookup(SEAPP_TYPE, info ? info->uid : uid, 0,
                              info ? info->seinfo : seinfo, info ? info->name : pkgname, ctx);
    if (rc < 0)
        goto err;

    secontext = context_str(ctx);
    if (!secontext)
        goto err;

    if (!strcmp(secontext, *secontextp))
        goto out;

    rc = security_check_context(secontext);
    if (rc < 0)
        goto err;

    freecon(*secontextp);
    *secontextp = strdup(secontext);
    if (!(*secontextp))
        goto err;

    rc = 0;

out:
    free(pkgname);
    context_free(ctx);
    return rc;
err:
    selinux_log(SELINUX_ERROR, "%s:  Error looking up context for path %s, pkgname %s, seinfo %s, uid %u: %s\n",
                __FUNCTION__, pathname, pkgname, info ? info->seinfo : seinfo,
                info ? info->uid : uid, strerror(errno));
    rc = -1;
    goto out;
}

#define RESTORECON_PARTIAL_MATCH_DIGEST  "security.sehash"

static int restorecon_sb(const char *pathname, const struct stat *sb,
                         bool nochange, bool verbose,
                         const char *seinfo, uid_t uid)
{
    char *secontext = NULL;
    char *oldsecontext = NULL;
    int rc = 0;

    if (selabel_lookup(fc_sehandle, &secontext, pathname, sb->st_mode) < 0)
        return 0;  /* no match, but not an error */

    if (lgetfilecon(pathname, &oldsecontext) < 0)
        goto err;

    /*
     * For subdirectories of /data/data or /data/user, we ignore selabel_lookup()
     * and use pkgdir_selabel_lookup() instead. Files within those directories
     * have different labeling rules, based off of /seapp_contexts, and
     * installd is responsible for managing these labels instead of init.
     */
    if (is_app_data_path(pathname)) {
        if (pkgdir_selabel_lookup(pathname, seinfo, uid, &secontext) < 0)
            goto err;
    }

    if (strcmp(oldsecontext, secontext) != 0) {
        if (verbose)
            selinux_log(SELINUX_INFO,
                        "SELinux:  Relabeling %s from %s to %s.\n", pathname, oldsecontext, secontext);
        if (!nochange) {
            if (lsetfilecon(pathname, secontext) < 0)
                goto err;
        }
    }

    rc = 0;

out:
    freecon(oldsecontext);
    freecon(secontext);
    return rc;

err:
    selinux_log(SELINUX_ERROR,
                "SELinux: Could not set context for %s:  %s\n",
                pathname, strerror(errno));
    rc = -1;
    goto out;
}

#define SYS_PATH "/sys"
#define SYS_PREFIX SYS_PATH "/"

struct dir_hash_node {
    char* path;
    uint8_t digest[SHA1_HASH_SIZE];
    struct dir_hash_node *next;
};

// Returns true if the digest of all partial matched contexts is the same as the one
// saved by setxattr. Otherwise returns false and constructs a dir_hash_node with the
// newly calculated digest.
static bool check_context_match_for_dir(const char *pathname, struct dir_hash_node **new_node,
                                        bool force, int error) {
    uint8_t read_digest[SHA1_HASH_SIZE];
    ssize_t read_size = getxattr(pathname, RESTORECON_PARTIAL_MATCH_DIGEST,
                     read_digest, SHA1_HASH_SIZE);
    uint8_t calculated_digest[SHA1_HASH_SIZE];
    bool status = selabel_hash_all_partial_matches(fc_sehandle, pathname,
                               calculated_digest);

    if (!new_node) {
        return false;
    }
    *new_node = NULL;
    if (!force && status && read_size == SHA1_HASH_SIZE &&
        memcmp(read_digest, calculated_digest, SHA1_HASH_SIZE) == 0) {
        return true;
    }

    // Save the digest of all matched contexts for the current directory.
    if (!error && status) {
        *new_node = calloc(1, sizeof(struct dir_hash_node));
        if (*new_node == NULL) {
            selinux_log(SELINUX_ERROR,
                        "SELinux: %s: Out of memory\n", __func__);
            return false;
        }

        (*new_node)->path = strdup(pathname);
        if ((*new_node)->path == NULL) {
            selinux_log(SELINUX_ERROR,
                        "SELinux: %s: Out of memory\n", __func__);
            free(*new_node);
            *new_node = NULL;
            return false;
        }
        memcpy((*new_node)->digest, calculated_digest, SHA1_HASH_SIZE);
        (*new_node)->next = NULL;
    }

    return false;
}

static int selinux_android_restorecon_common(const char* pathname_orig,
                                             const char *seinfo,
                                             uid_t uid,
                                             unsigned int flags)
{
    bool nochange = (flags & SELINUX_ANDROID_RESTORECON_NOCHANGE) ? true : false;
    bool verbose = (flags & SELINUX_ANDROID_RESTORECON_VERBOSE) ? true : false;
    bool recurse = (flags & SELINUX_ANDROID_RESTORECON_RECURSE) ? true : false;
    bool force = (flags & SELINUX_ANDROID_RESTORECON_FORCE) ? true : false;
    bool datadata = (flags & SELINUX_ANDROID_RESTORECON_DATADATA) ? true : false;
    bool skipce = (flags & SELINUX_ANDROID_RESTORECON_SKIPCE) ? true : false;
    bool cross_filesystems = (flags & SELINUX_ANDROID_RESTORECON_CROSS_FILESYSTEMS) ? true : false;
    bool setrestoreconlast = (flags & SELINUX_ANDROID_RESTORECON_SKIP_SEHASH) ? false : true;
    bool issys;
    struct stat sb;
    struct statfs sfsb;
    FTS *fts;
    FTSENT *ftsent;
    char *pathname = NULL, *pathdnamer = NULL, *pathdname, *pathbname;
    char * paths[2] = { NULL , NULL };
    int ftsflags = FTS_NOCHDIR | FTS_PHYSICAL;
    int error, sverrno;
    struct dir_hash_node *current = NULL;
    struct dir_hash_node *head = NULL;

    if (!cross_filesystems) {
        ftsflags |= FTS_XDEV;
    }

    if (is_selinux_enabled() <= 0)
        return 0;

    __selinux_once(fc_once, file_context_init);

    if (!fc_sehandle)
        return 0;

    /*
     * Convert passed-in pathname to canonical pathname by resolving realpath of
     * containing dir, then appending last component name.
     */
    pathbname = basename(pathname_orig);
    if (!strcmp(pathbname, "/") || !strcmp(pathbname, ".") || !strcmp(pathbname, "..")) {
        pathname = realpath(pathname_orig, NULL);
        if (!pathname)
            goto realpatherr;
    } else {
        pathdname = dirname(pathname_orig);
        pathdnamer = realpath(pathdname, NULL);
        if (!pathdnamer)
            goto realpatherr;
        if (!strcmp(pathdnamer, "/"))
            error = asprintf(&pathname, "/%s", pathbname);
        else
            error = asprintf(&pathname, "%s/%s", pathdnamer, pathbname);
        if (error < 0)
            goto oom;
    }

    paths[0] = pathname;
    issys = (!strcmp(pathname, SYS_PATH)
            || !strncmp(pathname, SYS_PREFIX, sizeof(SYS_PREFIX)-1)) ? true : false;

    if (!recurse) {
        if (lstat(pathname, &sb) < 0) {
            error = -1;
            goto cleanup;
        }

        error = restorecon_sb(pathname, &sb, nochange, verbose, seinfo, uid);
        goto cleanup;
    }

    /*
     * Ignore saved partial match digest on /data/data or /data/user
     * since their labeling is based on seapp_contexts and seinfo
     * assignments rather than file_contexts and is managed by
     * installd rather than init.
     */
    if (is_app_data_path(pathname))
        setrestoreconlast = false;

    /* Also ignore on /sys since it is regenerated on each boot regardless. */
    if (issys)
        setrestoreconlast = false;

    /* Ignore files on in-memory filesystems */
    if (statfs(pathname, &sfsb) == 0) {
        if (sfsb.f_type == RAMFS_MAGIC || sfsb.f_type == TMPFS_MAGIC)
            setrestoreconlast = false;
    }

    fts = fts_open(paths, ftsflags, NULL);
    if (!fts) {
        error = -1;
        goto cleanup;
    }

    error = 0;
    while ((ftsent = fts_read(fts)) != NULL) {
        switch (ftsent->fts_info) {
        case FTS_DC:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Directory cycle on %s.\n", ftsent->fts_path);
            errno = ELOOP;
            error = -1;
            goto out;
        case FTS_DP:
            continue;
        case FTS_DNR:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Could not read %s: %s.\n", ftsent->fts_path, strerror(errno));
            fts_set(fts, ftsent, FTS_SKIP);
            continue;
        case FTS_NS:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Could not stat %s: %s.\n", ftsent->fts_path, strerror(errno));
            fts_set(fts, ftsent, FTS_SKIP);
            continue;
        case FTS_ERR:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Error on %s: %s.\n", ftsent->fts_path, strerror(errno));
            fts_set(fts, ftsent, FTS_SKIP);
            continue;
        case FTS_D:
            if (issys && !selabel_partial_match(fc_sehandle, ftsent->fts_path)) {
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            }

            if (!datadata && !fnmatch(USER_PROFILE_PATH, ftsent->fts_path, FNM_PATHNAME)) {
                // Don't label this directory, vold takes care of that, but continue below it.
                continue;
            }

            if (setrestoreconlast) {
                struct dir_hash_node* new_node = NULL;
                if (check_context_match_for_dir(ftsent->fts_path, &new_node, force, error)) {
                    selinux_log(SELINUX_INFO,
                                "SELinux: Skipping restorecon on directory(%s)\n",
                                ftsent->fts_path);
                    fts_set(fts, ftsent, FTS_SKIP);
                    continue;
                }
                if (new_node) {
                    if (!current) {
                        current = new_node;
                        head = current;
                    } else {
                        current->next = new_node;
                        current = current->next;
                    }
                }
            }

            if (skipce &&
                (!strncmp(ftsent->fts_path, DATA_SYSTEM_CE_PATH, sizeof(DATA_SYSTEM_CE_PATH)-1) ||
                 !strncmp(ftsent->fts_path, DATA_MISC_CE_PATH, sizeof(DATA_MISC_CE_PATH)-1) ||
                 !strncmp(ftsent->fts_path, DATA_VENDOR_CE_PATH, sizeof(DATA_VENDOR_CE_PATH)-1))) {
                // Don't label anything below this directory.
                fts_set(fts, ftsent, FTS_SKIP);
                // but fall through and make sure we label the directory itself
            }

            if (!datadata && is_app_data_path(ftsent->fts_path)) {
                // Don't label anything below this directory.
                fts_set(fts, ftsent, FTS_SKIP);
                // but fall through and make sure we label the directory itself
            }
            /* fall through */
        default:
            error |= restorecon_sb(ftsent->fts_path, ftsent->fts_statp, nochange, verbose, seinfo, uid);
            break;
        }
    }

    // Labeling successful. Write the partial match digests for subdirectories.
    // TODO: Write the digest upon FTS_DP if no error occurs in its descents.
    if (setrestoreconlast && !nochange && !error) {
        current = head;
        while (current != NULL) {
            if (setxattr(current->path, RESTORECON_PARTIAL_MATCH_DIGEST, current->digest,
                    SHA1_HASH_SIZE, 0) < 0) {
                selinux_log(SELINUX_ERROR,
                            "SELinux:  setxattr failed: %s:  %s\n",
                            current->path,
                            strerror(errno));
            }
            current = current->next;
        }
    }

out:
    sverrno = errno;
    (void) fts_close(fts);
    errno = sverrno;
cleanup:
    free(pathdnamer);
    free(pathname);
    current = head;
    while (current != NULL) {
        struct dir_hash_node *next = current->next;
        free(current->path);
        free(current);
        current = next;
    }
    return error;
oom:
    sverrno = errno;
    selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __FUNCTION__);
    errno = sverrno;
    error = -1;
    goto cleanup;
realpatherr:
    sverrno = errno;
    selinux_log(SELINUX_ERROR, "SELinux: Could not get canonical path for %s restorecon: %s.\n",
            pathname_orig, strerror(errno));
    errno = sverrno;
    error = -1;
    goto cleanup;
}

int selinux_android_restorecon(const char *file, unsigned int flags)
{
    return selinux_android_restorecon_common(file, NULL, -1, flags);
}

int selinux_android_restorecon_pkgdir(const char *pkgdir,
                                      const char *seinfo,
                                      uid_t uid,
                                      unsigned int flags)
{
    return selinux_android_restorecon_common(pkgdir, seinfo, uid, flags | SELINUX_ANDROID_RESTORECON_DATADATA);
}


void selinux_android_set_sehandle(const struct selabel_handle *hndl)
{
      fc_sehandle = (struct selabel_handle *) hndl;
}

int selinux_android_load_policy()
{
	selinux_log(SELINUX_ERROR, "selinux_android_load_policy is not implemented\n");
	return -1;
}

int selinux_android_load_policy_from_fd(int fd __attribute__((unused)), const char *description __attribute__((unused)))
{
	selinux_log(SELINUX_ERROR, "selinux_android_load_policy_from_fd is not implemented\n");
	return -1;
}
