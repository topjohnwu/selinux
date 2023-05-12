#include <ctype.h>
#include <limits.h>
#include <linux/magic.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <selinux/context.h>
#include <selinux/selinux.h>

#include "android_internal.h"
#include "callbacks.h"
#include "selinux_internal.h"

/* Locations for the file_contexts files. For each partition, only the first
 * existing entry will be used (for example, if
 * /system/etc/selinux/plat_file_contexts exists, /plat_file_contexts will be
 * ignored).
 */
static const path_alts_t file_context_paths = { .paths = {
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
}};

/* Locations for the seapp_contexts files. For each partition, only the first
 * existing entry will be used (for example, if
 * /system/etc/selinux/plat_seapp_contexts exists, /plat_seapp_contexts will be
 * ignored).
 */
static const path_alts_t seapp_context_paths = { .paths = {
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
}};

/* Returns a handle for the file contexts backend, initialized with the Android
 * configuration */
struct selabel_handle* selinux_android_file_context_handle(void)
{
	const char* file_contexts[MAX_CONTEXT_PATHS];
	struct selinux_opt opts[MAX_CONTEXT_PATHS + 1];
	int npaths, nopts;

	npaths = find_existing_files(&file_context_paths, file_contexts);
	paths_to_opts(file_contexts, npaths, opts);

	opts[npaths].type = SELABEL_OPT_BASEONLY;
	opts[npaths].value = (char *) 1;
	nopts = npaths + 1;

	return initialize_backend(SELABEL_CTX_FILE, "file", opts, nopts);
}

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
	bool isIsolatedComputeApp;
	bool isSdkSandboxNext;
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
		(s1->isEphemeralAppSet && s1->isEphemeralApp == s2->isEphemeralApp) &&
		(s1->isIsolatedComputeApp && s1->isIsolatedComputeApp == s2->isIsolatedComputeApp) &&
		(s1->isSdkSandboxNext && s1->isSdkSandboxNext == s2->isSdkSandboxNext);

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

int seapp_context_reload_internal(const path_alts_t *context_paths)
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

	files_len = find_existing_files(context_paths, seapp_contexts_files);

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
				} else if (!strcasecmp(name, "isIsolatedComputeApp")) {
					if (!strcasecmp(value, "true"))
						cur->isIsolatedComputeApp = true;
					else if (!strcasecmp(value, "false"))
						cur->isIsolatedComputeApp = false;
					else {
						free_seapp_context(cur);
						goto err;
					}
				} else if (!strcasecmp(name, "isSdkSandboxNext")) {
					if (!strcasecmp(value, "true"))
						cur->isSdkSandboxNext = true;
					else if (!strcasecmp(value, "false"))
						cur->isSdkSandboxNext = false;
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
			selinux_log(SELINUX_INFO, "%s:  isSystemServer=%s isEphemeralApp=%s isIsolatedComputeApp=%s isSdkSandboxNext=%s user=%s seinfo=%s "
					"name=%s isPrivApp=%s minTargetSdkVersion=%d fromRunAs=%s -> domain=%s type=%s level=%s levelFrom=%s",
				__FUNCTION__,
				cur->isSystemServer ? "true" : "false",
				cur->isEphemeralAppSet ? (cur->isEphemeralApp ? "true" : "false") : "null",
				cur->user.str,
				cur->seinfo, cur->name.str,
				cur->isPrivAppSet ? (cur->isPrivApp ? "true" : "false") : "null",
				cur->minTargetSdkVersion,
				cur->fromRunAs ? "true" : "false",
				cur->isIsolatedComputeApp ? "true" : "false",
				cur->isSdkSandboxNext ? "true" : "false",
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

int selinux_android_seapp_context_reload(void)
{
	return seapp_context_reload_internal(&seapp_context_paths);
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

#define PRIVILEGED_APP_STR ":privapp"
#define ISOLATED_COMPUTE_APP_STR ":isolatedComputeApp"
#define APPLY_SDK_SANDBOX_NEXT_RESTRICTIONS_STR ":isSdkSandboxNext"
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
int set_range_from_level(context_t ctx, enum levelFrom levelFrom, uid_t userid, uid_t appid)
{
	char level[255];
	switch (levelFrom) {
	case LEVELFROM_NONE:
		strncpy(level, "s0", sizeof level);
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

/*
 * This code is Android specific, bionic guarantees that
 * calls to non-reentrant getpwuid() are thread safe.
 */
struct passwd *(*seapp_getpwuid)(uid_t uid) = getpwuid;

int seapp_context_lookup_internal(enum seapp_kind kind,
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
	bool isIsolatedComputeApp = false;
	bool isSdkSandboxNext = false;
	int32_t targetSdkVersion = 0;
	bool fromRunAs = false;
	char parsedseinfo[BUFSIZ];

	if (seinfo) {
		if (seinfo_parse(parsedseinfo, seinfo, BUFSIZ))
			goto err;
		isPrivApp = strstr(seinfo, PRIVILEGED_APP_STR) ? true : false;
		isEphemeralApp = strstr(seinfo, EPHEMERAL_APP_STR) ? true : false;
		isIsolatedComputeApp = strstr(seinfo, ISOLATED_COMPUTE_APP_STR) ? true : false;
		isSdkSandboxNext = strstr(seinfo, APPLY_SDK_SANDBOX_NEXT_RESTRICTIONS_STR) ? true : false;
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
		pwd = seapp_getpwuid(appid);
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

		if (cur->isIsolatedComputeApp != isIsolatedComputeApp)
			continue;

		if (cur->isSdkSandboxNext != isSdkSandboxNext)
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

int seapp_context_lookup(enum seapp_kind kind,
				uid_t uid,
				bool isSystemServer,
				const char *seinfo,
				const char *pkgname,
				context_t ctx)
{
	// Ensure the default context files are loaded.
	selinux_android_seapp_context_init();
	return seapp_context_lookup_internal(kind, uid, isSystemServer, seinfo, pkgname, ctx);
}
