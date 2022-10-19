#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include <selinux/context.h>
#include <selinux/selinux.h>

#ifdef __cplusplus
extern "C" {
#endif

// Context files (file_contexts, service_contexts, etc) may be spread over
// multiple partitions: system, apex, system_ext, product, vendor and/or odm.
#define MAX_CONTEXT_PATHS 6
// The maximum number of alternatives for a file on one partition.
#define MAX_ALT_CONTEXT_PATHS 2
typedef struct path_alts {
	const char *paths[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS];
} path_alts_t;

/* Within each set of files, adds the first file that is accessible to `paths`.
 * Returns the number of accessible files. */
size_t find_existing_files(
	const path_alts_t *path_sets,
	const char *paths[MAX_CONTEXT_PATHS]);

/* Converts an array of file paths into an array of options for selabel_open.
 * opts must be at least as large as paths. */
void paths_to_opts(
	const char* paths[MAX_CONTEXT_PATHS],
	size_t npaths,
	struct selinux_opt* const opts);

/* Initialize a backend using the specified options. Ensure that any error is
 * reported to the android logging facility */
struct selabel_handle* initialize_backend(
	unsigned int backend,
	const char* name,
	const struct selinux_opt* opts,
	size_t nopts);

/* Initialize a backend using a set of context paths */
struct selabel_handle* context_handle(
		unsigned int backend,
		const path_alts_t *context_paths,
		const char* name);

/* The kind of request when looking up an seapp_context. */
enum seapp_kind {
	/* Returns the SELinux type for the app data directory */
	SEAPP_TYPE,
	/* Returns the SELinux type for the app process */
	SEAPP_DOMAIN
};

/* Search an app (or its data) based on its name and information within the list
 * of known seapp_contexts. If found, sets the type and categories of ctx and
 * returns 0. Returns -1 in case of error; -2 for out of memory */
int seapp_context_lookup(enum seapp_kind kind,
				uid_t uid,
				bool isSystemServer,
				const char *seinfo,
				const char *pkgname,
				context_t ctx);

/* Similar to seapp_context_lookup, but does not implicitly load and use the
 * default context files. It should only be used for unit tests. */
int seapp_context_lookup_internal(enum seapp_kind kind,
				uid_t uid,
				bool isSystemServer,
				const char *seinfo,
				const char *pkgname,
				context_t ctx);

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

/* Sets the categories of ctx based on the level request */
int set_range_from_level(context_t ctx, enum levelFrom levelFrom, uid_t userid, uid_t appid);

/* Similar to seapp_context_reload, but does not implicitly load the default
 * context files. It should only be used for unit tests. */
int seapp_context_reload_internal(const path_alts_t *context_paths);
#ifdef __cplusplus
}
#endif
