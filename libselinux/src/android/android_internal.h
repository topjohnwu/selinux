#pragma once

#include <sys/types.h>

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


#ifdef __cplusplus
}
#endif
