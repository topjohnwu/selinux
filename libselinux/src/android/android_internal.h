#include <sys/types.h>

#include "android_common.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Within each set of files, adds the first file that is accessible to `paths`.
 * Returns the number of accessible files. */
size_t find_existing_files(
	const char* const path_sets[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS],
	const char* paths[MAX_CONTEXT_PATHS]);

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
		const char* const context_paths[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS],
		const char* name);


#ifdef __cplusplus
}
#endif
