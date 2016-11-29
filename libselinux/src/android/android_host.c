#include <stdlib.h>

// HACK: placeholder for a library the python bindings expect.
// Delete after b/33170640 is fixed.
const char *selinux_openssh_contexts_path(void)
{
  abort();
}
