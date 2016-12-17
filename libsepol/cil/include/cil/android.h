#ifndef _SEPOL_ANDROID_H_
#define _SEPOL_ANDROID_H_
#include <cil/cil.h>

#define PLAT_VERS "curr"
#define PLAT_ID "p"
#define NON_PLAT_ID "n"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * cil_android_attrib_mapping - extract attributizable elements of the policy in
 * srcdb and create the mapping file necessary to link the platform and
 * non-platform policy files after non-platform policy attributization.
 *   mdb - uninitialized cil_db reference to the resulting policy. Caller
 *         responsibility to destroy.
 *   srcdb - initialized and parsed cil_db reference to source public policy.
 *   num - the version string to append types when converted to attributes.
 * returns SEPOL_OK if successful, otherwise passes on the encountered error.
 */
int cil_android_attrib_mapping(struct cil_db **mdb, struct cil_db *srcdb, const char *num);

/*
 * cil_android_attributize - extract attributizable elements of the policy in
 * srcdb and convert all usage of those elements in tgtdb to versioned attributes.
 *   tgtdb - initialized and parsed cil_db reference to modify.
 *   srcdb - initialized and parsed cil_db reference to source public policy
 *           from which to extract attributizable elements.
 *   num - the version string to append types when converted to attributes.
 * returns SEPOL_OK if successful, otherwise passes on the encountered error.
 */
int cil_android_attributize(struct cil_db *tgtdb, struct cil_db *srcdb, const char *num);

/*
 * cil_android_compile_policy - compile selinux policy from given source files.
 */
int cil_android_compile_policy(void **data, size_t *pol_len,
                               const char *const pol_files[], size_t num_files);

#ifdef __cplusplus
}
#endif
#endif /* _SEPOL_ANDROID_H_ */
