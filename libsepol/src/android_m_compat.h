/*
 * On Android 6.0, even though the policy version is POLICYDB_VERSION_XPERMS_IOCTL, it has a
 * different sepolicy binary format than the standard one.
 *
 * In the standard format, the avtab_extended_perms_t::specified field determines whether an
 * extended permission rule is IOCTLDRIVER or IOCTLFUNCTION.
 * On Android 6.0, there is no such avtab_extended_perms_t::specified field; instead,
 * IOCTLDRIVER and IOCTLFUNCTION has different avtab key specifications (avtab_key_t::specified)
 *
 * Our goal here is to add a compatibility layer, so that the rest of the library can treat
 * Android 6.0 policies as standard POLICYDB_VERSION_XPERMS_IOCTL format.
 */

#define AVTAB_OPTYPE_ALLOWED	0x1000
#define AVTAB_OPTYPE_AUDITALLOW	0x2000
#define AVTAB_OPTYPE_DONTAUDIT	0x4000
#define AVTAB_OPTYPE	(AVTAB_OPTYPE_ALLOWED | AVTAB_OPTYPE_AUDITALLOW | AVTAB_OPTYPE_DONTAUDIT)

#define avtab_xperms_to_optype(x) (x << 4)
#define avtab_optype_to_xperms(x) (x >> 4)

// Global indication whether an Android M policy is detected
extern unsigned avtab_android_m_compat;
