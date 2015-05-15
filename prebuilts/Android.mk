ifeq ($(HOST_OS), linux)

LOCAL_PATH:= $(call my-dir)
##
# libselinux.so host prebuilt
#
include $(CLEAR_VARS)
LOCAL_PREBUILT_LIBS := lib/libselinux.so.1
include $(BUILD_HOST_PREBUILT)

##
# audit2allow/audit2why prebuilt
# Shell wrapper that sets the LD_LIBRARY_PATH and calls the
# audit2allow/why python script
#
include $(CLEAR_VARS)
LOCAL_PREBUILT_EXECUTABLES := usr/bin/audit2allow \
                              usr/bin/audit2why
include $(BUILD_HOST_PREBUILT)

endif # ($(HOST_OS), linux)
