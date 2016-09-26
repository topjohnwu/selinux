LOCAL_PATH:= $(call my-dir)

# This Android.mk serves only to build sefcontext_compile. This was needed
# to work-around an issue/bug in the blueprint files. See the Android.bp
# file in the same directory for more details.

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := sefcontext_compile
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -DUSE_PCRE2 -DNO_PERSISTENTLY_STORED_PATTERNS
LOCAL_SRC_FILES := utils/sefcontext_compile.c
LOCAL_STATIC_LIBRARIES := libsepol libselinux
LOCAL_WHOLE_STATIC_LIBRARIES := libpcre2
LOCAL_CXX_STL := none

include $(BUILD_HOST_EXECUTABLE)
