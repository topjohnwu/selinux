LOCAL_PATH:= $(call my-dir)

common_src_files := secilc.c

common_cflags := \
	-Wall -Wshadow -O2 \
	-pipe -fno-strict-aliasing \

##
# secilc on the host.
#
include $(CLEAR_VARS)

LOCAL_MODULE := secilc
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := secilc.c
LOCAL_SHARED_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)

##
# secilc on the target.
#
include $(CLEAR_VARS)

LOCAL_MODULE := secilc
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := secilc.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)
