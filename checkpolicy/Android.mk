LOCAL_PATH:= $(call my-dir)

common_src_files := \
	policy_parse.y \
	policy_scan.l \
	queue.c \
	module_compiler.c \
	parse_util.c \
	policy_define.c

common_cflags := \
	-Wall -Wshadow -O2 \
	-pipe -fno-strict-aliasing \

##
# checkpolicy
#
include $(CLEAR_VARS)

LOCAL_MODULE := checkpolicy
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files) checkpolicy.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_YACCFLAGS := -v
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)


##
# checkmodule
#
include $(CLEAR_VARS)

LOCAL_MODULE := checkmodule
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files) checkmodule.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_YACCFLAGS := -v
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)

##
# dispol
#
include $(CLEAR_VARS)

LOCAL_MODULE := dispol
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := test/dispol.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
