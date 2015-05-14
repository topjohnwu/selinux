LOCAL_PATH:= $(call my-dir)

common_HOST_FILES := \
    src/enabled.c \
    src/setrans_client.c \
    src/callbacks.c \
    src/check_context.c \
    src/freecon.c \
    src/init.c \
    src/label.c \
    src/lgetfilecon.c \
    src/canonicalize_context.c \
    src/matchpathcon.c \
    src/label_media.c \
    src/label_x.c \
    src/label_db.c \
    src/seusers.c \
    src/load_policy.c \
    src/policyvers.c \
    src/selinux_config.c \
    src/label_file.c \
    src/lsetfilecon.c \
    src/disable.c \
    src/booleans.c \
    src/getenforce.c \
    src/setenforce.c \
    src/label_android_property.c

common_COPY_HEADERS_TO := selinux
common_COPY_HEADERS := \
    include/selinux/selinux.h \
    include/selinux/label.h \
    include/selinux/context.h \
    include/selinux/avc.h \
    include/selinux/get_default_type.h

include $(CLEAR_VARS)
LOCAL_CFLAGS := -DHOST -D_GNU_SOURCE

ifeq ($(HOST_OS),darwin)
LOCAL_CFLAGS += -DDARWIN
endif

LOCAL_SRC_FILES := $(common_HOST_FILES)
LOCAL_MODULE:= libselinux
LOCAL_MODULE_TAGS := eng
LOCAL_WHOLE_STATIC_LIBRARIES := libpcre libsepol
LOCAL_C_INCLUDES := external/pcre
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -DHOST -D_GNU_SOURCE

ifeq ($(HOST_OS),darwin)
LOCAL_CFLAGS += -DDARWIN
endif

LOCAL_SRC_FILES := $(common_HOST_FILES)
LOCAL_MODULE:= libselinux
LOCAL_MODULE_TAGS := eng
LOCAL_COPY_HEADERS_TO := $(common_COPY_HEADERS_TO)
LOCAL_COPY_HEADERS := $(common_COPY_HEADERS)
LOCAL_WHOLE_STATIC_LIBRARIES := libpcre libsepol
LOCAL_C_INCLUDES := external/pcre
include $(BUILD_HOST_SHARED_LIBRARY)
