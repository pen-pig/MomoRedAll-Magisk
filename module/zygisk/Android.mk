LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := zygisk
LOCAL_SRC_FILES := zygisk.cpp
LOCAL_LDLIBS := -llog
LOCAL_CFLAGS := -O2 -fvisibility=hidden
include $(BUILD_SHARED_LIBRARY)
