ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
ADDITIONAL_CFLAGS += -DTHEOS_PACKAGE_SCHEME_ROOTLESS=1
endif
SUBPROJECTS += Shadow.framework
SUBPROJECTS += Shadow.dylib
# ShadowSettings.bundle dropped — SMBC bypass is hardcoded in
# Shadow.dylib/hooks/smbc.x, no per-app config UI required.
SUBPROJECTS += shdw
include $(THEOS_MAKE_PATH)/aggregate.mk
