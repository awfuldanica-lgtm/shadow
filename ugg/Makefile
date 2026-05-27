ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

# ---------- Tweak only (App removed — platform app causes SpringBoard crash on roothide) ----------
TWEAK_NAME = ugg
ugg_FILES = Tweak.x
ugg_FRAMEWORKS = Foundation UIKit
ugg_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
