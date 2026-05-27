ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ugg
ugg_FILES = Tweak.x
ugg_FRAMEWORKS = Foundation UIKit CoreTelephony
ugg_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
