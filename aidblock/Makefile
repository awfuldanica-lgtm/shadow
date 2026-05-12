ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = aidblock
aidblock_FILES = Tweak.x
aidblock_FRAMEWORKS = UIKit Foundation
aidblock_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
