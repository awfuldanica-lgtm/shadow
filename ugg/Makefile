ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

# ---------- App ----------
APPLICATION_NAME = Ugg
Ugg_FILES = App/main.m App/AppDelegate.m \
    App/UggConfig.m \
    App/MainViewController.m \
    App/DeviceInfoViewController.m \
    App/TargetAppsViewController.m \
    App/BackupViewController.m \
    App/SettingsViewController.m \
    App/AboutViewController.m
Ugg_FRAMEWORKS = UIKit Foundation
Ugg_CFLAGS = -fobjc-arc
Ugg_CODESIGN_FLAGS = -Sentitlements.xml
Ugg_INFO_PLIST_PATH = App/Info.plist

# ---------- Tweak ----------
TWEAK_NAME = ugg
ugg_FILES = Tweak.x
ugg_FRAMEWORKS = Foundation UIKit
ugg_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/application.mk
include $(THEOS_MAKE_PATH)/tweak.mk
