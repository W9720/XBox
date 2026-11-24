TARGET := iphone:clang:latest:15.0
ARCHS := arm64
THEOS_PACKAGE_SCHEME = rootless

TWEAK_NAME = XBookEnhancer
XBookEnhancer_FILES = Tweak.x Menu.m CopyrightAnimation.m
XBookEnhancer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function
XBookEnhancer_FRAMEWORKS = UIKit Foundation Photos AVFoundation CoreServices

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 discover || true"
