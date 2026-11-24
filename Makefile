TARGET := iphone:clang:latest:15.0
ARCHS := arm64
THEOS_PACKAGE_SCHEME = rootless

TWEAK_NAME = XBookEnhancer
XBookEnhancer_FILES = Tweak.x Menu.m CopyrightAnimation.m
XBookEnhancer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function
XBookEnhancer_FRAMEWORKS = UIKit Foundation Photos AVFoundation CoreServices

# Linux 上的 ld64.lld 不实现 -iphoneos_version_min，必须显式给出 platform_version
# 注意：链接由 clang 驱动，所以要用 -Wl, 形式转发给底层 ld64.lld
ifeq ($(shell uname -s),Linux)
XBookEnhancer_LDFLAGS += -Wl,-platform_version,ios,15.0,16.5
endif

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 discover || true"
