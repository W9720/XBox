TARGET := iphone:clang:latest:15.0
ARCHS := arm64
THEOS_PACKAGE_SCHEME = rootless

TWEAK_NAME = XBookEnhancer
XBookEnhancer_FILES = Tweak.x Menu.m CopyrightAnimation.m
XBookEnhancer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function
XBookEnhancer_FRAMEWORKS = UIKit Foundation Photos AVFoundation CoreServices

# Linux 上没有 Xcode 的 Mach-O 链接器，强制 clang 使用 LLVM 的 ld64.lld
ifeq ($(shell uname -s),Linux)
XBookEnhancer_LDFLAGS = -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld64.lld
endif

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 discover || true"
