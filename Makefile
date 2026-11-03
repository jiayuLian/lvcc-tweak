TARGET := iphone:clang:latest:14.0
ARCHS := arm64 arm64e
INSTALL_TARGET_PROCESSES = Charge

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LvccLogin
LvccLogin_FILES = Tweak.x
LvccLogin_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function
LvccLogin_FRAMEWORKS = UIKit Foundation Security

include $(THEOS)/makefiles/tweak.mk
