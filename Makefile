TARGET := iphone:clang:latest:14.0
# 单架构 arm64：A15(iPhone 13) 跑 arm64 完全够用。
# 用 fat(arm64+arm64e) 会让 TrollFools 内置的老版 ldid 在部分机型上直接摆烂。
ARCHS := arm64
INSTALL_TARGET_PROCESSES = Charge

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LvccLogin
LvccLogin_FILES = Tweak.x
LvccLogin_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function
LvccLogin_FRAMEWORKS = UIKit Foundation Security
# 关掉 debug 符号，避免产出 dSYM 干扰产物收集（上次就是被 dSYM 里的同名文件顶掉的）
LvccLogin_CFLAGS += -g0
LvccLogin_LDFLAGS = -Wl,-dead_strip

include $(THEOS)/makefiles/tweak.mk
