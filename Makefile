TARGET := iphone:clang:latest:14.0
# 单架构 arm64：iPhone 13(A15) 跑 arm64 足够，避免 fat 与老版 ldid 的兼容问题
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

# 关键：必须用 library.mk，不能用 tweak.mk。
# tweak.mk 会自动 -lsubstrate，产物带
#   /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate
# 与 _MSHookFunction / _MSHookMessageEx 未定义符号。
# TrollStore 设备没装 ElleKit/Substrate 时 dyld 加载失败 -> App 一启动就闪退。
LIBRARY_NAME = LvccLogin
LvccLogin_FILES = Lvcc.m
LvccLogin_CFLAGS = -fobjc-arc -g0 -Wno-deprecated-declarations -Wno-unused-function -Wno-unused-variable
LvccLogin_FRAMEWORKS = UIKit Foundation Security
LvccLogin_LDFLAGS = -Wl,-install_name,@rpath/LvccLogin.dylib -Wl,-dead_strip

include $(THEOS)/makefiles/library.mk
