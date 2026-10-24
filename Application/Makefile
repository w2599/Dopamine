.PHONY: all clean build_clean

all: Dopamine.ipa

Dopamine.ipa: build/Build/Products/Debug-iphoneos/Dopamine.app
	# 暂不打包 1800，同时移除旧构建目录遗留的副本。
	rm -f build/Build/Products/Debug-iphoneos/Dopamine.app/bootstrap_1800.tar.zst
	# 不再打包 palera1n，并清理增量构建中的旧框架。
	rm -rf build/Build/Products/Debug-iphoneos/Dopamine.app/Frameworks/palera1n.framework
	@echo Ad-Hoc signing Dopamine
	xattr -rc build/Build/Products/Debug-iphoneos/Dopamine.app
	ldid -SDopamine/Dopamine.entitlements build/Build/Products/Debug-iphoneos/Dopamine.app/Dopamine
	ldid -s build/Build/Products/Debug-iphoneos/Dopamine.app
	rm -rf Payload Dopamine.ipa
	mkdir Payload
	cp -r build/Build/Products/Debug-iphoneos/Dopamine.app Payload/Dopamine.app
	zip -Ar Dopamine.ipa Payload
	rm -rf Payload
	rm -rf Dopamine.tipa
	cp Dopamine.ipa Dopamine.tipa

ifeq ($(NIGHTLY), 1)
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"'
else
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
endif
	touch build/Build/Products/Debug-iphoneos/Dopamine.app/Dopamine.roothide
	cp -a Dopamine/Resources/*.deb build/Build/Products/Debug-iphoneos/Dopamine.app/
	cp ../BaseBin/.build/libroothider.dylib build/Build/Products/Debug-iphoneos/Dopamine.app/
	plutil -replace CFBundleIdentifier -string "cn.zqbb.dopaRH" build/Build/Products/Debug-iphoneos/Dopamine.app/Info.plist
	plutil -replace CFBundleShortVersionString -string "$(shell cat ../BaseBin/_external/basebin/.version)-$(shell cat ../BaseBin/_external/basebin/.version-roothide)" build/Build/Products/Debug-iphoneos/Dopamine.app/Info.plist
	plutil -replace DOBuildTimestamp -integer "$(BUILD_TIMESTAMP)" build/Build/Products/Debug-iphoneos/Dopamine.app/Info.plist


clean:
	rm -rf build Payload Dopamine.ipa Dopamine.tipa

build_clean:
	rm -rf Payload build

FORCE: ;
