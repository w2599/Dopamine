TARGET = dopamine

CC = clang

CHOMA_CFLAGS = -DDISABLE_SIGNING=1
XPF_CFLAGS = -DUSE_COMMONCRYPTO -DUSE_LIBCOMPRESSION -DiOS10 -DDER_MULTIBYTE_TAGS=1 -D__unused="__attribute__((unused))" -DDER_TAG_SIZE=8 -I../XPF/external/img4lib -Wno-variadic-macros -Wno-multichar -Wno-four-char-constants -Wno-unused-parameter
XPF_DEPS = $(filter-out ../XPF/external/img4lib/libvfs/vfs_lzvn.c, $(wildcard ../XPF/external/img4lib/lzss.c ../XPF/external/img4lib/libvfs/*.c ../XPF/external/img4lib/libDER/*.c))

CFLAGS = $(XPF_CFLAGS) $(CHOMA_CFLAGS) -framework Security -framework Foundation -framework CoreServices -framework IOKit -framework IOSurface -framework Security -framework IOMobileFramebuffer -framework LocalAuthentication -weak_framework CoreGraphics -weak_framework ImageIO -I../.include -I./src -I./src/ui-stub -I../../Application/Dopamine/Jailbreak -I../../Application/Dopamine/Extensions -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -Wno-availability -miphoneos-version-min=15.0 -fobjc-arc -I$(shell brew --prefix)/opt/libarchive/include -Iexternal/include -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -L../.build -larchive -lbsm -lcompression -lMobileGestalt -F ../_external/frameworks

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(wildcard src/*.c src/*.m src/*.S src/ui-stub/*.m ../libjailbreak/src/*.c ../libjailbreak/src/*.m ../libjailbreak/src/*.S ../ChOma/src/*.c ../XPF/src/*.c ../../Application/Dopamine/Jailbreak/*.m ../../Application/Dopamine/Jailbreak/*.c ../../Application/Dopamine/Extensions/NSData+Hex.m external/lib/*.a) $(XPF_DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)