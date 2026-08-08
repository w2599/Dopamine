HOOKD_SKIP_CALLER_VERIFICATION ?= 0

TARGET = hookd

CC = clang

CFLAGS = -I../.include -I./src -DHOOKD_SKIP_CALLER_VERIFICATION=$(HOOKD_SKIP_CALLER_VERIFICATION) -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -Wno-availability -miphoneos-version-min=15.0 -D BUILD_STANDALONE=$(BUILD_STANDALONE) 
LDFLAGS = -lbsm

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(wildcard src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)