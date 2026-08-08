.PHONY: all clean build_clean

OUT_FILE = Dopamine.tar

all: $(OUT_FILE)

$(OUT_FILE): FORCE
	@mkdir -p .build
	@cp ../BaseBin/basebin.tar .build/basebin.tar
	@cp ../BaseBin/dopamine/dopamine .build/dopamine
	@mkdir -p .build/Packages
	@cp $(wildcard ../Packages/*/*.deb) .build/Packages
	@DYLD_FALLBACK_LIBRARY_PATH="../BaseBin" ../BaseBin/tar --transform "s|^.build|.|" -cvf "$(OUT_FILE)" ".build" --owner=0 --group=0

clean:
	rm -rf build Dopamine.tar

build_clean:
	rm -rf build

FORCE: ;