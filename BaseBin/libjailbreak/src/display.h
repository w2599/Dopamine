#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <CoreGraphics/CoreGraphics.h>
#include <IOMobileFramebuffer/IOMobileFramebuffer.h>
#include <IOSurface/IOSurfaceRef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct drawctx {
	bool inited;
	void *base;
	IOMobileFramebufferDisplaySize size;
	int bytesPerRow;
	IOMobileFramebufferRef framebuffer;
	IOSurfaceRef surface;
};

int draw_image_to_buf(CGImageRef cgImage, IOMobileFramebufferDisplaySize size, CGFloat rotation, void **bufOut, size_t *bufSizeOut);
int draw_image_to_buf_for_main_screen(CGImageRef image, void **bufOut, size_t *bufSizeOut);
int draw_image_path_to_buf(const char *image_path, IOMobileFramebufferDisplaySize size, CGFloat rotation, void **bufOut, size_t *bufSizeOut);
int draw_image_path_to_buf_for_main_screen(const char *image_path, void **bufOut, size_t *bufSizeOut);
int save_image_bitmap_to_plist(CGImageRef imageRef, const char *outPath);
CGImageRef load_image_from_bitmap_plist(const char *bitmapPlistPath);

CGSize find_display_size(void);
struct drawctx *drawctx_init(void);
void drawctx_free(struct drawctx *ctx);
int drawctx_draw_raw_path(struct drawctx *ctx, const char *path);
int drawctx_draw_raw(struct drawctx *ctx, void *rawBuf, size_t rawBufSize);
int drawctx_draw_image_path(struct drawctx *ctx, const char *image_path);
int drawctx_draw_image(struct drawctx *ctx, CGImageRef cgImage);

#ifdef __cplusplus
}
#endif

#endif // DISPLAY_H
