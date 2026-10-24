#ifndef TROLLSTORE_LITE_TXM_H
#define TROLLSTORE_LITE_TXM_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <spawn.h>

struct trollstore_lite_txm_lease;
#define TROLLSTORE_LITE_TXM_MAX_IMAGES 128
struct trollstore_lite_txm_session {
    size_t count;
    struct trollstore_lite_txm_lease *images[TROLLSTORE_LITE_TXM_MAX_IMAGES];
};
int trollstore_lite_txm_begin(const char *path, const posix_spawnattr_t *attributes,
                        struct trollstore_lite_txm_session **session);
int trollstore_lite_txm_end(struct trollstore_lite_txm_session *session, pid_t pid);
// 内部接口：接管 fd，按签名地址共享租约；失败时也负责释放或保留 fd。
int trollstore_lite_txm_acquire(int fd, uint64_t vnode, uint64_t address,
                          struct trollstore_lite_txm_lease **lease);
#endif
