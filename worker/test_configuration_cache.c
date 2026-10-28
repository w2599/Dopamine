// 直接测试生产配置缓存，模拟替换、损坏、并发读取和 fork。
#include <CoreFoundation/CoreFoundation.h>
#include <xpc/xpc.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdatomic.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "_configuration.h"

extern xpc_object_t xpc_create_from_plist(const void *, size_t);
extern bool cache_test_foundation_bool(const char *);
static _Atomic unsigned open_calls, parse_calls, serial;
static _Atomic bool delay_parse, parsing, reader_failed;
static _Atomic bool delay_allocate, allocating, fail_allocate, fail_mutex;
static _Atomic bool delay_path_free, freeing_path;
static _Atomic(void *) tracked_path;
static const char *tracked_path_name;
static _Atomic unsigned allocation_arrivals, mutex_inits, mutex_destroys;
static bool race_initialization;
static const char *raw_string;
static CFDataRef fixtures[2];
static char test_root[PATH_MAX];

// 固定延迟只扩大真实临界区，不依赖子进程替父进程释放测试屏障。
static void pause_window(void) {
    struct timespec delay = {.tv_nsec = 200000000};
    nanosleep(&delay, NULL);
}

// 覆盖首次状态分配失败、竞争发布和发布前 fork。
void *cache_test_calloc(size_t count, size_t size) {
    if (atomic_exchange(&fail_allocate, false)) return NULL;
    void *result = calloc(count, size);
    if (race_initialization) {
        atomic_fetch_add(&allocation_arrivals, 1);
        while (atomic_load(&allocation_arrivals) < 6) sched_yield();
    }
    if (atomic_exchange(&delay_allocate, false)) {
        atomic_store(&allocating, true);
        pause_window();
    }
    return result;
}

// 验证互斥锁初始化失败不会发布不可用状态。
int cache_test_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attributes) {
    if (atomic_exchange(&fail_mutex, false)) return EAGAIN;
    atomic_fetch_add(&mutex_inits, 1);
    return pthread_mutex_init(mutex, attributes);
}

// 统计竞争发布失败后未发布状态的清理。
int cache_test_mutex_destroy(pthread_mutex_t *mutex) {
    atomic_fetch_add(&mutex_destroys, 1);
    return pthread_mutex_destroy(mutex);
}

// 记录缓存持有的路径，供测试暂停在条目部分清理的位置。
char *cache_test_strdup(const char *path) {
    char *result = strdup(path);
    if (tracked_path_name && !strcmp(path, tracked_path_name)) atomic_store(&tracked_path, result);
    return result;
}

// 在路径已经释放、条目尚未清零时复制进程，检查子进程不会遍历旧状态。
void cache_test_free(void *pointer) {
    bool tracked = pointer && pointer == atomic_load(&tracked_path);
    free(pointer);
    if (tracked && atomic_exchange(&delay_path_free, false)) {
        atomic_store(&freeing_path, true);
        pause_window();
    }
}

// 只统计生产文件访问，测试写文件仍调用真实 open。
int cache_test_open(const char *path, int flags, ...) {
    atomic_fetch_add(&open_calls, 1);
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, int);
        va_end(args);
        return open(path, flags, mode);
    }
    return open(path, flags);
}

// 只统计真实解析器调用，并为 fork 故障注入制造持锁窗口。
xpc_object_t cache_test_parse(const void *data, size_t size) {
    atomic_fetch_add(&parse_calls, 1);
    if (atomic_exchange(&delay_parse, false)) {
        atomic_store(&parsing, true);
        pause_window();
    }
    // 仅边界样例注入原始 XPC 字符串，正常配置仍调用真实解析器。
    if (raw_string) {
        xpc_object_t dictionary = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(dictionary, "value", raw_string);
        return dictionary;
    }
    return xpc_create_from_plist(data, size);
}

// 失败时退出，便于 sanitizer 和运行器准确报告。
static void require(bool condition, const char *message) {
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

// 生成真实二进制 plist，覆盖布尔、字符串、数值和分层字典。
static CFDataRef make_fixture(bool enabled) {
    int64_t negative = -2, zero = 0;
    double fraction = 0.5;
    CFNumberRef n = CFNumberCreate(NULL, kCFNumberSInt64Type, &negative);
    CFNumberRef z = CFNumberCreate(NULL, kCFNumberSInt64Type, &zero);
    CFNumberRef f = CFNumberCreate(NULL, kCFNumberDoubleType, &fraction);
    const void *nested_keys[] = {CFSTR("entry"), CFSTR("number"), CFSTR("zero")};
    const void *nested_values[] = {CFSTR("YES"), n, z};
    CFDictionaryRef nested = CFDictionaryCreate(NULL, nested_keys, nested_values, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const void *keys[] = {CFSTR("enabled"), CFSTR("needle"), CFSTR("fake"),
        CFSTR("str_yes"), CFSTR("str_true"), CFSTR("str_zero"), CFSTR("number"),
        CFSTR("zero"), CFSTR("fraction"), CFSTR("section")};
    const void *values[] = {enabled ? kCFBooleanTrue : kCFBooleanFalse, kCFBooleanTrue,
        CFSTR("YES"), CFSTR("YES"), CFSTR("true"), CFSTR("0"), n, z, f, nested};
    CFDictionaryRef dictionary = CFDictionaryCreate(NULL, keys, values, 10,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef data = CFPropertyListCreateData(NULL, dictionary, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    CFRelease(dictionary); CFRelease(nested); CFRelease(n); CFRelease(z); CFRelease(f);
    require(data != NULL, "fixture serialization");
    return data;
}

// 在同目录完整写入后原子替换，可指定旧文件的修改时间。
static void replace_bytes(const char *path, const void *data, size_t size, const struct stat *old) {
    char temporary[PATH_MAX];
    snprintf(temporary, sizeof(temporary), "%s.tmp.%u", path, atomic_fetch_add(&serial, 1));
    int fd = open(temporary, O_CREAT | O_EXCL | O_WRONLY, 0600);
    require(fd >= 0, "create temporary plist");
    size_t done = 0;
    while (done < size) {
        ssize_t n = write(fd, (const char *)data + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "write temporary plist");
        done += (size_t)n;
    }
    if (old) {
        struct timespec times[] = {old->st_atimespec, old->st_mtimespec};
        require(futimens(fd, times) == 0, "preserve mtime");
    }
    require(close(fd) == 0 && rename(temporary, path) == 0, "atomic plist replace");
}

// 使用预先生成的数据避免并发测试把耗时花在生成样本上。
static void replace_fixture(const char *path, bool enabled, const struct stat *old) {
    CFDataRef data = fixtures[enabled];
    replace_bytes(path, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data), old);
}

// 检查返回快照的类型和值，调用者负责释放自己的引用。
static bool snapshot_enabled(xpc_object_t dictionary) {
    require(dictionary && xpc_get_type(dictionary) == XPC_TYPE_DICTIONARY, "valid dictionary snapshot");
    xpc_object_t value = xpc_dictionary_get_value(dictionary, "enabled");
    require(value && xpc_get_type(value) == XPC_TYPE_BOOL, "snapshot contains bool");
    return xpc_bool_get_value(value);
}

// 验证命中不重复打开或解析，并返回用于后续生命周期测试的引用。
static xpc_object_t test_cache_hits_and_conversion(const char *path) {
    replace_fixture(path, true, NULL);
    unsigned opens = atomic_load(&open_calls), parses = atomic_load(&parse_calls);
    xpc_object_t retained = zqbb_read_dictionary(path);
    require(snapshot_enabled(retained), "initial snapshot true");
    for (int i = 0; i < 1000; i++) {
        xpc_object_t value = zqbb_read_dictionary(path);
        require(snapshot_enabled(value), "unchanged snapshot");
        xpc_release(value);
    }
    require(atomic_load(&open_calls) == opens + 1, "unchanged cache opens once");
    require(atomic_load(&parse_calls) == parses + 1, "unchanged cache parses once");
    require(zqbb_dictionary_enabled("enabled", path), "strict bool true");
    require(!zqbb_dictionary_enabled("str_yes", path), "strict bool ignores string");
    require(zqbb_dictionary_matches_path("/a/needle/tool", path), "enabled substring matches");
    require(!zqbb_dictionary_matches_path("/a/fake/tool", path), "substring ignores string");
    require(zqbb_dictionary_bool_value("str_yes", NULL, path), "Foundation YES string");
    require(zqbb_dictionary_bool_value("str_true", NULL, path), "Foundation true string");
    require(!zqbb_dictionary_bool_value("str_zero", NULL, path), "Foundation zero string");
    require(zqbb_dictionary_bool_value("number", NULL, path), "Foundation negative number");
    require(zqbb_dictionary_bool_value("fraction", NULL, path), "Foundation fractional number");
    require(!zqbb_dictionary_bool_value("zero", NULL, path), "Foundation zero number");
    require(zqbb_dictionary_bool_value("entry", "section", path), "nested Foundation string");
    require(!zqbb_dictionary_bool_value("missing", "section", path), "missing value false");
    require(!zqbb_dictionary_bool_value("entry", "absent", path), "missing section false");
    puts("PASS unchanged hit costs and query conversion");
    return retained;
}

// 与 Foundation 对照 Unicode 空白、换行、符号及数字前缀。
static void test_string_conversion(const char *path) {
    const char *values[] = {
        "\xC2\xA0YES", "\xE3\x80\x80true", "\xE2\x80\x83 1",
        "", " \t", "\xC2\xA0", "YES", "true", "false", "  \tYES", "\n1", "\r1", "\v1", "\f1",
        "\xC2\x85" "1", "\xE1\x9A\x80YES",
        "\xE2\x80\x80YES", "\xE2\x80\x87YES",
        "\xE2\x80\x8AYES", "\xE2\x80\x8BYES", "\xE2\x80\xA8" "1",
        "\xE2\x80\xA9" "1", "\xE2\x80\xAFYES", "\xE2\x81\x9FYES",
        "\xE2\x81\xA0YES", "\xEF\xBB\xBFYES",
        "\xE1\xA0\x8EYES", "\xC2\xA1YES", "+1", "-0001", "+0000", "00YES",
        "+YES", "-T", "0.1", "-0.1", "0x1", "1e-100", " + 1", "-\t1", "+", "-", "000", "001tail",
        "999999999999999999999999999999999999999999", "\xEF\xBC\x91"
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); i++) {
        CFStringRef value = CFStringCreateWithCString(NULL, values[i], kCFStringEncodingUTF8);
        require(value != NULL, "UTF-8 Foundation fixture");
        const void *keys[] = {CFSTR("value")}, *objects[] = {value};
        CFDictionaryRef dictionary = CFDictionaryCreate(NULL, keys, objects, 1,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDataRef bytes = CFPropertyListCreateData(NULL, dictionary, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
        require(bytes != NULL, "serialize string fixture");
        replace_bytes(path, CFDataGetBytePtr(bytes), (size_t)CFDataGetLength(bytes), NULL);
        bool expected = cache_test_foundation_bool(values[i]);
        errno = EDOM;
        bool actual = zqbb_dictionary_bool_value("value", NULL, path);
        if (actual != expected) fprintf(stderr, "String conversion mismatch at case %zu\n", i);
        require(actual == expected, "string bool matches Foundation");
        require(errno == EDOM, "string conversion preserves errno");
        CFRelease(bytes); CFRelease(dictionary); CFRelease(value);
    }
    const char *truncated[] = {"\xC2", "\xE1", "\xE1\x9A", "\xE2", "\xE2\x80", "\xE3\x80"};
    for (size_t i = 0; i < sizeof(truncated) / sizeof(*truncated); i++) {
        raw_string = truncated[i];
        replace_bytes(path, "test", 4, NULL);
        require(!zqbb_dictionary_bool_value("value", NULL, path), "truncated UTF-8 remains false without overread");
    }
    raw_string = NULL;
    puts("PASS Foundation Unicode whitespace, numeric prefixes, errno and truncated UTF-8");
}

// 原子替换即使大小与 mtime 不变，也必须载入新 inode 的内容。
static void test_replacement_and_recovery(const char *path, xpc_object_t old_snapshot) {
    struct stat old, changed;
    require(stat(path, &old) == 0, "stat original");
    replace_fixture(path, false, &old);
    require(stat(path, &changed) == 0 && old.st_ino != changed.st_ino
        && old.st_size == changed.st_size
        && old.st_mtimespec.tv_sec == changed.st_mtimespec.tv_sec
        && old.st_mtimespec.tv_nsec == changed.st_mtimespec.tv_nsec, "same mtime/size replacement fixture");
    xpc_object_t value = zqbb_read_dictionary(path);
    require(!snapshot_enabled(value), "atomic replacement refreshes");
    xpc_release(value);
    require(snapshot_enabled(old_snapshot), "old retained snapshot survives replacement");
    replace_bytes(path, "bad plist", 9, NULL);
    value = zqbb_read_dictionary(path);
    require(!snapshot_enabled(value), "malformed file preserves last valid snapshot");
    xpc_release(value);
    replace_bytes(path, "", 0, NULL);
    value = zqbb_read_dictionary(path);
    require(!snapshot_enabled(value), "empty file preserves last valid snapshot");
    xpc_release(value);
    replace_fixture(path, true, NULL);
    value = zqbb_read_dictionary(path);
    require(snapshot_enabled(value), "recovered valid configuration loads");
    xpc_release(value);
    require(unlink(path) == 0, "delete configuration");
    require(zqbb_read_dictionary(path) == NULL, "deleted configuration clears cache");
    require(snapshot_enabled(old_snapshot), "retained snapshot survives deletion");
    replace_fixture(path, false, NULL);
    value = zqbb_read_dictionary(path);
    require(!snapshot_enabled(value), "recreated configuration immediately loads");
    xpc_release(value);
    puts("PASS inode refresh, malformed fallback, deletion and recreation");
}

// 父目录被普通文件替换时清除缓存，恢复目录后立即读到新配置。
static void test_enotdir(void) {
    char parent[PATH_MAX], path[PATH_MAX];
    snprintf(parent, sizeof(parent), "%s/enotdir", test_root);
    snprintf(path, sizeof(path), "%s/config.plist", parent);
    require(mkdir(parent, 0700) == 0, "create configuration parent");
    replace_fixture(path, true, NULL);
    xpc_object_t value = zqbb_read_dictionary(path);
    require(snapshot_enabled(value), "initial nested configuration");
    xpc_release(value);
    require(unlink(path) == 0 && rmdir(parent) == 0, "remove configuration parent");
    replace_bytes(parent, "file", 4, NULL);
    require(zqbb_read_dictionary(path) == NULL, "ENOTDIR clears cached snapshot");
    require(unlink(parent) == 0 && mkdir(parent, 0700) == 0, "restore configuration parent");
    replace_fixture(path, false, NULL);
    value = zqbb_read_dictionary(path);
    require(!snapshot_enabled(value), "configuration reloads after ENOTDIR");
    xpc_release(value);
    puts("PASS ENOTDIR clears cache and directory recovery reloads");
}

// 填满 64 槽后保留热点，确认最近最少使用项被逐出。
static void test_lru(xpc_object_t old_snapshot) {
    char paths[65][PATH_MAX];
    for (int i = 0; i < 65; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/lru-%02d.plist", test_root, i);
        replace_fixture(paths[i], true, NULL);
        if (i < 64) {
            xpc_object_t value = zqbb_read_dictionary(paths[i]);
            require(snapshot_enabled(value), "LRU populate");
            xpc_release(value);
        }
    }
    xpc_object_t value = zqbb_read_dictionary(paths[0]); xpc_release(value);
    value = zqbb_read_dictionary(paths[64]); xpc_release(value);
    unsigned parses = atomic_load(&parse_calls);
    value = zqbb_read_dictionary(paths[0]); xpc_release(value);
    require(atomic_load(&parse_calls) == parses, "LRU retains recent hit");
    value = zqbb_read_dictionary(paths[1]); xpc_release(value);
    require(atomic_load(&parse_calls) == parses + 1, "LRU evicts least recent path");
    require(snapshot_enabled(old_snapshot), "old retained snapshot survives LRU eviction");
    puts("PASS bounded 64-slot LRU and retained lifetime");
}

// 读线程在快照更新期间继续持有并检查对象，供 ASAN/TSAN 捕获竞态。
static void *read_thread(void *argument) {
    const char *path = argument;
    for (int i = 0; i < 1500; i++) {
        xpc_object_t value = zqbb_read_dictionary(path);
        if (!value) continue;
        sched_yield();
        xpc_object_t enabled = xpc_dictionary_get_value(value, "enabled");
        if (xpc_get_type(value) != XPC_TYPE_DICTIONARY || !enabled || xpc_get_type(enabled) != XPC_TYPE_BOOL)
            atomic_store(&reader_failed, true);
        xpc_release(value);
    }
    return NULL;
}

// 并发替换、损坏和删除不能使读者拿到悬空快照。
static void test_concurrent_updates(const char *path) {
    pthread_t readers[6];
    replace_fixture(path, true, NULL);
    for (int i = 0; i < 6; i++) require(!pthread_create(&readers[i], NULL, read_thread, (void *)path), "start reader");
    for (int i = 0; i < 300; i++) {
        if (i % 5 == 0) unlink(path);
        else if (i % 5 == 1) replace_bytes(path, "bad", 3, NULL);
        else replace_fixture(path, i % 2, NULL);
    }
    for (int i = 0; i < 6; i++) require(!pthread_join(readers[i], NULL), "join reader");
    require(!atomic_load(&reader_failed), "concurrent snapshots retain valid types");
    replace_fixture(path, true, NULL);
    xpc_object_t value = zqbb_read_dictionary(path);
    require(snapshot_enabled(value), "configuration recovers after churn"); xpc_release(value);
    puts("PASS six concurrent readers with replace/delete/corrupt writer");
}

// 仅用于制造另一线程正在解析配置时的 fork。
static void *load_once(void *argument) {
    xpc_object_t value = zqbb_read_dictionary(argument);
    bool valid = value && xpc_dictionary_get_bool(value, "enabled");
    if (value) xpc_release(value);
    return (void *)(uintptr_t)valid;
}

// 子进程应建立自己的缓存，并保留调用者在 fork 前持有的快照。
static bool check_child_cache(const char *path, xpc_object_t retained) {
    unsigned parses = atomic_load(&parse_calls);
    errno = EDOM;
    xpc_object_t first = zqbb_read_dictionary(path);
    bool valid = errno == EDOM && first && xpc_dictionary_get_bool(first, "enabled");
    xpc_object_t second = zqbb_read_dictionary(path);
    valid = valid && first == second && atomic_load(&parse_calls) == parses + 1;
    if (retained) valid = valid && xpc_dictionary_get_bool(retained, "enabled");
    if (first) xpc_release(first);
    if (second) xpc_release(second);
    return valid;
}

// 覆盖真实 fork/vfork、首次发布窗口和多代子进程重新建缓存。
static void test_fork(const char *path, bool use_vfork, bool initializing) {
    replace_fixture(path, true, NULL);
    _Atomic bool *entered = initializing ? &allocating : &parsing;
    atomic_store(entered, false);
    atomic_store(initializing ? &delay_allocate : &delay_parse, true);
    pthread_t thread;
    require(!pthread_create(&thread, NULL, load_once, (void *)path), "start delayed parser");
    for (int i = 0; i < 1000 && !atomic_load(entered); i++) usleep(1000);
    require(atomic_load(entered), "delayed cache operation entered");
    pid_t child = use_vfork ? vfork() : fork();
    require(child >= 0, "fork during configuration load");
    if (!child) {
        alarm(3);
        bool valid = check_child_cache(path, NULL);
        pid_t nested = fork();
        if (nested == 0) {
            alarm(3);
            _exit(check_child_cache(path, NULL) ? 0 : 3);
        }
        int status;
        valid = valid && nested > 0 && waitpid(nested, &status, 0) == nested &&
                WIFEXITED(status) && WEXITSTATUS(status) == 0;
        _exit(valid ? 0 : 2);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "wait fork child");
    require(!pthread_join(thread, NULL), "join delayed parser");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "fork child cache is usable without deadlock");
    printf("PASS %s during %s and nested fork cache reset\n", use_vfork ? "vfork" : "fork",
           initializing ? "unpublished state allocation" : "configuration parsing");
}

// 覆盖继承条目已经释放路径但尚未清空的窗口。
static void test_partial_vfork(const char *path) {
    char removed[PATH_MAX];
    snprintf(removed, sizeof(removed), "%s/removed.plist", test_root);
    replace_fixture(path, true, NULL);
    replace_fixture(removed, true, NULL);
    tracked_path_name = removed;
    xpc_object_t retained = zqbb_read_dictionary(removed);
    require(snapshot_enabled(retained) && atomic_load(&tracked_path), "track cached path allocation");
    require(unlink(removed) == 0, "remove tracked configuration");
    atomic_store(&delay_path_free, true);
    pthread_t thread;
    require(!pthread_create(&thread, NULL, load_once, removed), "start cache eviction");
    for (int i = 0; i < 1000 && !atomic_load(&freeing_path); i++) usleep(1000);
    require(atomic_load(&freeing_path), "partial cache cleanup entered");
    pid_t child = vfork();
    require(child >= 0, "vfork during partial cleanup");
    if (child == 0) {
        alarm(3);
        _exit(check_child_cache(path, retained) ? 0 : 2);
    }
    int status;
    require(waitpid(child, &status, 0) == child, "wait partial cleanup child");
    require(!pthread_join(thread, NULL), "join cache eviction");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child discards partially cleared inherited entries");
    require(snapshot_enabled(retained), "parent retained snapshot survives partial cleanup");
    xpc_release(retained);
    tracked_path_name = NULL;
    atomic_store(&tracked_path, NULL);
    puts("PASS vfork during freed-path cleanup and inherited retained snapshot");
}

static const char *callback_path;
static unsigned callback_phase, callback_calls;

// 在独立 prepare/parent/child 回调中模拟启动 hook 读取配置。
static void read_from_callback(unsigned phase) {
    if (phase != callback_phase) return;
    alarm(3);
    xpc_object_t value = zqbb_read_dictionary(callback_path);
    if (!value || !xpc_dictionary_get_bool(value, "enabled")) _exit(10);
    xpc_release(value);
    callback_calls++;
}

// 触发 prepare 阶段读取。
static void test_prepare_callback(void) { read_from_callback(1); }

// 触发 parent 阶段读取。
static void test_parent_callback(void) { read_from_callback(2); }

// 触发 child 阶段读取。
static void test_child_callback(void) { read_from_callback(3); }

// 同时覆盖早于和晚于首次缓存读取注册的三种 atfork 回调。
static void test_atfork_callbacks(const char *path) {
    replace_fixture(path, true, NULL);
    xpc_object_t value = zqbb_read_dictionary(path);
    require(snapshot_enabled(value), "prime cache after early callback registration");
    xpc_release(value);
    require(!pthread_atfork(test_prepare_callback, test_parent_callback, test_child_callback), "register late callbacks");
    callback_path = path;
    for (unsigned phase = 1; phase <= 3; phase++) {
        callback_phase = phase;
        callback_calls = 0;
        alarm(3);
        pid_t child = fork();
        require(child >= 0, "fork with reading callbacks");
        if (child == 0) _exit(callback_calls == (phase == 2 ? 0 : 2) ? 0 : 2);
        int status;
        require(waitpid(child, &status, 0) == child, "wait callback child");
        alarm(0);
        require(callback_calls == (phase == 3 ? 0 : 2), "parent callback count");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "callbacks can reenter configuration reads");
    }
    callback_phase = 0;
    puts("PASS early/late prepare, parent and child callbacks read configuration");
}

// 六个线程同时分配首次状态，只保留一个发布者并清理其余状态。
static void test_initialization_race(const char *path) {
    replace_fixture(path, true, NULL);
    race_initialization = true;
    pthread_t threads[6];
    alarm(5);
    for (size_t i = 0; i < 6; i++) require(!pthread_create(&threads[i], NULL, load_once, (void *)path), "start initializing reader");
    for (size_t i = 0; i < 6; i++) {
        void *valid;
        require(!pthread_join(threads[i], &valid) && valid == (void *)1, "join initializing reader");
    }
    alarm(0);
    race_initialization = false;
    require(atomic_load(&mutex_inits) == 6 && atomic_load(&mutex_destroys) == 5, "unpublished losing states are destroyed");
    require(atomic_load(&parse_calls) == 1, "initialization contenders share one cache");
    puts("PASS six simultaneous initializers publish once and clean up losers");
}

// 分配或 mutex 初始化失败时读取不丢失，随后可正常建立缓存。
static void test_initialization_failure(const char *path) {
    replace_fixture(path, true, NULL);
    for (int i = 0; i < 2; i++) {
        _Atomic bool *failure = i == 0 ? &fail_allocate : &fail_mutex;
        atomic_store(failure, true);
        errno = EDOM;
        xpc_object_t value = zqbb_read_dictionary(path);
        require(errno == EDOM && snapshot_enabled(value), "uncached failure fallback preserves result and errno");
        require(!atomic_load(failure), "initialization failure injected");
        xpc_release(value);
    }
    require(check_child_cache(path, NULL), "cache initializes after transient failures");
    puts("PASS allocation/mutex failure fallback and subsequent recovery");
}

// 主机回归入口，所有数据由运行器放入独立临时目录。
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    require(argc == 3, "temporary directory and case arguments");
    snprintf(test_root, sizeof(test_root), "%s", argv[1]);
    const char *mode = argv[2];
    require(!pthread_atfork(test_prepare_callback, test_parent_callback, test_child_callback), "register early callbacks");
    fixtures[0] = make_fixture(false); fixtures[1] = make_fixture(true);
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/main.plist", test_root);
    if (!strcmp(mode, "unicode")) { test_string_conversion(path); return 0; }
    if (!strcmp(mode, "fork") || !strcmp(mode, "vfork")) {
        test_fork(path, !strcmp(mode, "vfork"), false); return 0;
    }
    if (!strcmp(mode, "atfork")) { test_atfork_callbacks(path); return 0; }
    if (!strcmp(mode, "partial-vfork")) { test_partial_vfork(path); return 0; }
    if (!strcmp(mode, "initialization-fork") || !strcmp(mode, "initialization-vfork")) {
        test_fork(path, !strcmp(mode, "initialization-vfork"), true); return 0;
    }
    if (!strcmp(mode, "initialization-race")) { test_initialization_race(path); return 0; }
    if (!strcmp(mode, "initialization-failure")) { test_initialization_failure(path); return 0; }
    require(!strcmp(mode, "all"), "known test case");
    xpc_object_t retained = test_cache_hits_and_conversion(path);
    test_replacement_and_recovery(path, retained);
    test_enotdir();
    test_lru(retained);
    test_concurrent_updates(path);
    snprintf(path, sizeof(path), "%s/strings.plist", test_root);
    test_string_conversion(path);
    snprintf(path, sizeof(path), "%s/fork.plist", test_root);
    test_fork(path, false, false);
    snprintf(path, sizeof(path), "%s/vfork.plist", test_root);
    test_fork(path, true, false);
    test_partial_vfork(path);
    test_atfork_callbacks(path);
    xpc_release(retained); CFRelease(fixtures[0]); CFRelease(fixtures[1]);
    puts("PASS production configuration cache regression");
    return 0;
}
