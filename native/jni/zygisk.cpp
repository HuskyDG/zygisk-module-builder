/* Copyright 2022-2023 John "topjohnwu" Wu
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <tuple>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "zygisk.hpp"
#include "utils.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOG_TAG "MyModule"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// prepare functions for hooking open(const char* path, int flags, ...)
DCL_HOOK_FUNC(static int, open, const char* path, int flags, ...) {
    LOGD("calling open(%s, %d, ...)", path, flags);
    va_list args;
    va_start (args, flags);
    const char *new_path =
        (strcmp(path, "/system/etc/hosts") == 0 && access("/data/hosts", F_OK) == 0)?
            "/data/hosts" : path;
    int ret = old_open(new_path, flags, args);
    va_end (args);
    LOGI("open(%s, %d, ...) = %d", path, flags, ret);
    return ret;
}

// Define a macro for calling memfd_create
#define memfd_create(name, flags) syscall(__NR_memfd_create, (name), (flags))

enum CompanionRequest {
    GET_CHROME_UID
};

class MyModule : public zygisk::ModuleBase {
public:
#define PLT_HOOK_REGISTER_SYM(DEV, INODE, SYM, NAME) \
    register_hook(DEV, INODE, SYM, \
    reinterpret_cast<void *>(new_##NAME), reinterpret_cast<void **>(&old_##NAME))

#define PLT_HOOK_REGISTER(DEV, INODE, NAME) \
    PLT_HOOK_REGISTER_SYM(DEV, INODE, #NAME, NAME)

#define PLT_HOOK_COMMIT (api->pltHookCommit())

#define to_app_id(uid) (uid % 100000)

    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // An example Zygisk module that installs hook open() call from libc for Google Chrome 
        // and redirects /system/etc/hosts to our custom hosts

        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        char *cached_proc_name = strdup(process);
        {
            char *s = strchr(cached_proc_name, ':');
            if (s) s[0] = '\0';
        }
        preSpecialize(process, args->uid);
        env->ReleaseStringUTFChars(args->nice_name, process);

        // Demonstrate connecting to to companion process
        // We ask the companion for a uid number of Chrome app
        int fd = companion_request(GET_CHROME_UID);
        if (fd < 0) return;

        int kuid = read_int(fd);
        close(fd);

        bool IS_GOOGLE_CHROME = kuid > 0 && to_app_id(args->uid) == kuid;

        if (!IS_GOOGLE_CHROME && to_app_id(args->uid) >= 90000 && to_app_id(args->uid) <= 99999 && strcmp(cached_proc_name, "com.android.chrome") == 0)
            IS_GOOGLE_CHROME = true;
        free(cached_proc_name);

        if (!IS_GOOGLE_CHROME)
            return; // skip process if it is not Google Chrome

        // Find the dev and inode of libc.so
        dev_t __dev = 0;
        ino_t __inode = 0;
        for (auto &map : scan_maps()) {
            if (map.path.ends_with("/libc.so")) {
                __dev = map.dev;
                __inode = map.inode;
            }
        }

        // Register hooks
        PLT_HOOK_REGISTER(__dev, __inode, open);

        // Commit all registered hooks
        if (PLT_HOOK_COMMIT)
            LOGD("hook success!");
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
    	if (plt_backup.empty()) {
            // Since we do not hook any functions, we should let Zygisk dlclose ourselves
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            LOGD("unload success!");
        }
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        preSpecialize("system_server", 1000);
    }

    void postServerSpecialize(const ServerSpecializeArgs *args) override {
        // Since we do not hook any functions, we should let Zygisk dlclose ourselves
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;

    std::vector<std::tuple<dev_t, ino_t, const char *, void **>> plt_backup;

    [[maybe_unused]] void register_hook(
        dev_t dev, ino_t inode, const char *symbol, void *new_func, void **old_func) {
        api->pltHookRegister(dev, inode, symbol, new_func, old_func);
        LOGD("register hook: device=[%lu] inode=[%lu] symbol=[%s] new=[%p] backup=[%p]", dev, inode, symbol, new_func, old_func);
        plt_backup.emplace_back(dev, inode, symbol, old_func);
    }

    [[maybe_unused]] bool restore_plt_hook() {
        for (const auto &[dev, inode, sym, old_func] : plt_backup) {
            api->pltHookRegister(dev, inode, sym, *old_func, nullptr);
            LOGD("register unhook: device=[%lu] inode=[%lu] symbol=[%s] backup=[%p]", dev, inode, sym, old_func);
        }
        bool ret = PLT_HOOK_COMMIT;
        if (ret) {
            LOGD("unhook success");
            plt_backup.clear();
        }
        return ret;
    }

    [[maybe_unused]] int companion_request (int req) {
        int fd = api->connectCompanion();
        if (fd >= 0) write(fd, &req, sizeof(req));
        return fd;
    }

    void preSpecialize(const char *process, int uid) {
        LOGD("process=[%s], uid=[%d]\n", process, uid);
    }

};

static void companion_handler(int i) {
    struct stat st{};

    switch (read_int(i)) {
        case GET_CHROME_UID: {
            stat("/data/data/com.android.chrome", &st);
            LOGD("com.android.chrome UID=[%d]\n", st.st_uid);
            write_int(i, st.st_uid);
            break;
        }
        default: {
            break;
        }
    }
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
