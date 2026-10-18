/*
 * soter-svc: the A-side software Soter TA daemon.
 *
 * The vendor AIDL HAL `vendor.qti.hardware.soter.ISoter/default` is a thin proxy
 * over a Qualcomm TA in the secure world. On this device the applet cannot run,
 * so every Soter call fails with -20 and applications that use Soter as a local
 * integrity probe read that as "this device is up to something". While the stock
 * HAL is stopped, this daemon owns the same service name and answers the 14 AIDL
 * transactions from the software TA in libsoter_ta.a.
 *
 * It owns the parcel, because only the process holding the AParcel can read the
 * request and write the reply; the ledger, the blobs and the answers come from
 * soter-ta over the C ABI in soter-ta/src/ffi.rs (mirrored below).
 *
 * Usage:
 *   stop vendor.soter
 *   /data/misc/keystore/omk/data/soterta/soterta-svc --mode=answer &
 *   ...
 *   kill <pid>            # releases the name
 *   start vendor.soter    # the stock HAL takes the slot back
 *
 * Modes:
 *   --mode=dead    answer exactly what the stock HAL answers while its TA is
 *                  dead (default): no key, no device id, no sign session
 *   --mode=log     log every request, answer only the ATTK trio (2/6/14) with
 *                  -20, and leave the rest unanswered
 *   --mode=answer  answer from the software TA
 *
 * Biometric gate (--mode=answer):
 *   --bio-gate=on   (default) sign only inside a fresh fingerprint match, the
 *                   way the stock TA does; the evidence is the fingerprint
 *                   provider's accepted-capture counter, read before and after
 *                   the sign session
 *   --bio-gate=off  sign without one (the pre-gate behaviour, for debugging)
 */

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "soterta-svc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* The C ABI of soter-ta (soter-ta/src/ffi.rs). */
#define SOTERTA_KIND_CODE 0
#define SOTERTA_KIND_BUFFER 1
#define SOTERTA_KIND_INIT 2
#define SOTERTA_HANDLED 0
#define SOTERTA_UNHANDLED 1
#define SOTERTA_ERROR (-1)

struct soterta_reply {
    int32_t kind;
    int32_t code;
    int32_t field;
    int64_t session;
    uint8_t *buffer;
    size_t buffer_len;
};

extern int32_t soterta_init(const char *state_path);
extern int32_t soterta_handle(uint32_t tx, uint32_t uid, const char *kname,
                              const char *challenge, int64_t session,
                              struct soterta_reply *reply);
extern int32_t soterta_dead_reply(uint32_t tx, struct soterta_reply *reply);
extern int32_t soterta_save(void);
extern void soterta_free(struct soterta_reply *reply);
extern int32_t soterta_last_error(char *buffer, int32_t capacity);

/* Platform hooks the Rust half calls back into (soter-ta/src/platform.rs). */
typedef int64_t (*platform_probe_fn)(void);
extern void soterta_set_platform(platform_probe_fn boot_ms, platform_probe_fn bio_mark);

/* The interface this daemon impersonates, from the vendor AIDL stubs. */
#define SOTER_DESCRIPTOR "vendor.qti.hardware.soter.ISoter"
#define SOTER_SERVICE_NAME "vendor.qti.hardware.soter.ISoter/default"
#define SOTER_INTERFACE_VERSION 1
#define SOTER_INTERFACE_HASH "81832c92aa802927e98f3bf426e95b03e5d7f5e6"

#define TX_EXPORT_ASK 1u
#define TX_EXPORT_ATTK 2u
#define TX_EXPORT_AUTH 3u
#define TX_FINISH_SIGN 4u
#define TX_GENERATE_ASK 5u
#define TX_GENERATE_ATTK 6u
#define TX_GENERATE_AUTH 7u
#define TX_GET_DEVICE_ID 8u
#define TX_HAS_ASK 9u
#define TX_HAS_AUTH 10u
#define TX_INIT_SIGN 11u
#define TX_REMOVE_ALL_UID_KEY 12u
#define TX_REMOVE_AUTH 13u
#define TX_VERIFY_ATTK 14u

#define CODE_GET_INTERFACE_VERSION 0x00ffffffu
#define CODE_GET_INTERFACE_HASH 0x00fffffeu

#define DEFAULT_STATE_PATH "/data/misc/keystore/omk/data/soterta/state.json"

/* No Soter argument is anywhere near this long; refusing to allocate more keeps
 * a bogus length in a request from exhausting the daemon. */
#define MAX_FIELD_LEN 8192
#define PREVIEW_LEN 64

enum mode { MODE_DEAD, MODE_LOG, MODE_ANSWER };

static enum mode g_mode = MODE_DEAD;
static bool g_bio_gate = true;

static const char *mode_name(enum mode mode) {
    switch (mode) {
        case MODE_LOG:
            return "log";
        case MODE_ANSWER:
            return "answer";
        default:
            return "dead";
    }
}

/* Platform symbols the NDK does not declare in its headers. */
typedef binder_status_t (*add_service_fn)(AIBinder *, const char *);
typedef void (*start_thread_pool_fn)(void);
/* The VINTF-stable HAL binder can be called from both system and vendor. */
typedef void (*mark_vintf_stability_fn)(AIBinder *);

static add_service_fn g_add_service;
static start_thread_pool_fn g_start_thread_pool;
static mark_vintf_stability_fn g_mark_vintf_stability;

/* ----------------------------------------------------------------- platform */

/* CLOCK_BOOTTIME: monotone inside one boot, which is the lifetime a sign
 * session and its biometric freshness window live in. */
static int64_t platform_boot_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)(now.tv_nsec / 1000000);
}

static int hex_digit(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

/* Changes on every boot, so a mark read in a previous boot can never pass for
 * evidence in this one. */
static uint32_t boot_tag(void) {
    FILE *file = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (file == NULL) {
        return 0;
    }
    char line[64] = {0};
    char *read = fgets(line, sizeof(line), file);
    fclose(file);
    if (read == NULL) {
        return 0;
    }
    uint32_t tag = 0;
    int digits = 0;
    for (const char *cursor = line; *cursor != '\0' && digits < 8; cursor++) {
        int value = hex_digit(*cursor);
        if (value < 0) {
            continue;
        }
        tag = (tag << 4) | (uint32_t)value;
        digits++;
    }
    return tag;
}

/* Add every `"<key>": <number>` in the dump; -1 when the key is absent. */
static int64_t sum_dump_counter(const char *dump, const char *key) {
    int64_t total = 0;
    int found = 0;
    size_t key_len = strlen(key);
    const char *cursor = dump;
    while ((cursor = strstr(cursor, key)) != NULL) {
        cursor += key_len;
        const char *value = cursor;
        while (*value == ' ') {
            value++;
        }
        if (*value != ':') {
            continue;
        }
        value++;
        while (*value == ' ') {
            value++;
        }
        if (*value < '0' || *value > '9') {
            continue;
        }
        total += strtoll(value, NULL, 10);
        found++;
    }
    return found > 0 ? total : -1;
}

/* How many fingerprint captures the framework has accepted since boot.
 *
 * A stock TA signs only inside a fresh biometric match, and it reads that match
 * where it lives: in the secure world, from the fingerprint TA. The software TA
 * cannot; the closest platform-visible trace is this counter, which moves for
 * any accepted capture no matter which UI drove it. */
static int64_t fingerprint_accept_count(void) {
    FILE *stream = popen("/system/bin/dumpsys fingerprint 2>/dev/null", "r");
    if (stream == NULL) {
        return -1;
    }
    char dump[16384];
    size_t used = fread(dump, 1, sizeof(dump) - 1, stream);
    int status = pclose(stream);
    dump[used] = '\0';
    if (status != 0) {
        return -1;
    }
    int64_t plain = sum_dump_counter(dump, "\"accept\"");
    int64_t crypto = sum_dump_counter(dump, "\"acceptCrypto\"");
    if (plain < 0 && crypto < 0) {
        return -1;
    }
    if (plain < 0) {
        plain = 0;
    }
    if (crypto < 0) {
        crypto = 0;
    }
    return plain + crypto;
}

/* The mark the Rust half compares before and after a sign session. */
static int64_t platform_bio_mark(void) {
    int64_t accepted = fingerprint_accept_count();
    if (accepted < 0) {
        LOGE("bio gate: cannot read the fingerprint accept counter");
        return -1;
    }
    /* The tag has to stay inside 31 bits: the Rust half reads a negative hook
     * answer as "cannot tell", and a tag whose top bit is set would make the
     * packed mark negative, so the gate would fail open for that whole boot
     * (seen on a boot whose id started with bb...). */
    uint32_t tag = boot_tag() & 0x7FFFFFFFu;
    LOGI("bio marker: accepted=%lld boot=%08x", (long long)accepted, (unsigned)tag);
    return ((int64_t)tag << 32) | (accepted & 0xFFFFFFFFLL);
}

struct request {
    uint32_t uid;
    char *kname;
    char *challenge;
    int64_t session;
};

/* `AParcel_readString` hands the allocator the caller's slot (`data`) and the
 * buffer the framework fills (`buffer`). For a null string the length is -1 and
 * there is no buffer at all, so only the slot may be written: touching `buffer`
 * there is a null dereference (seen as a SIGSEGV in AParcel_readString). */
static bool field_alloc(void *data, int32_t length, char **buffer) {
    char **slot = (char **)data;
    if (slot != NULL) {
        *slot = NULL;
    }
    if (length < 0) {
        return true;
    }
    if (length > MAX_FIELD_LEN || slot == NULL || buffer == NULL) {
        return false;
    }
    char *value = malloc((size_t)length + 1);
    if (value == NULL) {
        return false;
    }
    value[length] = 0;
    *slot = value;
    *buffer = value;
    return true;
}

static bool is_soter_token(const char *token) {
    return token != NULL && (strcmp(token, SOTER_DESCRIPTOR) == 0 ||
                             strcmp(token, SOTER_SERVICE_NAME) == 0);
}

/* An AIDL client writes `[strict-mode policy][interface token][arguments]`. The
 * binder framework may already have consumed the first two blocks before the
 * callback runs and the C API does not say which, so look for a token and rewind
 * when there is none. */
static const char *read_layout(const AParcel *in) {
    int32_t start = AParcel_getDataPosition(in);
    int32_t policy = 0;
    char *token = NULL;
    bool found = AParcel_readInt32(in, &policy) == STATUS_OK &&
                 AParcel_readString(in, &token, field_alloc) == STATUS_OK &&
                 is_soter_token(token);
    free(token);
    if (found) {
        return "token";
    }
    AParcel_setDataPosition(in, start);
    return "arguments";
}

static void request_clear(struct request *request) {
    free(request->kname);
    free(request->challenge);
    request->kname = NULL;
    request->challenge = NULL;
}

static bool read_uid(const AParcel *in, struct request *request) {
    int32_t uid = 0;
    if (AParcel_readInt32(in, &uid) != STATUS_OK || uid < 0) {
        return false;
    }
    request->uid = (uint32_t)uid;
    return true;
}

static bool read_string_field(const AParcel *in, char **field) {
    return AParcel_readString(in, field, field_alloc) == STATUS_OK;
}

/* Reads the arguments of the transactions this daemon answers; the ATTK trio and
 * unknown codes carry arguments it does not look at. */
static bool read_request(uint32_t tx, const AParcel *in, struct request *request) {
    memset(request, 0, sizeof(*request));
    switch (tx) {
        case TX_EXPORT_ASK:
        case TX_GENERATE_ASK:
        case TX_HAS_ASK:
        case TX_REMOVE_ALL_UID_KEY:
            return read_uid(in, request);
        case TX_EXPORT_AUTH:
        case TX_GENERATE_AUTH:
        case TX_HAS_AUTH:
        case TX_REMOVE_AUTH:
            return read_uid(in, request) && read_string_field(in, &request->kname);
        case TX_INIT_SIGN:
            return read_uid(in, request) && read_string_field(in, &request->kname) &&
                   read_string_field(in, &request->challenge);
        case TX_FINISH_SIGN: {
            int64_t session = 0;
            if (AParcel_readInt64(in, &session) != STATUS_OK) {
                return false;
            }
            request->session = session;
            return true;
        }
        default:
            return true;
    }
}

static void preview(char *out, size_t capacity, const char *value) {
    if (value == NULL) {
        snprintf(out, capacity, "(absent)");
        return;
    }
    size_t length = strlen(value);
    snprintf(out, capacity, "\"%.*s\" (%zu bytes)", length > PREVIEW_LEN ? PREVIEW_LEN : (int)length, value, length);
}

static void log_request(uint32_t tx, const char *layout, const struct request *request) {
    char kname[PREVIEW_LEN + 32];
    char challenge[PREVIEW_LEN + 32];
    preview(kname, sizeof(kname), request->kname);
    preview(challenge, sizeof(challenge), request->challenge);
    LOGI("tx=%u layout=%s uid=%u kname=%s challenge=%s session=%lld", tx, layout,
         request->uid, kname, challenge, (long long)request->session);
}

static int32_t align4(int32_t value) {
    return (value + 3) & ~3;
}

/* The AIDL reply: the status header (0 = no exception) is written by the server
 * implementation, then the return value and the out parameters follow. */
static binder_status_t write_reply(AParcel *out, const struct soterta_reply *reply) {
    binder_status_t status = AParcel_writeInt32(out, 0);
    if (status != STATUS_OK) {
        return status;
    }
    switch (reply->kind) {
        case SOTERTA_KIND_BUFFER: {
            int32_t size = 4 + 4 + align4((int32_t)reply->buffer_len) + 4;
            status = AParcel_writeInt32(out, reply->code);
            if (status == STATUS_OK) {
                status = AParcel_writeInt32(out, 1); /* the out parameter is present */
            }
            if (status == STATUS_OK) {
                status = AParcel_writeInt32(out, size);
            }
            if (status == STATUS_OK) {
                status = AParcel_writeByteArray(out, (const int8_t *)reply->buffer,
                                                (int32_t)reply->buffer_len);
            }
            if (status == STATUS_OK) {
                status = AParcel_writeInt32(out, reply->field);
            }
            return status;
        }
        case SOTERTA_KIND_INIT:
            status = AParcel_writeInt32(out, 1);
            if (status == STATUS_OK) {
                status = AParcel_writeInt32(out, 16); /* SoterInitReturn size */
            }
            if (status == STATUS_OK) {
                status = AParcel_writeInt32(out, reply->code);
            }
            if (status == STATUS_OK) {
                status = AParcel_writeInt64(out, reply->session);
            }
            return status;
        default:
            return AParcel_writeInt32(out, reply->code);
    }
}

/* The AIDL metadata answers, captured from the stock HAL: `00000000 00000001`
 * for the version and `00000000 00000028 00310038 ...` for the hash. */
static binder_status_t write_metadata_reply(AParcel *out, uint32_t tx) {
    binder_status_t status = AParcel_writeInt32(out, 0);
    if (status != STATUS_OK) {
        return status;
    }
    if (tx == CODE_GET_INTERFACE_VERSION) {
        return AParcel_writeInt32(out, SOTER_INTERFACE_VERSION);
    }
    return AParcel_writeString(out, SOTER_INTERFACE_HASH,
                               (int32_t)strlen(SOTER_INTERFACE_HASH));
}

static binder_status_t on_transact(AIBinder *binder, transaction_code_t code,
                                   const AParcel *in, AParcel *out) {
    (void)binder;
    const uint32_t tx = (uint32_t)code;

    if (tx == CODE_GET_INTERFACE_VERSION || tx == CODE_GET_INTERFACE_HASH) {
        binder_status_t status = write_metadata_reply(out, tx);
        LOGI("tx=%u metadata answered (%s) status=%d", tx,
             tx == CODE_GET_INTERFACE_VERSION ? "version" : "hash", (int)status);
        return status == STATUS_OK ? STATUS_OK : STATUS_UNKNOWN_TRANSACTION;
    }

    struct request request;
    const char *layout = read_layout(in);
    if (!read_request(tx, in, &request)) {
        LOGE("tx=%u layout=%s: the request could not be read", tx, layout);
        request_clear(&request);
        return STATUS_UNKNOWN_TRANSACTION;
    }
    log_request(tx, layout, &request);

    struct soterta_reply reply;
    int32_t result;
    if (g_mode == MODE_ANSWER) {
        result = soterta_handle(tx, request.uid, request.kname, request.challenge,
                                request.session, &reply);
    } else if (g_mode == MODE_DEAD) {
        result = soterta_dead_reply(tx, &reply);
    } else if (tx == TX_EXPORT_ATTK || tx == TX_GENERATE_ATTK || tx == TX_VERIFY_ATTK) {
        result = soterta_dead_reply(tx, &reply);
    } else {
        result = SOTERTA_UNHANDLED;
    }
    request_clear(&request);

    if (result == SOTERTA_ERROR) {
        char message[256];
        soterta_last_error(message, (int32_t)sizeof(message));
        LOGE("tx=%u could not be answered: %s", tx, message);
        return STATUS_UNKNOWN_TRANSACTION;
    }
    if (result != SOTERTA_HANDLED) {
        LOGI("tx=%u left unanswered (%s mode)", tx, mode_name(g_mode));
        return STATUS_UNKNOWN_TRANSACTION;
    }

    binder_status_t status = write_reply(out, &reply);
    LOGI("tx=%u answered kind=%d code=%d buffer=%zu status=%d", tx, reply.kind,
         reply.code, reply.buffer_len, (int)status);
    soterta_free(&reply);
    return status == STATUS_OK ? STATUS_OK : STATUS_UNKNOWN_TRANSACTION;
}

static void *on_create(void *args) {
    (void)args;
    return NULL;
}

static void on_destroy(void *userdata) {
    (void)userdata;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s [--mode=dead|log|answer] [--state=PATH] [--name=SERVICE] "
            "[--bio-gate=on|off]\n",
            program);
}

int main(int argc, char **argv) {
    const char *state_path = DEFAULT_STATE_PATH;
    const char *service_name = SOTER_SERVICE_NAME;

    for (int index = 1; index < argc; index++) {
        const char *arg = argv[index];
        if (strncmp(arg, "--mode=", 7) == 0) {
            const char *value = arg + 7;
            if (strcmp(value, "dead") == 0) {
                g_mode = MODE_DEAD;
            } else if (strcmp(value, "log") == 0) {
                g_mode = MODE_LOG;
            } else if (strcmp(value, "answer") == 0) {
                g_mode = MODE_ANSWER;
            } else {
                fprintf(stderr, "unknown mode: %s\n", value);
                usage(argv[0]);
                return 2;
            }
        } else if (strncmp(arg, "--state=", 8) == 0) {
            state_path = arg + 8;
        } else if (strncmp(arg, "--name=", 7) == 0) {
            service_name = arg + 7;
        } else if (strncmp(arg, "--bio-gate=", 11) == 0) {
            const char *value = arg + 11;
            if (strcmp(value, "on") == 0) {
                g_bio_gate = true;
            } else if (strcmp(value, "off") == 0) {
                g_bio_gate = false;
            } else {
                fprintf(stderr, "unknown bio gate: %s\n", value);
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(arg, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            usage(argv[0]);
            return 2;
        }
    }

    LOGI("starting: mode=%s pid=%d uid=%d state=%s service=%s", mode_name(g_mode),
         (int)getpid(), (int)getuid(), state_path, service_name);

    /* Block the termination signals before the binder thread pool starts, so
     * every thread inherits the mask and only this thread wakes on them. */
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGHUP);
    if (pthread_sigmask(SIG_BLOCK, &signals, NULL) != 0) {
        LOGE("cannot block the termination signals");
    }

    void *library = dlopen("/system/lib64/libbinder_ndk.so", RTLD_NOW);
    if (library == NULL) {
        LOGE("dlopen(libbinder_ndk.so) failed: %s", dlerror());
        return 4;
    }
    g_add_service = (add_service_fn)dlsym(library, "AServiceManager_addService");
    g_start_thread_pool =
        (start_thread_pool_fn)dlsym(library, "ABinderProcess_startThreadPool");
    g_mark_vintf_stability =
        (mark_vintf_stability_fn)dlsym(library, "AIBinder_markVintfStability");
    if (g_add_service == NULL || g_start_thread_pool == NULL) {
        LOGE("libbinder_ndk.so is missing a platform symbol");
        return 5;
    }
    if (g_mark_vintf_stability == NULL) {
        LOGE("libbinder_ndk.so is missing AIBinder_markVintfStability");
        return 5;
    }

    int32_t state_rc = soterta_init(state_path);
    if (state_rc < 0) {
        char message[256];
        soterta_last_error(message, (int32_t)sizeof(message));
        LOGE("cannot initialize %s: %s", state_path, message);
        if (g_mode == MODE_ANSWER) {
            return 6;
        }
    } else {
        LOGI("state %s: %s", state_path, state_rc == 1 ? "generated" : "loaded");
    }

    /* Session freshness needs the boot clock in either gate position; the
     * biometric gate adds the fingerprint counter. --bio-gate=off leaves that
     * hook unset, which makes the Rust half sign without one. */
    soterta_set_platform(platform_boot_ms, g_bio_gate ? platform_bio_mark : NULL);
    LOGI("bio gate=%s", g_bio_gate ? "on" : "off");

    /* Without this the transactions only queue up and are never answered. */
    g_start_thread_pool();

    AIBinder_Class *clazz =
        AIBinder_Class_define(SOTER_DESCRIPTOR, on_create, on_destroy, on_transact);
    if (clazz == NULL) {
        LOGE("AIBinder_Class_define(%s) failed", SOTER_DESCRIPTOR);
        return 2;
    }
    AIBinder *binder = AIBinder_new(clazz, NULL);
    if (binder == NULL) {
        LOGE("AIBinder_new(%s) failed", SOTER_DESCRIPTOR);
        return 2;
    }
    /* A vendor-only binder lets cryptoeng through but breaks SoterService on
     * the system side; system-only has the opposite failure. The stock AIDL
     * HAL is declared in VINTF, so mark the replacement accordingly. */
    g_mark_vintf_stability(binder);
    LOGI("service marked as VINTF stability");
    binder_status_t status = g_add_service(binder, service_name);
    LOGI("addService(%s) status=%d (VINTF)", service_name, (int)status);
    if (status != STATUS_OK) {
        /* Some vendor builds do not declare the Qualcomm Soter interface in
         * their VINTF manifest.  servicemanager rejects a VINTF-stable binder
         * for such a name with BAD_VALUE (-3), even though an ordinary binder
         * can still serve the exact same AIDL transactions.  Drop the failed
         * object and retry with a fresh, unmarked object; the first attempt is
         * retained for devices whose manifest does declare the HAL. */
        AIBinder_decStrong(binder);
        binder = AIBinder_new(clazz, NULL);
        if (binder == NULL) {
            LOGE("AIBinder_new(%s) failed for unmarked fallback", SOTER_DESCRIPTOR);
            return 2;
        }
        LOGI("retrying addService(%s) without VINTF stability", service_name);
        status = g_add_service(binder, service_name);
        LOGI("addService(%s) status=%d (unmarked fallback)", service_name,
             (int)status);
        if (status != STATUS_OK) {
            AIBinder_decStrong(binder);
            LOGE("is the stock HAL still running? stop vendor.soter first "
                 "(0=OK 7=PERMISSION_DENIED 9=ALREADY_EXISTS)");
            return 3;
        }
    }

    LOGI("ready: mode=%s service=%s pid=%d", mode_name(g_mode), service_name,
         (int)getpid());

    int signal_number = 0;
    if (sigwait(&signals, &signal_number) != 0) {
        LOGE("sigwait failed");
        pause();
    }
    LOGI("stopping on signal %d", signal_number);
    if (g_mode == MODE_ANSWER && soterta_save() < 0) {
        char message[256];
        soterta_last_error(message, (int32_t)sizeof(message));
        LOGE("cannot save the ledger: %s", message);
    }
    return 0;
}
