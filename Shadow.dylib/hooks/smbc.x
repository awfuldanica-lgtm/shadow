// SMBC bypass — translated from frida bypass12.js
//
// Two-pronged approach:
//  (a) Suppress security/system-error popups at construction time:
//      +[UIAlertController alertControllerWithTitle:message:preferredStyle:]
//      returns nil when title or message contains a Japanese-text needle
//      identifying a JB-detection alert.
//  (b) Make -[UIViewController presentViewController:animated:completion:]
//      tolerate a nil viewControllerToPresent (just call completion).
//  (c) NOP the libc termination chain (exit/abort/raise/kill/pthread_kill,
//      __cxa_throw, _objc_terminate, swift_unexpected, objc_exception_throw)
//      so any leftover kill path that fires after we suppress the alert
//      can't bring the process down.

#import "hooks.h"
#import <objc/runtime.h>
#import <pthread.h>
#import <signal.h>
#import <stdlib.h>
#import <mach/vm_map.h>
#import <mach/vm_statistics.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <dlfcn.h>
#import <errno.h>
#import <stdarg.h>
#import <stdio.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>

// ---------- diagnostics (smbc24) ----------
//
// NSLog from this dylib does not appear in idevicesyslog (presumably routed
// through a private os_log channel that requires Apple's logging profile).
// Append events to a file in the host app's NSDocumentDirectory so we can
// read it back via NewTerm:
//   sudo find /var/mobile/Containers/Data/Application -name "shadow_smbc24.log"
//   cat <found path>

// smbc57: write log entries via raw POSIX open(O_APPEND) + write().
// NSFileHandle.writeData (used in smbc55/56) was producing interleaved
// gibberish in the log even with @synchronized / pthread_mutex around
// the whole sequence — the writeData itself was apparently not the
// single-syscall write we assumed. Switch to raw POSIX:
//
//   fd = open(path, O_WRONLY | O_APPEND)
//   write(fd, line_bytes, len)
//   close(fd)
//
// POSIX guarantees that any write() of fewer than PIPE_BUF (=4096)
// bytes to a file opened with O_APPEND is atomic at the kernel level
// — no interleaving even if many threads write simultaneously, no
// userspace lock needed. seekToEndOfFile is implicit in O_APPEND.
//
// open() goes through our own hook which short-circuits on the diag
// path (smbc53), so no recursion.

static const char* shadowhook_smbc_diag_path = NULL;

void smbc24_diag(NSString* event) {
    static dispatch_once_t once = 0;
    dispatch_once(&once, ^{
        @try {
            NSArray* dirs = NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES);
            if (dirs.count == 0) return;
            NSString* p = [[dirs firstObject]
                stringByAppendingPathComponent:@"shadow_smbc24.log"];
            const char* utf = [p UTF8String];
            if (!utf) return;
            shadowhook_smbc_diag_path = strdup(utf);
            // Truncate the file so each fresh process starts with an
            // empty log. Header line below.
            int fd = open(shadowhook_smbc_diag_path,
                O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                NSString* hdr = [NSString stringWithFormat:
                    @"=== smbc24 session %@ ===\n", [NSDate date]];
                const char* hb = [hdr UTF8String];
                if (hb) write(fd, hb, strlen(hb));
                close(fd);
            }
        } @catch (id ex) {}
    });
    if (!shadowhook_smbc_diag_path) return;
    @try {
        NSString* line = [NSString stringWithFormat:@"%@ %@\n",
            [NSDate date], event];
        const char* bytes = [line UTF8String];
        if (!bytes) return;
        size_t len = strlen(bytes);
        if (len >= 4000) len = 4000;  // keep under PIPE_BUF for atomicity
        int fd = open(shadowhook_smbc_diag_path, O_WRONLY | O_APPEND);
        if (fd >= 0) {
            write(fd, bytes, len);
            close(fd);
        }
    } @catch (id ex) {}
}

// ---------- needles ----------

static NSArray<NSString *>* shadowhook_smbc_needles(void) {
    static NSArray* a = nil;
    static dispatch_once_t t = 0;
    dispatch_once(&t, ^{
        a = @[
            // Japanese (SMBC)
            @"セキュリティ", @"脱獄", @"改竄", @"改ざん",
            @"システムエラー",
            @"本アプリを終了",
            @"終了させていただ",
            @"本アプリはご利用",
            // Korean (UI Bank — uses Korean even on Japanese app)
            @"탈옥",          // jailbreak
            @"루팅",          // rooting
            @"비정상 단말",    // abnormal device
            @"비정상",         // abnormal (substring)
            @"지원하지 않",    // not supported
            // Generic English
            @"jailbreak", @"Jailbreak",
            @"Security Alert",
            @"Rooted",
        ];
    });
    return a;
}

static BOOL shadowhook_smbc_text_is_blocklisted(NSString* s) {
    if (!s || [s length] == 0) return NO;
    for (NSString* n in shadowhook_smbc_needles()) {
        if ([s rangeOfString:n].location != NSNotFound) return YES;
    }
    return NO;
}

// smbc42: obfuscated-string detector. UI Bank's JB warning alert (smbc41 log)
// shows title="tLTTQUXUc" and message starting with random base64-ish text
// like "4GLUyjCNZxwDL643FL6MvyE4A/wXwT". These look like WMatrix string-table
// lookup keys that did not get resolved, so the raw key leaks into the UI.
// Real, user-facing alert titles either contain whitespace, Japanese/Korean
// characters, or recognizable English words. A short ASCII-only token with
// no whitespace and length 5..30 is almost always an obfuscated key.
static BOOL shadowhook_smbc_text_looks_obfuscated(NSString* s) {
    if (!s) return NO;
    NSUInteger len = [s length];
    if (len < 5 || len > 30) return NO;
    NSCharacterSet* allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="];
    NSCharacterSet* notAllowed = [allowed invertedSet];
    // Disqualify if any char is outside the alphanumeric/base64 set
    // (this excludes whitespace, punctuation, CJK, accented letters).
    if ([s rangeOfCharacterFromSet:notAllowed].location != NSNotFound) return NO;
    // Require both letters and at least one of mixed case OR a digit, so we
    // do not flag short all-lowercase common words like "login" or "error".
    BOOL hasUpper = [s rangeOfCharacterFromSet:[NSCharacterSet uppercaseLetterCharacterSet]].location != NSNotFound;
    BOOL hasLower = [s rangeOfCharacterFromSet:[NSCharacterSet lowercaseLetterCharacterSet]].location != NSNotFound;
    BOOL hasDigit = [s rangeOfCharacterFromSet:[NSCharacterSet decimalDigitCharacterSet]].location != NSNotFound;
    if (!(hasUpper && hasLower)) return hasDigit && (hasUpper || hasLower);
    return YES;  // mixed case alphanumeric without spaces — looks obfuscated
}

static BOOL shadowhook_smbc_alert_text_should_block(NSString* s) {
    return shadowhook_smbc_text_is_blocklisted(s)
        || shadowhook_smbc_text_looks_obfuscated(s);
}

// ---------- (a) UIAlertController.alertControllerWithTitle:message:preferredStyle: ----------

typedef UIAlertController* (*shadowhook_smbc_alert_imp_t)(
    Class self, SEL _cmd, NSString* title, NSString* message, UIAlertControllerStyle style);
static shadowhook_smbc_alert_imp_t shadowhook_smbc_orig_alert = NULL;

static UIAlertController* shadowhook_smbc_alert_replacement(
    Class self, SEL _cmd, NSString* title, NSString* message, UIAlertControllerStyle style) {
    smbc24_diag([NSString stringWithFormat:@"FIRE: +alertControllerWithTitle: title=%@ message=%@",
                 title ?: @"(nil)", message ?: @"(nil)"]);
    if (shadowhook_smbc_alert_text_should_block(title) ||
        shadowhook_smbc_alert_text_should_block(message)) {
        NSLog(@"[Shadow/SMBC] suppress alert: title=%@ message=%@", title, message);
        return nil;
    }
    return shadowhook_smbc_orig_alert(self, _cmd, title, message, style);
}

// ---------- (b) -[UIViewController presentViewController:animated:completion:] ----------

typedef void (*shadowhook_smbc_present_imp_t)(
    id self, SEL _cmd, UIViewController* vc, BOOL animated, void (^completion)(void));
static shadowhook_smbc_present_imp_t shadowhook_smbc_orig_present = NULL;

static void shadowhook_smbc_present_replacement(
    id self, SEL _cmd, UIViewController* vc, BOOL animated, void (^completion)(void)) {
    smbc24_diag([NSString stringWithFormat:@"FIRE: presentViewController: vcClass=%@",
                 vc ? NSStringFromClass([vc class]) : @"(nil)"]);
    if (vc == nil) {
        NSLog(@"[Shadow/SMBC] skip present (nil vc)");
        if (completion) completion();
        return;
    }
    // Backstop: if vc is a UIAlertController whose title or message contains
    // a JB-detection needle, suppress the present even though it was built via
    // a path our +alertControllerWithTitle:message: swizzle did not intercept
    // (e.g., [[UIAlertController alloc] init] + KVC setTitle/setMessage).
    // UIBank_PRO syslog shows _willShowAlertController firing for a real
    // UIAlertController with the Korean JB warning text on com.dnx.japan.ui.bank.
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController* alert = (UIAlertController*)vc;
        NSString* title = alert.title;
        NSString* message = alert.message;
        if (shadowhook_smbc_text_is_blocklisted(title) ||
            shadowhook_smbc_text_is_blocklisted(message)) {
            NSLog(@"[Shadow/SMBC] suppress JB alert at present: title=%@ message=%@",
                  title, message);
            if (completion) completion();
            return;
        }
    }
    shadowhook_smbc_orig_present(self, _cmd, vc, animated, completion);
}

// ---------- (b2) -[UIViewController viewWillAppear:] backstop ----------
//
// UI Bank shows its JB-detection alert through a path that bypasses our
// presentViewController:animated:completion: hook (UIBank_PRO syslog
// 2026-04-29 16:38: alert reaches _willShowAlertController without our
// present hook firing). Most likely the app uses UIAlertControllerStackManager
// privately or attaches the alert to a UIWindow rootViewController directly.
//
// viewWillAppear: is the latest gate every UIViewController must pass before
// its view is rendered, regardless of how it was queued for display. We
// intercept here as a final backstop: if the controller is a UIAlertController
// whose title/message contains a JB-detection needle, schedule a dismiss on
// the next main-runloop tick so the alert never reaches the user.

typedef void (*shadowhook_smbc_vwa_imp_t)(id self, SEL _cmd, BOOL animated);
static shadowhook_smbc_vwa_imp_t shadowhook_smbc_orig_vwa = NULL;

static void shadowhook_smbc_vwa_replacement(id self, SEL _cmd, BOOL animated) {
    if ([self isKindOfClass:[UIAlertController class]]) {
        smbc24_diag([NSString stringWithFormat:@"FIRE: UIVC.viewWillAppear: selfClass=%@ title=%@",
                     NSStringFromClass([self class]),
                     [(UIAlertController*)self title] ?: @"(nil)"]);
    }
    UIAlertController* alertSelf = nil;
    BOOL shouldDismiss = NO;
    if ([self isKindOfClass:[UIAlertController class]]) {
        alertSelf = (UIAlertController*)self;
        NSString* title = alertSelf.title;
        NSString* message = alertSelf.message;
        if (shadowhook_smbc_text_is_blocklisted(title) ||
            shadowhook_smbc_text_is_blocklisted(message)) {
            NSLog(@"[Shadow/SMBC] suppress alert at viewWillAppear: title=%@ message=%@",
                  title, message);
            shouldDismiss = YES;
        }
    }
    // Always call original first to keep UIKit's bookkeeping intact.
    shadowhook_smbc_orig_vwa(self, _cmd, animated);
    if (shouldDismiss && alertSelf) {
        dispatch_async(dispatch_get_main_queue(), ^{
            UIViewController* presenting = alertSelf.presentingViewController;
            if (presenting) {
                [presenting dismissViewControllerAnimated:NO completion:nil];
            } else {
                [alertSelf dismissViewControllerAnimated:NO completion:nil];
            }
        });
    }
}

// (b3) UIAlertController-specific viewWillAppear: override (smbc21).
//
// smbc20 hooked -[UIViewController viewWillAppear:] but UI Bank's JB alert
// still reached the user fully displayed. UIAlertController has its own
// viewWillAppear: override in iOS UIKit; replacing the UIViewController-class
// IMP does not affect dispatch to UIAlertController's overridden IMP.
// Hook the UIAlertController-class Method directly so the override path is
// covered.

static shadowhook_smbc_vwa_imp_t shadowhook_smbc_orig_alert_vwa = NULL;

static void shadowhook_smbc_alert_vwa_replacement(id self, SEL _cmd, BOOL animated) {
    UIAlertController* alert = (UIAlertController*)self;
    NSString* title = alert.title;
    NSString* message = alert.message;
    smbc24_diag([NSString stringWithFormat:@"FIRE: UIAlertController.viewWillAppear: title=%@",
                 title ?: @"(nil)"]);
    BOOL hit = (shadowhook_smbc_alert_text_should_block(title) ||
                shadowhook_smbc_alert_text_should_block(message));
    shadowhook_smbc_orig_alert_vwa(self, _cmd, animated);
    if (hit) {
        NSLog(@"[Shadow/SMBC] suppress alert at -[UIAlertController viewWillAppear:]: title=%@ message=%@",
              title, message);
        dispatch_async(dispatch_get_main_queue(), ^{
            UIViewController* presenting = alert.presentingViewController;
            if (presenting) {
                [presenting dismissViewControllerAnimated:NO completion:nil];
            } else {
                [alert dismissViewControllerAnimated:NO completion:nil];
            }
        });
    }
}

void shadowhook_smbc_alerts(void) {
    {
        Class cls = [UIAlertController class];
        SEL sel = @selector(alertControllerWithTitle:message:preferredStyle:);
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_alert =
                (shadowhook_smbc_alert_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_alert_replacement);
            NSLog(@"[Shadow/SMBC] hooked +alertControllerWithTitle:message:preferredStyle:");
            smbc24_diag(@"INSTALL: +alertControllerWithTitle:message:preferredStyle:");
        }
    }
    {
        Class cls = [UIViewController class];
        SEL sel = @selector(presentViewController:animated:completion:);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_present =
                (shadowhook_smbc_present_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_present_replacement);
            NSLog(@"[Shadow/SMBC] hooked -presentViewController:animated:completion:");
            smbc24_diag(@"INSTALL: -[UIViewController presentViewController:]");
        }
    }
    {
        Class cls = [UIViewController class];
        SEL sel = @selector(viewWillAppear:);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_vwa =
                (shadowhook_smbc_vwa_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_vwa_replacement);
            NSLog(@"[Shadow/SMBC] hooked -[UIViewController viewWillAppear:]");
            smbc24_diag(@"INSTALL: -[UIViewController viewWillAppear:]");
        }
    }
    {
        // Cover the case where UIAlertController has its own viewWillAppear:
        // override (which iOS does — alerts run private setup at this point).
        // Only install if its Method differs from UIViewController's; if it
        // inherits, the parent hook above already covers it.
        Method ucm = class_getInstanceMethod([UIViewController class], @selector(viewWillAppear:));
        Method acm = class_getInstanceMethod([UIAlertController class], @selector(viewWillAppear:));
        if (acm && acm != ucm) {
            shadowhook_smbc_orig_alert_vwa =
                (shadowhook_smbc_vwa_imp_t)method_getImplementation(acm);
            method_setImplementation(acm, (IMP)shadowhook_smbc_alert_vwa_replacement);
            NSLog(@"[Shadow/SMBC] hooked -[UIAlertController viewWillAppear:] (own override)");
            smbc24_diag(@"INSTALL: -[UIAlertController viewWillAppear:] (own override)");
        } else if (acm == ucm) {
            NSLog(@"[Shadow/SMBC] UIAlertController inherits viewWillAppear: from UIViewController");
            smbc24_diag(@"INSTALL_NOTE: UIAlertController inherits viewWillAppear: from parent");
        }
    }
}

// ---------- (c) terminator blocks ----------

// smbc38: log via smbc24_diag (NSLog never shows up in the device syslog),
// include __builtin_return_address(0) so we can map the caller's PC back to
// a symbol with `atos -l <slide> -o <bin>` later.
#define SMBC_DIAG_DYING(fmt, ...) \
    smbc24_diag([NSString stringWithFormat:(@"FIRE: dying via " fmt @" from %p"), \
                 ##__VA_ARGS__, __builtin_return_address(0)])

static void (*shadowhook_smbc_orig_exit)(int) = NULL;
static void shadowhook_smbc_block_exit(int status) {
    SMBC_DIAG_DYING(@"exit(%d)", status);
    NSLog(@"[Shadow/SMBC] blocked exit(%d)", status);
}

static void (*shadowhook_smbc_orig__exit)(int) = NULL;
static void shadowhook_smbc_block__exit(int status) {
    SMBC_DIAG_DYING(@"_exit(%d)", status);
    NSLog(@"[Shadow/SMBC] blocked _exit(%d)", status);
}

static void (*shadowhook_smbc_orig_abort)(void) = NULL;
static void shadowhook_smbc_block_abort(void) {
    SMBC_DIAG_DYING(@"abort()");
    NSLog(@"[Shadow/SMBC] blocked abort");
}

static int (*shadowhook_smbc_orig_raise)(int) = NULL;
static int shadowhook_smbc_block_raise(int sig) {
    SMBC_DIAG_DYING(@"raise(%d)", sig);
    NSLog(@"[Shadow/SMBC] blocked raise(%d)", sig);
    return 0;
}

static int (*shadowhook_smbc_orig_kill)(pid_t, int) = NULL;
static int shadowhook_smbc_block_kill(pid_t pid, int sig) {
    if (sig == 0) {
        // probe call (existence check) — let it through
        return shadowhook_smbc_orig_kill(pid, sig);
    }
    SMBC_DIAG_DYING(@"kill(pid=%d,sig=%d)", pid, sig);
    NSLog(@"[Shadow/SMBC] blocked kill(%d,%d)", pid, sig);
    return 0;
}

static int (*shadowhook_smbc_orig_pthread_kill)(pthread_t, int) = NULL;
static int shadowhook_smbc_block_pthread_kill(pthread_t t, int sig) {
    SMBC_DIAG_DYING(@"pthread_kill(sig=%d)", sig);
    NSLog(@"[Shadow/SMBC] blocked pthread_kill(%d)", sig);
    return 0;
}

// __cxa_throw lives in libc++abi which shadow.dylib does not link against.
// Resolve at runtime via dlsym so we don't drag a hard link dependency.
static void (*shadowhook_smbc_orig_cxa_throw)(void*, void*, void (*)(void*)) = NULL;
static void shadowhook_smbc_block_cxa_throw(void* a, void* b, void (*c)(void*)) {
    SMBC_DIAG_DYING(@"__cxa_throw");
    NSLog(@"[Shadow/SMBC] blocked __cxa_throw");
}

// smbc38: additional kernel-direct termination paths that bypass libc.
// abort_with_reason / abort_with_payload — newer __noreturn aborts that
// don't go through abort() and therefore aren't caught by the abort hook.
// Used by frameworks that want to attach a reason code visible in the
// crash report. Signature matches <sys/reason.h>:
//   void abort_with_reason(uint32_t namespace, uint64_t code,
//                          const char *reason, uint64_t flags) __dead2;
//   void abort_with_payload(uint32_t namespace, uint64_t code,
//                           void *payload, uint32_t payload_size,
//                           const char *reason, uint64_t flags) __dead2;
static void (*shadowhook_smbc_orig_abort_with_reason)(
    uint32_t, uint64_t, const char*, uint64_t) = NULL;
static void shadowhook_smbc_block_abort_with_reason(
    uint32_t ns, uint64_t code, const char* reason, uint64_t flags) {
    SMBC_DIAG_DYING(@"abort_with_reason ns=%u code=0x%llx reason=%s",
                    ns, (long long)code, reason ? reason : "(null)");
    NSLog(@"[Shadow/SMBC] blocked abort_with_reason ns=%u code=0x%llx reason=%s",
          ns, (long long)code, reason ?: "(null)");
}

static void (*shadowhook_smbc_orig_abort_with_payload)(
    uint32_t, uint64_t, void*, uint32_t, const char*, uint64_t) = NULL;
static void shadowhook_smbc_block_abort_with_payload(
    uint32_t ns, uint64_t code, void* payload, uint32_t payload_size,
    const char* reason, uint64_t flags) {
    SMBC_DIAG_DYING(@"abort_with_payload ns=%u code=0x%llx reason=%s",
                    ns, (long long)code, reason ? reason : "(null)");
    NSLog(@"[Shadow/SMBC] blocked abort_with_payload ns=%u code=0x%llx reason=%s",
          ns, (long long)code, reason ?: "(null)");
}

// task_terminate / task_terminate_internal — Mach-level terminate that does
// not go through any signal/exception layer. If the app calls
// task_terminate(mach_task_self()) directly the kernel just kills us.
static kern_return_t (*shadowhook_smbc_orig_task_terminate)(mach_port_t) = NULL;
static kern_return_t shadowhook_smbc_block_task_terminate(mach_port_t target) {
    if (target == mach_task_self()) {
        SMBC_DIAG_DYING(@"task_terminate(self)");
        NSLog(@"[Shadow/SMBC] blocked task_terminate(self)");
        return KERN_SUCCESS;
    }
    return shadowhook_smbc_orig_task_terminate(target);
}

// smbc39: raw libsystem_kernel syscall wrappers. The libc termination
// functions (exit/_exit/abort/kill/pthread_kill) we hook are user-mode
// wrappers that ultimately call into libsystem_kernel.dylib's __exit /
// __pthread_kill / __kill. Code paths that link those kernel-level
// wrappers directly (or hand-write the syscall in inline asm) bypass
// our libc hooks. Hook them at libsystem_kernel level too. Note: if the
// binary inlines `mov x16, #1; svc 0`, we still can't catch that — that
// would require __text scanning + patching.
static void (*shadowhook_smbc_orig_kern_exit)(int) = NULL;
static void shadowhook_smbc_block_kern_exit(int status) {
    SMBC_DIAG_DYING(@"__exit(%d) [libsystem_kernel]", status);
    NSLog(@"[Shadow/SMBC] blocked __exit(%d)", status);
}

static int (*shadowhook_smbc_orig_kern_kill)(pid_t, int, int) = NULL;
static int shadowhook_smbc_block_kern_kill(pid_t pid, int sig, int posix) {
    if (sig == 0) {
        return shadowhook_smbc_orig_kern_kill(pid, sig, posix);
    }
    SMBC_DIAG_DYING(@"__kill(pid=%d,sig=%d) [libsystem_kernel]", pid, sig);
    NSLog(@"[Shadow/SMBC] blocked __kill(%d,%d)", pid, sig);
    return 0;
}

static int (*shadowhook_smbc_orig_kern_pthread_kill)(mach_port_t, int) = NULL;
static int shadowhook_smbc_block_kern_pthread_kill(mach_port_t thread_port, int sig) {
    SMBC_DIAG_DYING(@"__pthread_kill(sig=%d) [libsystem_kernel]", sig);
    NSLog(@"[Shadow/SMBC] blocked __pthread_kill(%d)", sig);
    return 0;
}

// posix_spawn / execve — used to re-exec self for "kill via replacement"
// pattern. Log and let through (we may need exec for legitimate cases).
static int (*shadowhook_smbc_orig_posix_spawn)(
    pid_t*, const char*, const void*, const void*,
    char* const[], char* const[]) = NULL;
static int shadowhook_smbc_block_posix_spawn(
    pid_t* pid, const char* path, const void* file_actions,
    const void* attrp, char* const argv[], char* const envp[]) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: posix_spawn path=%s", path ?: "(null)"]);
    return shadowhook_smbc_orig_posix_spawn(pid, path, file_actions, attrp,
                                             argv, envp);
}

// SIGABRT/SIGSEGV/SIGTERM/SIGPIPE catcher for visibility — purely diagnostic,
// reraise after logging so we don't paper over real crashes here.
static void shadowhook_smbc_sigterm_diag(int sig, siginfo_t* info, void* ctx) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: signal %d si_code=%d si_addr=%p",
        sig, info ? info->si_code : 0, info ? info->si_addr : NULL]);
    // Restore default and re-raise so the original behavior happens — this
    // is diagnostic only; we just want to know which signal arrived.
    signal(sig, SIG_DFL);
    raise(sig);
}

// atexit hook — fires on normal-ish exit paths (exit() — not _exit).
// If this fires we know exit() was reached by some path that bypassed our
// libc.exit hook (e.g. a static-linked exit, or a vector we didn't cover).
static void shadowhook_smbc_atexit_log(void) {
    smbc24_diag(@"FIRE: atexit reached (process exiting normally)");
}

// NSUncaughtException handler — function pointer (NSSetUncaughtExceptionHandler
// takes a C func, not a block).
static void shadowhook_smbc_uncaught_exc(NSException* e) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: NSUncaughtException name=%@ reason=%@",
        e.name, e.reason]);
}

// Swift fatal-error block (smbc35). All Swift runtime "report fatal error"
// entry points have different signatures, but they all share the property
// that they're __noreturn and end in a BRK trap. We replace them all with
// the same arg-agnostic stub that just logs and returns. The caller is
// __noreturn-expecting so returning is technically UB, but in practice
// most call sites are compiled with the next instruction being unreachable
// and the abort happens via the trap deeper in the function — preventing
// the trap by returning early lets the caller continue (with broken
// invariants we can't repair, but at least not crashed).
__attribute__((unused))
static void shadowhook_smbc_block_swift_fatal(void) {
    NSLog(@"[Shadow/SMBC] blocked swift_fatal");
    smbc24_diag(@"FIRE: blocked swift fatal");
}

// SIGTRAP/SIGILL handler (smbc36): smbc35 hooked the named Swift runtime
// fatal-error entry points but none fired before the 1s post-splash crash.
// The kill is most likely a direct BRK #1 trap inline in user code (Swift
// preconditionFailure on Optional unwrap or array-out-of-bounds, or a raw
// __builtin_trap() in app C code) that bypasses every libc/ObjC/Swift-fn
// hook. Catch it at the signal layer instead: sigaction handler for
// SIGTRAP/SIGILL/SIGBUS that advances PC by 4 (size of arm64 BRK) so the
// thread resumes past the trap. State is corrupted afterwards but the
// process keeps running — same gamble as the swift fatal NOP, more
// universal capture point.
#define _XOPEN_SOURCE 700
#include <signal.h>
#include <sys/ucontext.h>
#include <mach/mach.h>
#include <mach/exception_types.h>
#include <mach/arm/thread_state.h>
#include <ptrauth.h>
#include <string.h>
#include <pthread.h>
static void shadowhook_smbc_sigtrap_handler(int sig, siginfo_t* info, void* context) {
    void* faddr = info ? info->si_addr : NULL;
    NSLog(@"[Shadow/SMBC] caught sig=%d at %p — advancing PC", sig, faddr);
    smbc24_diag([NSString stringWithFormat:@"FIRE: caught sig=%d at %p", sig, faddr]);
#if defined(__arm64__) || defined(__aarch64__)
    if (context) {
        ucontext_t* uc = (ucontext_t*)context;
        if (uc->uc_mcontext) {
            uint64_t pc = (uint64_t)arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
            arm_thread_state64_set_pc_fptr(uc->uc_mcontext->__ss,
                (void(*)(void))(pc + 4));
        }
    }
#endif
}

// Mach exception handler (smbc37): smbc36 confirmed SIGTRAP/SIGILL/SIGBUS
// signal handler installs but never fires before the 1s post-splash kill.
// On iOS, BRK traps go through the Mach exception path FIRST (task port,
// then host port) before any signal is generated. If the app or one of its
// frameworks installed its own EXC_BREAKPOINT handler that calls
// task_terminate(), the signal layer never fires.
//
// Set the task's EXC_BREAKPOINT/EXC_BAD_INSTRUCTION/EXC_CRASH/EXC_GUARD
// exception ports to one we own. shadow.dylib loads during dyld init so we
// install before app code runs and our port wins. Server thread receives
// the Mach message, uses thread_set_state to advance the trapping
// thread's PC by 4 (size of arm64 BRK), replies KERN_SUCCESS so the kernel
// resumes the thread instead of terminating the task.
static mach_port_t shadowhook_smbc_exc_port = MACH_PORT_NULL;

static void* shadowhook_smbc_exception_thread(void* arg) {
    (void)arg;
    while (1) {
        // Mach exception message layout matches mach_exc_server expectations.
        // Packed because int64_t code[2] lands on offset 68 (not 8-aligned)
        // — kernel sends it that way, so we must match.
        struct __attribute__((packed)) {
            mach_msg_header_t Head;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t thread;
            mach_msg_port_descriptor_t task;
            NDR_record_t NDR;
            exception_type_t exception;
            mach_msg_type_number_t codeCnt;
            int64_t code[2];
            char trailer[64];
        } msg;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
        kern_return_t r = mach_msg(&msg.Head, MACH_RCV_MSG, 0, sizeof(msg),
            shadowhook_smbc_exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
#pragma clang diagnostic pop
        if (r != KERN_SUCCESS) continue;

        smbc24_diag([NSString stringWithFormat:
            @"FIRE: Mach exc=%d code0=0x%llx code1=0x%llx",
            msg.exception, (long long)msg.code[0], (long long)msg.code[1]]);
        NSLog(@"[Shadow/SMBC] caught Mach exc=%d code=0x%llx",
              msg.exception, (long long)msg.code[0]);

        arm_thread_state64_t state;
        mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(msg.thread.name, ARM_THREAD_STATE64,
                (thread_state_t)&state, &state_count) == KERN_SUCCESS) {
            uint64_t pc = (uint64_t)arm_thread_state64_get_pc(state);
            uint64_t fp = (uint64_t)arm_thread_state64_get_fp(state);
            // smbc44: previous reading misidentified code1 as PC. For
            // EXC_BAD_ACCESS, code[0]=KR (KERN_INVALID_ADDRESS=1) and
            // code[1]=the bad address being accessed. The actual PC is
            // in thread state. Logged PC + FP here so we can see what
            // we are actually faulting on.
            // smbc79: resolve PC and badaddr to library + symbol via dladdr
            // so we can identify which framework the BAD_ACCESS originates
            // in (after smbc78 eliminated all raise:format: events, the
            // remaining Mach exceptions are downstream PAC failures from
            // missing Firebase state — we need to know exactly where).
            Dl_info pc_info; memset(&pc_info, 0, sizeof(pc_info));
            Dl_info bad_info; memset(&bad_info, 0, sizeof(bad_info));
            int pc_ok = dladdr((const void*)(uintptr_t)pc, &pc_info);
            int bad_ok = (msg.code[1] >= 0x100000000) ?
                dladdr((const void*)(uintptr_t)msg.code[1], &bad_info) : 0;
            const char* pc_lib = pc_ok && pc_info.dli_fname
                ? strrchr(pc_info.dli_fname, '/') : NULL;
            pc_lib = pc_lib ? pc_lib + 1 : (pc_ok ? pc_info.dli_fname : "?");
            const char* pc_sym = pc_ok && pc_info.dli_sname ? pc_info.dli_sname : "?";
            const char* bad_lib = bad_ok && bad_info.dli_fname
                ? strrchr(bad_info.dli_fname, '/') : NULL;
            bad_lib = bad_lib ? bad_lib + 1 : (bad_ok ? bad_info.dli_fname : "?");
            const char* bad_sym = bad_ok && bad_info.dli_sname ? bad_info.dli_sname : "?";
            smbc24_diag([NSString stringWithFormat:
                @"FIRE: Mach state pc=0x%llx (%s+%s) fp=0x%llx badaddr=0x%llx (%s+%s)",
                pc, pc_lib, pc_sym, fp, (long long)msg.code[1], bad_lib, bad_sym]);

            // Pop a stack frame when:
            //   (a) PC is in NULL page (jumped to garbage), OR
            //   (b) BAD_ACCESS bad address is NULL/near-NULL (the
            //       function is doing *NULL — almost always means the
            //       caller is a JB-detection routine whose locals got
            //       wiped after our exception swallow).
            // Both cases: PC+=4 just keeps spinning. Forcing a frame
            // pop returns to the caller cleanly so the rest of the
            // app init can proceed.
            // smbc81: surgical fix for strlen(NULL) — set x0=0, PC=LR
            // and skip the multi-frame pop. _platform_strlen is hit
            // dozens of times after smbc78 because Foundation/Swift/
            // Firebase code calls strlen on nil pointers. Popping
            // unwinds whole worker threads (destructive). Returning 0
            // from strlen mimics empty-string semantics.
            BOOL strlen_handled = NO;
            if (msg.exception == EXC_BAD_ACCESS
                && (uint64_t)msg.code[1] < 0x10000
                && pc_ok && pc_info.dli_sname
                && strstr(pc_info.dli_sname, "platform_strlen")) {
                uint64_t lr = (uint64_t)arm_thread_state64_get_lr(state);
                lr = (uint64_t)ptrauth_strip(
                    (void*)lr, ptrauth_key_function_pointer);
                arm_thread_state64_set_pc_fptr(state, (void*)lr);
                state.__x[0] = 0;
                if (thread_set_state(msg.thread.name, ARM_THREAD_STATE64,
                        (thread_state_t)&state, ARM_THREAD_STATE64_COUNT)
                        == KERN_SUCCESS) {
                    smbc24_diag(
                        @"smbc81: strlen(NULL) -> x0=0 PC=LR");
                    strlen_handled = YES;
                }
            }

            BOOL should_pop = !strlen_handled && ((pc < 0x10000)
                || (msg.exception == EXC_BAD_ACCESS
                    && (uint64_t)msg.code[1] < 0x10000));
            if (should_pop && fp >= 0x10000 && (fp & 0x7) == 0) {
                // smbc46: pop multiple frames in a single exception
                // until we exit the dyld shared cache (>= 0x180000000)
                // back into app text or library text the user controls.
                // The shared-cache callers all dereference the same nil
                // ivar, so popping just 1 frame leaves us in another
                // system function with the same corrupted state — a
                // 2-address ping-pong as observed in smbc44 logs. Bound
                // the loop to 8 pops as a safety net.
                uint64_t cur_fp = fp;
                uint64_t saved_x29 = 0;
                uint64_t ret_addr = 0;
                int pops = 0;
                for (pops = 0; pops < 8; pops++) {
                    if (cur_fp < 0x10000 || (cur_fp & 0x7) != 0) break;
                    saved_x29 = ((uint64_t*)cur_fp)[0];
                    uint64_t saved_x30_signed = ((uint64_t*)cur_fp)[1];
                    void* stripped = ptrauth_strip(
                        (void*)saved_x30_signed,
                        ptrauth_key_function_pointer);
                    ret_addr = (uint64_t)stripped;
                    if (ret_addr < 0x10000) break;  // bad ret, stop
                    // If ret is outside the shared-cache region, accept
                    // this frame and stop popping.
                    if (ret_addr < 0x180000000ULL) break;
                    // Otherwise advance up one more frame.
                    cur_fp = saved_x29;
                }
                smbc24_diag([NSString stringWithFormat:
                    @"smbc46 pop x%d: pc=0x%llx fp=0x%llx -> ret=0x%llx fp_new=0x%llx",
                    pops + 1, pc, fp,
                    (long long)ret_addr, (long long)saved_x29]);
                arm_thread_state64_set_fp(state, saved_x29);
                arm_thread_state64_set_sp(state, cur_fp + 16);
                arm_thread_state64_set_pc_fptr(state,
                    (void(*)(void))ret_addr);
                arm_thread_state64_set_lr_fptr(state,
                    (void(*)(void))ret_addr);
            } else {
                arm_thread_state64_set_pc_fptr(state,
                    (void(*)(void))(pc + 4));
            }
            thread_set_state(msg.thread.name, ARM_THREAD_STATE64,
                (thread_state_t)&state, state_count);
        }

        // Send a "handled" reply so the kernel resumes the thread.
        struct __attribute__((packed)) {
            mach_msg_header_t Head;
            NDR_record_t NDR;
            kern_return_t RetCode;
        } reply;
        reply.Head.msgh_bits = MACH_MSGH_BITS(
            MACH_MSGH_BITS_REMOTE(msg.Head.msgh_bits), 0);
        reply.Head.msgh_size = sizeof(reply);
        reply.Head.msgh_remote_port = msg.Head.msgh_remote_port;
        reply.Head.msgh_local_port = MACH_PORT_NULL;
        reply.Head.msgh_id = msg.Head.msgh_id + 100;
        reply.Head.msgh_voucher_port = 0;
        reply.NDR = msg.NDR;
        reply.RetCode = KERN_SUCCESS;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
        mach_msg(&reply.Head, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
#pragma clang diagnostic pop

        // Release ports we received.
        mach_port_deallocate(mach_task_self(), msg.thread.name);
        mach_port_deallocate(mach_task_self(), msg.task.name);
    }
    return NULL;
}

static void shadowhook_smbc_install_mach_exc_handler(void) {
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
            &shadowhook_smbc_exc_port) != KERN_SUCCESS) {
        smbc24_diag(@"INSTALL: Mach exc port allocate FAILED");
        return;
    }
    if (mach_port_insert_right(mach_task_self(), shadowhook_smbc_exc_port,
            shadowhook_smbc_exc_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        smbc24_diag(@"INSTALL: Mach exc insert_right FAILED");
        return;
    }
    // smbc41: include EXC_MASK_BAD_ACCESS so jumps to garbage after our
    // __noreturn-returning hooks (raise:format: etc.) get intercepted at
    // the Mach layer. Without it, BAD_ACCESS reaches the signal layer
    // (which we cover too) but only after Mach reflection — the Mach
    // path is faster and lets us advance PC before signal translation.
    if (task_set_exception_ports(mach_task_self(),
            EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION
            | EXC_MASK_CRASH | EXC_MASK_GUARD | EXC_MASK_BAD_ACCESS,
            shadowhook_smbc_exc_port,
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
            ARM_THREAD_STATE64) != KERN_SUCCESS) {
        smbc24_diag(@"INSTALL: task_set_exception_ports FAILED");
        return;
    }
    pthread_t t;
    pthread_create(&t, NULL, shadowhook_smbc_exception_thread, NULL);
    pthread_detach(t);
    smbc24_diag(@"INSTALL: Mach exc handler (BRK/BAD_INSTR/CRASH/GUARD/BAD_ACCESS)");
    NSLog(@"[Shadow/SMBC] Mach exception handler installed on port %u",
          shadowhook_smbc_exc_port);
}

// smbc41: dispatch_after diagnostic. If FraudAlert/WMatrix queues a
// delayed kill (most likely culprit since app survives 1.3s after JB
// detection without any hooked terminator firing), we'll see it here.
// Just log the delay and call through — we don't want to disrupt
// legitimate dispatch_after usage.
static void (*shadowhook_smbc_orig_dispatch_after)(
    dispatch_time_t, dispatch_queue_t, dispatch_block_t) = NULL;
static void shadowhook_smbc_block_dispatch_after(
    dispatch_time_t when, dispatch_queue_t queue, dispatch_block_t block) {
    // Compute approximate delay in ms by subtracting from now.
    dispatch_time_t now = dispatch_time(DISPATCH_TIME_NOW, 0);
    int64_t delay_ns = (int64_t)when - (int64_t)now;
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: dispatch_after delay=%lldms block=%p caller=%p",
        delay_ns / 1000000, (void*)block, __builtin_return_address(0)]);
    shadowhook_smbc_orig_dispatch_after(when, queue, block);
}

// smbc41: NSTimer scheduledTimerWithTimeInterval:target:selector:... —
// the most common way to schedule a delayed action. Variants exist for
// block-based and userInfo-based timers; hook the most popular three.
typedef NSTimer* (*shadowhook_smbc_nstimer_imp_t)(Class, SEL, NSTimeInterval, id, SEL, id, BOOL);
static shadowhook_smbc_nstimer_imp_t shadowhook_smbc_orig_nstimer = NULL;
static NSTimer* shadowhook_smbc_block_nstimer(
    Class self, SEL _cmd, NSTimeInterval interval, id target, SEL action,
    id userInfo, BOOL repeats) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: NSTimer interval=%.3fs target=%@ action=%@ repeats=%d caller=%p",
        interval, [target class], NSStringFromSelector(action), repeats,
        __builtin_return_address(0)]);
    return shadowhook_smbc_orig_nstimer(self, _cmd, interval, target, action,
                                         userInfo, repeats);
}

typedef NSTimer* (*shadowhook_smbc_nstimer_block_imp_t)(Class, SEL, NSTimeInterval, BOOL, void(^)(NSTimer*));
static shadowhook_smbc_nstimer_block_imp_t shadowhook_smbc_orig_nstimer_block = NULL;
static NSTimer* shadowhook_smbc_block_nstimer_block(
    Class self, SEL _cmd, NSTimeInterval interval, BOOL repeats,
    void(^block)(NSTimer*)) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: NSTimer.block interval=%.3fs repeats=%d block=%p caller=%p",
        interval, repeats, (void*)block, __builtin_return_address(0)]);
    return shadowhook_smbc_orig_nstimer_block(self, _cmd, interval, repeats,
                                               block);
}

// +[NSException raise:format:] — variadic, matched by ObjC selector
typedef void (*shadowhook_smbc_nsexc_raise_imp_t)(
    Class self, SEL _cmd, NSString* name, NSString* format, ...);
static shadowhook_smbc_nsexc_raise_imp_t shadowhook_smbc_orig_nsexception_raise = NULL;

static void shadowhook_smbc_nsexception_raise_replacement(
    Class self, SEL _cmd, NSString* name, NSString* format, ...) {
    // smbc63: log the format string too — the obfuscated `name` reveals
    // nothing, but the format may contain a recognizable Swift fatal
    // template ("Fatal error: ...") or app-specific error wording that
    // tells us where in the code the raise is firing from.
    NSString* fmt_safe = format ?: @"(nil format)";
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: dying via +[NSException raise:format:] name=%@ fmt=%@ from %p",
        name, fmt_safe, __builtin_return_address(0)]);
    NSLog(@"[Shadow/SMBC] swallowed NSException raise: name=%@ format=%@", name, format);
}

// smbc40: -[NSException raise] (instance method, no format) — separate
// selector from +[NSException raise:format:]. Caught here so we can
// distinguish between class-method and instance-method raise paths.
typedef void (*shadowhook_smbc_nsexc_irraise_imp_t)(NSException*, SEL);
static shadowhook_smbc_nsexc_irraise_imp_t shadowhook_smbc_orig_nsexception_irraise = NULL;
static void shadowhook_smbc_nsexception_irraise_replacement(
    NSException* self, SEL _cmd) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: dying via -[NSException raise] name=%@ reason=%@ from %p",
        self.name, self.reason, __builtin_return_address(0)]);
    NSLog(@"[Shadow/SMBC] swallowed -[NSException raise] name=%@ reason=%@",
          self.name, self.reason);
}

// smbc40: objc_exception_throw — the low-level libobjc entry point that
// +[NSException raise:format:] eventually calls. If app code calls
// objc_exception_throw directly (e.g. precompiled foundation, ObjC
// rethrow), it bypasses our raise:format: hook.
static void (*shadowhook_smbc_orig_objc_throw)(id) = NULL;
static void shadowhook_smbc_block_objc_throw(id exception) {
    @try {
        NSException* e = (NSException*)exception;
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: dying via objc_exception_throw name=%@ reason=%@ from %p",
            e.name, e.reason, __builtin_return_address(0)]);
    } @catch (id ex) {
        smbc24_diag(@"FIRE: dying via objc_exception_throw (unreadable)");
    }
    NSLog(@"[Shadow/SMBC] swallowed objc_exception_throw");
}

// smbc40: __assert_rtn — BSD-style assertion failure. Calls abort() but
// some toolchains link __assert_rtn directly bypassing our abort hook
// (e.g. when the trap is part of a __noreturn-marked path).
static void (*shadowhook_smbc_orig_assert_rtn)(const char*, const char*, int, const char*) = NULL;
static void shadowhook_smbc_block_assert_rtn(const char* func, const char* file, int line, const char* expr) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: dying via __assert_rtn func=%s file=%s:%d expr=%s",
        func ?: "?", file ?: "?", line, expr ?: "?"]);
    NSLog(@"[Shadow/SMBC] blocked __assert_rtn %s:%d %s", file, line, expr);
}

// smbc40: heartbeat thread. Writes "tick N" every 100ms so we can see
// exactly how long the process survives after CTOR_REACHED. The last
// tick number before death tells us elapsed survival time, and any log
// entries between two ticks are the events leading up to the kill.
// smbc76: re-run validateAPIKey: swizzle from heartbeat. Forward declare.
extern void shadowhook_uibank_retry_validateAPIKey_swizzle(void);

static void* shadowhook_smbc_heartbeat_thread(void* arg) {
    (void)arg;
    int n = 0;
    while (1) {
        usleep(100 * 1000);  // 100ms
        smbc24_diag([NSString stringWithFormat:@"tick %d", n++]);
        // smbc76: every tick, retry the swizzle. The implementing class
        // for -validateAPIKey: lives in a framework that loads later;
        // keep retrying until we catch it.
        if (n < 100) {
            // Only retry for first 10 seconds — don't burn CPU forever.
            shadowhook_uibank_retry_validateAPIKey_swizzle();
        }
    }
    return NULL;
}

// smbc45: map a read-only zero page at virtual address 0 so that any
// NULL pointer dereference in the app reads zero instead of faulting.
// After our exception swallow corrupts an instance's ivars to NULL, the
// app keeps using that NULL object — system frameworks (CoreFoundation,
// UIKit, Swift runtime) deref offset 0x0 (isa) and 0x8 (next ivar)
// over and over, hitting BAD_ACCESS each time. With page 0 mapped
// readable, those reads silently return 0 and execution continues
// instead of stalling in the Mach exception handler.
//
// Limited to the first 16KB so writes still trap (we want to know
// about NULL writes — those are real bugs we should not paper over).
static void shadowhook_smbc_install_null_page(void) {
    vm_address_t addr = 0;
    vm_size_t size = 0x4000;  // one 16K page
    kern_return_t kr = vm_allocate(mach_task_self(), &addr, size,
        VM_FLAGS_FIXED);
    if (kr != KERN_SUCCESS) {
        smbc24_diag([NSString stringWithFormat:
            @"INSTALL: NULL page allocate FAILED kr=%d", kr]);
        return;
    }
    if (addr != 0) {
        // Got a different address back — the FIXED flag was ignored.
        // Release and abandon rather than leaving an unrelated mapping.
        vm_deallocate(mach_task_self(), addr, size);
        smbc24_diag([NSString stringWithFormat:
            @"INSTALL: NULL page allocated at 0x%lx (not 0), released",
            (unsigned long)addr]);
        return;
    }
    kr = vm_protect(mach_task_self(), 0, size, FALSE, VM_PROT_READ);
    if (kr != KERN_SUCCESS) {
        smbc24_diag([NSString stringWithFormat:
            @"INSTALL: NULL page protect FAILED kr=%d", kr]);
        return;
    }
    smbc24_diag(@"INSTALL: NULL page mapped read-only at 0x0..0x4000");
}

// smbc49: hook the actual JB indicator probes (sysctlbyname, dlsym,
// dlopen, dladdr, access, open, fopen, getenv) at libc/dyld level. The
// agent's deeper disassembly showed UI Bank queries these directly
// (12x sysctlbyname, 25x dlsym, 5x dlopen, 10x dladdr, 4x access, 3x
// getenv, etc.) to detect substrate/frida/roothide and trace state,
// then fails with Swift fatal-error nil-unwrap (which is what we were
// previously catching as raise:format:). Patch the probes to deny
// every JB indicator so the app's "isJB" decision becomes false and
// the Swift inits populate their Optional<T>s correctly — no nil
// force-unwrap, no exceptions, no state corruption.

// smbc51/52/53: per-hook trace counters with a path filter that skips
// any access touching our own diag log file. The __thread guard from
// smbc52 wasn't enough — NSFileHandle writes go through a Foundation
// dispatch queue running on a different thread, so the guard didn't
// transfer and we still saw recursive log entries (~200 deep). Plus
// concurrent writes from multiple worker threads got their bytes
// interleaved at the file level, producing pages of base64-looking
// gibberish in the log.
//
// Use a path-string filter instead — every path-based hook checks
// whether the path is our diag log and bails out before trace+lie if
// so. This is reliable across threads since it doesn't rely on TLS.
#include <stdatomic.h>
#define SMBC_TRACE_LIMIT 200
static __thread int shadowhook_smbc_in_hook = 0;

// True when the path is one we generate from inside smbc24_diag — must
// pass through silently or we will log our own writes (and possibly
// race with concurrent diag writes).
static BOOL shadowhook_smbc_path_is_diag(const char* p) {
    return p && strstr(p, "shadow_smbc24.log") != NULL;
}
static atomic_int shadowhook_smbc_trace_n_sysctlbyname = 0;
static atomic_int shadowhook_smbc_trace_n_sysctl = 0;
static atomic_int shadowhook_smbc_trace_n_access = 0;
static atomic_int shadowhook_smbc_trace_n_stat = 0;
static atomic_int shadowhook_smbc_trace_n_lstat = 0;
static atomic_int shadowhook_smbc_trace_n_open = 0;
static atomic_int shadowhook_smbc_trace_n_fopen = 0;
static atomic_int shadowhook_smbc_trace_n_getenv = 0;
static atomic_int shadowhook_smbc_trace_n_dlopen = 0;
static atomic_int shadowhook_smbc_trace_n_dlsym = 0;
static atomic_int shadowhook_smbc_trace_n_dladdr = 0;
static atomic_int shadowhook_smbc_trace_n_fexists = 0;
static atomic_int shadowhook_smbc_trace_n_dyldimg = 0;

#define SMBC_TRACE(counter, fmt, ...) do {                  \
    if (shadowhook_smbc_in_hook) break;                     \
    shadowhook_smbc_in_hook = 1;                            \
    int __n = atomic_fetch_add(&(counter), 1);              \
    if (__n < SMBC_TRACE_LIMIT) {                           \
        smbc24_diag([NSString stringWithFormat:(fmt),       \
            ##__VA_ARGS__]);                                \
    }                                                       \
    shadowhook_smbc_in_hook = 0;                            \
} while (0)

static int (*shadowhook_smbc_orig_sysctlbyname)(const char*, void*, size_t*, void*, size_t) = NULL;
static int shadowhook_smbc_block_sysctlbyname(
    const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    SMBC_TRACE(shadowhook_smbc_trace_n_sysctlbyname,
        @"trace: sysctlbyname(%s)", name ?: "(null)");
    int rv = shadowhook_smbc_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (rv == 0 && oldp && oldlenp && name) {
        // Anti-debug pattern: query KERN_PROC for current pid then check
        // p_flag for P_TRACED (0x800). Clear that flag so the app sees
        // "not being traced".
        if (strcmp(name, "kern.proc.pid") == 0
            || strncmp(name, "kern.proc.pid.", 14) == 0) {
            // kp_proc.p_flag is at offset 32 in struct kinfo_proc (xnu).
            if (*oldlenp >= 36) {
                int* pflag = (int*)((char*)oldp + 32);
                if (*pflag & 0x800) {
                    *pflag &= ~0x800;
                    smbc24_diag([NSString stringWithFormat:
                        @"FIRE: sysctlbyname(%s) — cleared P_TRACED",
                        name]);
                }
            }
        }
        // amfi.dev_signed is queried to detect dev-signed binaries — pretend
        // the device only runs Apple-signed code.
        if (strcmp(name, "security.mac.amfi.dev_signed") == 0
            && *oldlenp >= 4) {
            *(int*)oldp = 0;
            smbc24_diag(@"FIRE: sysctlbyname amfi.dev_signed -> 0 (lied)");
        }
    }
    return rv;
}

static int (*shadowhook_smbc_orig_sysctl)(int*, unsigned int, void*, size_t*, void*, size_t) = NULL;
static int shadowhook_smbc_block_sysctl(
    int* mib, unsigned int namelen, void* oldp, size_t* oldlenp,
    void* newp, size_t newlen) {
    SMBC_TRACE(shadowhook_smbc_trace_n_sysctl,
        @"trace: sysctl(mib[0..%u]={%d,%d,%d,%d})", namelen,
        namelen >= 1 ? mib[0] : 0, namelen >= 2 ? mib[1] : 0,
        namelen >= 3 ? mib[2] : 0, namelen >= 4 ? mib[3] : 0);
    int rv = shadowhook_smbc_orig_sysctl(mib, namelen, oldp, oldlenp,
                                          newp, newlen);
    if (rv == 0 && namelen >= 4 && mib && oldp && oldlenp
        && mib[0] == 1 /*CTL_KERN*/ && mib[1] == 14 /*KERN_PROC*/
        && mib[2] == 1 /*KERN_PROC_PID*/) {
        if (*oldlenp >= 36) {
            int* pflag = (int*)((char*)oldp + 32);
            if (*pflag & 0x800) {
                *pflag &= ~0x800;
                smbc24_diag(@"FIRE: sysctl KERN_PROC_PID — cleared P_TRACED");
            }
        }
    }
    return rv;
}

// smbc50: previous needle list was too broad. "jbroot-" matched the user's
// own roothide-managed Documents/AppGroup container path, so EVERY file
// access from the app got denied — including its own data — which crashed
// the app within a second. roothide-specific path prefixes (jbroot-,
// roothide) are SYSTEM-WIDE, not JB indicators. Same for unanchored
// substrings like "frida" / "Frida" / "FRIDA" which can collide with
// app names. Restrict needles to absolute JB-tool paths only.
static BOOL shadowhook_smbc_path_looks_jb(const char* p) {
    if (!p) return NO;
    static const char* needles[] = {
        // smbc54: roothide redirects "/var/jb/..." accesses to
        // "/var/containers/Bundle/Application/.jbroot-XXX/var/jb/..."
        // Both forms appear in app traces. The trailing slash on
        // "/var/jb/" prevents matching "/var/jbroot-" (the system's
        // legitimate jailbreak-root container marker, used as a path
        // prefix for ALL roothide-managed apps' data — was the bug
        // in smbc49 that crashed every file access). UI Bank queries
        // this layer to detect known JB tweaks like VCamPlus.
        "/var/jb/",
        "/private/var/jb/",
        // Classic JB filesystem layouts (absolute paths only).
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/TweakInject.dylib",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/Library/PreferenceLoader",
        "/Library/Activator",
        "/var/lib/apt/",
        "/var/lib/cydia/",
        "/var/cache/apt/",
        "/private/var/lib/apt/",
        "/private/var/lib/cydia/",
        "/etc/apt/",
        "/var/checkra1n.dmg",
        "/.bootstrapped_electra",
        "/.installed_unc0ver",
        // Frida agent paths (anchored).
        "/usr/sbin/frida-server",
        "/usr/local/frida-server",
        "/var/usr/lib/frida",
        // URL schemes (only checked when caller uses these as strings).
        "cydia://",
        "sileo://",
        "filza://",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strstr(p, needles[i])) return YES;
    }
    return NO;
}

static int (*shadowhook_smbc_orig_access)(const char*, int) = NULL;
static int shadowhook_smbc_block_access(const char* path, int amode) {
    if (shadowhook_smbc_path_is_diag(path))
        return shadowhook_smbc_orig_access(path, amode);
    SMBC_TRACE(shadowhook_smbc_trace_n_access,
        @"trace: access(%s,%d)", path ?: "(null)", amode);
    if (shadowhook_smbc_path_looks_jb(path)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: access(%s,%d) -> ENOENT (lied)", path, amode]);
        errno = 2; // ENOENT
        return -1;
    }
    return shadowhook_smbc_orig_access(path, amode);
}

static int (*shadowhook_smbc_orig_stat)(const char*, struct stat*) = NULL;
static int shadowhook_smbc_block_stat(const char* path, struct stat* buf) {
    if (shadowhook_smbc_path_is_diag(path))
        return shadowhook_smbc_orig_stat(path, buf);
    SMBC_TRACE(shadowhook_smbc_trace_n_stat,
        @"trace: stat(%s)", path ?: "(null)");
    if (shadowhook_smbc_path_looks_jb(path)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: stat(%s) -> ENOENT (lied)", path]);
        errno = 2;
        return -1;
    }
    return shadowhook_smbc_orig_stat(path, buf);
}

static int (*shadowhook_smbc_orig_lstat)(const char*, struct stat*) = NULL;
static int shadowhook_smbc_block_lstat(const char* path, struct stat* buf) {
    if (shadowhook_smbc_path_is_diag(path))
        return shadowhook_smbc_orig_lstat(path, buf);
    SMBC_TRACE(shadowhook_smbc_trace_n_lstat,
        @"trace: lstat(%s)", path ?: "(null)");
    if (shadowhook_smbc_path_looks_jb(path)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: lstat(%s) -> ENOENT (lied)", path]);
        errno = 2;
        return -1;
    }
    return shadowhook_smbc_orig_lstat(path, buf);
}

static int (*shadowhook_smbc_orig_open)(const char*, int, ...) = NULL;
static int shadowhook_smbc_block_open(const char* path, int oflag, ...) {
    if (shadowhook_smbc_path_is_diag(path)) {
        mode_t mode = 0;
        if (oflag & 0x200) {
            va_list ap; va_start(ap, oflag); mode = va_arg(ap, int); va_end(ap);
        }
        return shadowhook_smbc_orig_open(path, oflag, mode);
    }
    SMBC_TRACE(shadowhook_smbc_trace_n_open,
        @"trace: open(%s,0x%x)", path ?: "(null)", oflag);
    if (shadowhook_smbc_path_looks_jb(path)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: open(%s) -> ENOENT (lied)", path]);
        errno = 2;
        return -1;
    }
    mode_t mode = 0;
    if (oflag & 0x200 /* O_CREAT */) {
        va_list ap; va_start(ap, oflag); mode = va_arg(ap, int); va_end(ap);
    }
    return shadowhook_smbc_orig_open(path, oflag, mode);
}

static FILE* (*shadowhook_smbc_orig_fopen)(const char*, const char*) = NULL;
static FILE* shadowhook_smbc_block_fopen(const char* path, const char* mode) {
    if (shadowhook_smbc_path_is_diag(path))
        return shadowhook_smbc_orig_fopen(path, mode);
    SMBC_TRACE(shadowhook_smbc_trace_n_fopen,
        @"trace: fopen(%s,%s)", path ?: "(null)", mode ?: "(null)");
    if (shadowhook_smbc_path_looks_jb(path)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: fopen(%s) -> NULL (lied)", path]);
        errno = 2;
        return NULL;
    }
    return shadowhook_smbc_orig_fopen(path, mode);
}

static char* (*shadowhook_smbc_orig_getenv)(const char*) = NULL;
static char* shadowhook_smbc_block_getenv(const char* name) {
    SMBC_TRACE(shadowhook_smbc_trace_n_getenv,
        @"trace: getenv(%s)", name ?: "(null)");
    // smbc59: use exact name match instead of substring match. smbc58s
    // substring "ROOTHIDE" and "TWEAK" matched env vars roothide and
    // shadow internals legitimately read, causing those internals to
    // fail and the app to crash within ~1s (regression from smbc57s
    // white-screen behaviour). Only lie for env vars that are
    // unambiguously JB-detection indicators.
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0
                 || strcmp(name, "_MSSafeMode") == 0
                 || strcmp(name, "_SubstrateUseSystemLogs") == 0
                 || strcmp(name, "JBPATHLOG") == 0)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: getenv(%s) -> NULL (lied)", name]);
        return NULL;
    }
    return shadowhook_smbc_orig_getenv(name);
}

static void* (*shadowhook_smbc_orig_dlopen)(const char*, int) = NULL;
static void* shadowhook_smbc_block_dlopen(const char* path, int mode) {
    SMBC_TRACE(shadowhook_smbc_trace_n_dlopen,
        @"trace: dlopen(%s,0x%x)", path ?: "(null)", mode);
    if (shadowhook_smbc_path_looks_jb(path)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: dlopen(%s) -> NULL (lied)", path]);
        return NULL;
    }
    return shadowhook_smbc_orig_dlopen(path, mode);
}

static void* (*shadowhook_smbc_orig_dlsym)(void*, const char*) = NULL;
static void* shadowhook_smbc_block_dlsym(void* handle, const char* name) {
    SMBC_TRACE(shadowhook_smbc_trace_n_dlsym,
        @"trace: dlsym(%s)", name ?: "(null)");
    if (name) {
        // Substrate / frida / hooking-tool symbols.
        static const char* hot[] = {
            "MSGetImageByName",
            "MSHookFunction",
            "MSHookMessageEx",
            "MSFindSymbol",
            "task_for_pid",
            "_dyld_get_image_count",
            "_dyld_get_image_header",
            "_dyld_get_image_name",
            "_dyld_get_image_vmaddr_slide",
            "frida_agent_main",
            "gum_init",
            "Substrate",
            "substitute_hook_functions",
            NULL
        };
        for (int i = 0; hot[i]; i++) {
            if (strstr(name, hot[i])) {
                smbc24_diag([NSString stringWithFormat:
                    @"FIRE: dlsym(%s) -> NULL (lied)", name]);
                return NULL;
            }
        }
    }
    return shadowhook_smbc_orig_dlsym(handle, name);
}

static int (*shadowhook_smbc_orig_dladdr)(const void*, Dl_info*) = NULL;
static int shadowhook_smbc_block_dladdr(const void* addr, Dl_info* info) {
    int rv = shadowhook_smbc_orig_dladdr(addr, info);
    if (rv && info && info->dli_fname) {
        SMBC_TRACE(shadowhook_smbc_trace_n_dladdr,
            @"trace: dladdr(%p) -> %s", addr, info->dli_fname);
    }
    if (rv && info && info->dli_fname && shadowhook_smbc_path_looks_jb(info->dli_fname)) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: dladdr returned %s — replacing with /usr/lib/dyld",
            info->dli_fname]);
        info->dli_fname = "/usr/lib/dyld";
    }
    return rv;
}

// smbc62: task_info(mach_task_self(), TASK_DYLD_INFO, ...) returns the
// address of dyld_all_image_infos — a kernel-exposed structure with the
// complete list of loaded mach_headers and their imageFilePath strings.
// Apps that scan this directly bypass _dyld_image_count entirely. UI
// Bank's main exe references task_info 2x and mach_task_self 2x. To
// block the inventory-style JB detection, we return KERN_FAILURE
// specifically for the TASK_DYLD_INFO flavor and pass every other
// flavor through unchanged. TASK_DYLD_INFO is flavor 17. The struct
// task_dyld_info has count TASK_DYLD_INFO_COUNT; we don't touch the
// out buffer when failing.
//
// Risk: legitimate callers (Crashlytics, profilers, lldb) ask for
// TASK_DYLD_INFO. Returning failure may degrade their function but
// shouldn't crash — they generally check the kern_return_t.
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_init.h>

static atomic_int shadowhook_smbc_trace_n_taskinfo = 0;
static kern_return_t (*shadowhook_smbc_orig_task_info)(
    task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t*) = NULL;
static kern_return_t shadowhook_smbc_block_task_info(
    task_name_t target, task_flavor_t flavor,
    task_info_t info_out, mach_msg_type_number_t* count) {
    SMBC_TRACE(shadowhook_smbc_trace_n_taskinfo,
        @"trace: task_info(target=0x%x flavor=%d)", target, flavor);
    if (flavor == TASK_DYLD_INFO) {
        smbc24_diag([NSString stringWithFormat:
            @"FIRE: task_info(TASK_DYLD_INFO) -> KERN_FAILURE (lied)"]);
        return KERN_FAILURE;
    }
    return shadowhook_smbc_orig_task_info(target, flavor, info_out, count);
}

// smbc60: dyld image enumeration hooks. UI Bank's main exe binary
// references _dyld_image_count, _dyld_get_image_name,
// _dyld_get_image_header, _dyld_register_func_for_add_image (verified
// 2x each in /Desktop/shadow/UIBank_PRO). The app iterates loaded
// dylibs and any image whose path contains JB markers
// (Shadow.dylib, TweakLoader.dylib, /var/jb/, libsubstrate.dylib, etc.)
// signals jailbreak. Strategy: present a filtered view that hides JB
// images entirely. The keep-list is rebuilt on every image_count call
// so a subsequent get_image_name(i) sees a stable index space.
//
// Important: only invoke smbc24_diag from these hooks INSIDE the
// SMBC_TRACE re-entry guard (it sets shadowhook_smbc_in_hook). The
// raw-POSIX writer in smbc57 won't recurse, but the underlying call
// site iterates *all* dylibs and we don't want each image visit to
// log a line during normal startup.
#define SHADOWHOOK_SMBC_DYLD_KEEP_MAX 1024
static uint32_t shadowhook_smbc_dyld_keep_indices[SHADOWHOOK_SMBC_DYLD_KEEP_MAX];
static uint32_t shadowhook_smbc_dyld_keep_count = 0;
static pthread_mutex_t shadowhook_smbc_dyld_mtx;
static int shadowhook_smbc_dyld_mtx_inited = 0;

static uint32_t (*shadowhook_smbc_orig_dyld_image_count)(void) = NULL;
static const char* (*shadowhook_smbc_orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header*
    (*shadowhook_smbc_orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t
    (*shadowhook_smbc_orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;
static void (*shadowhook_smbc_orig_dyld_register_func_for_add_image)(
    void (*)(const struct mach_header*, intptr_t)) = NULL;

static void shadowhook_smbc_dyld_init_mtx_once(void) {
    if (!shadowhook_smbc_dyld_mtx_inited) {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&shadowhook_smbc_dyld_mtx, &attr);
        pthread_mutexattr_destroy(&attr);
        shadowhook_smbc_dyld_mtx_inited = 1;
    }
}

static void shadowhook_smbc_dyld_rebuild_keep_locked(void) {
    if (!shadowhook_smbc_orig_dyld_image_count ||
        !shadowhook_smbc_orig_dyld_get_image_name) {
        return;
    }
    uint32_t real = shadowhook_smbc_orig_dyld_image_count();
    uint32_t kept = 0;
    int hidden = 0;
    for (uint32_t i = 0; i < real && kept < SHADOWHOOK_SMBC_DYLD_KEEP_MAX; i++) {
        const char* name = shadowhook_smbc_orig_dyld_get_image_name(i);
        if (!name || !shadowhook_smbc_path_looks_jb(name)) {
            shadowhook_smbc_dyld_keep_indices[kept++] = i;
        } else {
            hidden++;
            // Log only first time per session per name; bounded by
            // trace counter to avoid flood.
            SMBC_TRACE(shadowhook_smbc_trace_n_dyldimg,
                @"FIRE: dyld image hidden idx=%u %s", i, name);
        }
    }
    shadowhook_smbc_dyld_keep_count = kept;
    if (hidden) {
        SMBC_TRACE(shadowhook_smbc_trace_n_dyldimg,
            @"trace: dyld_image_count real=%u kept=%u hidden=%d",
            real, kept, hidden);
    }
}

static uint32_t shadowhook_smbc_block_dyld_image_count(void) {
    shadowhook_smbc_dyld_init_mtx_once();
    pthread_mutex_lock(&shadowhook_smbc_dyld_mtx);
    shadowhook_smbc_dyld_rebuild_keep_locked();
    uint32_t c = shadowhook_smbc_dyld_keep_count;
    pthread_mutex_unlock(&shadowhook_smbc_dyld_mtx);
    return c;
}

static const char* shadowhook_smbc_block_dyld_get_image_name(uint32_t i) {
    shadowhook_smbc_dyld_init_mtx_once();
    uint32_t real_i = i;
    pthread_mutex_lock(&shadowhook_smbc_dyld_mtx);
    if (i < shadowhook_smbc_dyld_keep_count) {
        real_i = shadowhook_smbc_dyld_keep_indices[i];
    }
    pthread_mutex_unlock(&shadowhook_smbc_dyld_mtx);
    if (!shadowhook_smbc_orig_dyld_get_image_name) return NULL;
    return shadowhook_smbc_orig_dyld_get_image_name(real_i);
}

static const struct mach_header*
shadowhook_smbc_block_dyld_get_image_header(uint32_t i) {
    shadowhook_smbc_dyld_init_mtx_once();
    uint32_t real_i = i;
    pthread_mutex_lock(&shadowhook_smbc_dyld_mtx);
    if (i < shadowhook_smbc_dyld_keep_count) {
        real_i = shadowhook_smbc_dyld_keep_indices[i];
    }
    pthread_mutex_unlock(&shadowhook_smbc_dyld_mtx);
    if (!shadowhook_smbc_orig_dyld_get_image_header) return NULL;
    return shadowhook_smbc_orig_dyld_get_image_header(real_i);
}

static intptr_t
shadowhook_smbc_block_dyld_get_image_vmaddr_slide(uint32_t i) {
    shadowhook_smbc_dyld_init_mtx_once();
    uint32_t real_i = i;
    pthread_mutex_lock(&shadowhook_smbc_dyld_mtx);
    if (i < shadowhook_smbc_dyld_keep_count) {
        real_i = shadowhook_smbc_dyld_keep_indices[i];
    }
    pthread_mutex_unlock(&shadowhook_smbc_dyld_mtx);
    if (!shadowhook_smbc_orig_dyld_get_image_vmaddr_slide) return 0;
    return shadowhook_smbc_orig_dyld_get_image_vmaddr_slide(real_i);
}

// register_func_for_add_image: dyld invokes the supplied callback once
// per currently-loaded image, then again on every future dlopen. Apps
// use this for inventory-based JB checks. We wrap the user's callback
// with a filter that drops invocations for JB images. Multiple
// callbacks may be registered; track up to 16.
typedef void (*shadowhook_smbc_dyld_addimg_cb_t)(
    const struct mach_header*, intptr_t);

#define SHADOWHOOK_SMBC_DYLD_ADDIMG_MAX 16
static shadowhook_smbc_dyld_addimg_cb_t
    shadowhook_smbc_dyld_addimg_user[SHADOWHOOK_SMBC_DYLD_ADDIMG_MAX];
static int shadowhook_smbc_dyld_addimg_count = 0;

#define SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(N) \
static void shadowhook_smbc_dyld_addimg_tramp_##N( \
    const struct mach_header* mh, intptr_t slide) { \
    Dl_info info; \
    if (mh && shadowhook_smbc_orig_dladdr && \
        shadowhook_smbc_orig_dladdr((const void*)mh, &info) && \
        info.dli_fname && \
        shadowhook_smbc_path_looks_jb(info.dli_fname)) { \
        SMBC_TRACE(shadowhook_smbc_trace_n_dyldimg, \
            @"FIRE: addimg cb#%d swallowed for %s", N, info.dli_fname); \
        return; \
    } \
    shadowhook_smbc_dyld_addimg_cb_t cb = \
        shadowhook_smbc_dyld_addimg_user[N]; \
    if (cb) cb(mh, slide); \
}
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(0)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(1)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(2)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(3)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(4)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(5)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(6)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(7)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(8)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(9)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(10)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(11)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(12)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(13)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(14)
SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP(15)
#undef SHADOWHOOK_SMBC_DYLD_DEFINE_TRAMP

static const shadowhook_smbc_dyld_addimg_cb_t
    shadowhook_smbc_dyld_addimg_tramp_table[SHADOWHOOK_SMBC_DYLD_ADDIMG_MAX] = {
    shadowhook_smbc_dyld_addimg_tramp_0,  shadowhook_smbc_dyld_addimg_tramp_1,
    shadowhook_smbc_dyld_addimg_tramp_2,  shadowhook_smbc_dyld_addimg_tramp_3,
    shadowhook_smbc_dyld_addimg_tramp_4,  shadowhook_smbc_dyld_addimg_tramp_5,
    shadowhook_smbc_dyld_addimg_tramp_6,  shadowhook_smbc_dyld_addimg_tramp_7,
    shadowhook_smbc_dyld_addimg_tramp_8,  shadowhook_smbc_dyld_addimg_tramp_9,
    shadowhook_smbc_dyld_addimg_tramp_10, shadowhook_smbc_dyld_addimg_tramp_11,
    shadowhook_smbc_dyld_addimg_tramp_12, shadowhook_smbc_dyld_addimg_tramp_13,
    shadowhook_smbc_dyld_addimg_tramp_14, shadowhook_smbc_dyld_addimg_tramp_15,
};

static void shadowhook_smbc_block_dyld_register_func_for_add_image(
    void (*func)(const struct mach_header*, intptr_t)) {
    shadowhook_smbc_dyld_init_mtx_once();
    pthread_mutex_lock(&shadowhook_smbc_dyld_mtx);
    int idx = shadowhook_smbc_dyld_addimg_count;
    shadowhook_smbc_dyld_addimg_cb_t tramp = NULL;
    if (idx < SHADOWHOOK_SMBC_DYLD_ADDIMG_MAX) {
        shadowhook_smbc_dyld_addimg_user[idx] = func;
        tramp = shadowhook_smbc_dyld_addimg_tramp_table[idx];
        shadowhook_smbc_dyld_addimg_count = idx + 1;
    }
    pthread_mutex_unlock(&shadowhook_smbc_dyld_mtx);
    SMBC_TRACE(shadowhook_smbc_trace_n_dyldimg,
        @"trace: register_func_for_add_image cb=%p slot=%d", func, idx);
    if (shadowhook_smbc_orig_dyld_register_func_for_add_image) {
        shadowhook_smbc_orig_dyld_register_func_for_add_image(
            tramp ? tramp : func);
    }
}

// smbc50: NSFileManager fileExistsAtPath: — most common ObjC file check.
typedef BOOL (*shadowhook_smbc_fexists_imp_t)(id, SEL, NSString*);
static shadowhook_smbc_fexists_imp_t shadowhook_smbc_orig_fexists = NULL;
static BOOL shadowhook_smbc_block_fexists(id self, SEL _cmd, NSString* path) {
    if (path) {
        const char* cpath = [path UTF8String];
        if (shadowhook_smbc_path_is_diag(cpath))
            return shadowhook_smbc_orig_fexists(self, _cmd, path);
        SMBC_TRACE(shadowhook_smbc_trace_n_fexists,
            @"trace: fileExistsAtPath(%s)", cpath ?: "(null)");
        if (shadowhook_smbc_path_looks_jb(cpath)) {
            smbc24_diag([NSString stringWithFormat:
                @"FIRE: -[NSFileManager fileExistsAtPath:%@] -> NO (lied)",
                path]);
            return NO;
        }
    }
    return shadowhook_smbc_orig_fexists(self, _cmd, path);
}

typedef BOOL (*shadowhook_smbc_fexists_isdir_imp_t)(id, SEL, NSString*, BOOL*);
static shadowhook_smbc_fexists_isdir_imp_t shadowhook_smbc_orig_fexists_isdir = NULL;
static BOOL shadowhook_smbc_block_fexists_isdir(id self, SEL _cmd, NSString* path, BOOL* isDir) {
    if (path) {
        const char* cpath = [path UTF8String];
        if (shadowhook_smbc_path_is_diag(cpath))
            return shadowhook_smbc_orig_fexists_isdir(self, _cmd, path, isDir);
        SMBC_TRACE(shadowhook_smbc_trace_n_fexists,
            @"trace: fileExistsAtPath:isDir(%s)", cpath ?: "(null)");
        if (shadowhook_smbc_path_looks_jb(cpath)) {
            smbc24_diag([NSString stringWithFormat:
                @"FIRE: -[NSFileManager fileExistsAtPath:%@ isDir:] -> NO (lied)",
                path]);
            if (isDir) *isDir = NO;
            return NO;
        }
    }
    return shadowhook_smbc_orig_fexists_isdir(self, _cmd, path, isDir);
}

// smbc80: hook strlen / strnlen to gracefully handle NULL argument.
// After smbc78 patched out raise 6, downstream code (Firebase Swift,
// Foundation runtime) keeps invoking strlen on options properties that
// are now nil, segfaulting at _platform_strlen with badaddr=0x0.
static size_t (*shadowhook_smbc_orig_strlen)(const char*) = NULL;
static size_t shadowhook_smbc_block_strlen(const char* s) {
    if (!s) return 0;
    return shadowhook_smbc_orig_strlen(s);
}
static size_t (*shadowhook_smbc_orig_strnlen)(const char*, size_t) = NULL;
static size_t shadowhook_smbc_block_strnlen(const char* s, size_t n) {
    if (!s) return 0;
    return shadowhook_smbc_orig_strnlen(s, n);
}

static void shadowhook_smbc_install_probe_hooks(HKSubstitutor* hooks) {
    void* sym;
    sym = dlsym(RTLD_DEFAULT, "sysctlbyname");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_sysctlbyname,
                       (void**)&shadowhook_smbc_orig_sysctlbyname);
        smbc24_diag(@"INSTALL: sysctlbyname");
    }
    sym = dlsym(RTLD_DEFAULT, "sysctl");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_sysctl,
                       (void**)&shadowhook_smbc_orig_sysctl);
        smbc24_diag(@"INSTALL: sysctl");
    }
    sym = dlsym(RTLD_DEFAULT, "access");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_access,
                       (void**)&shadowhook_smbc_orig_access);
        smbc24_diag(@"INSTALL: access");
    }
    sym = dlsym(RTLD_DEFAULT, "stat");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_stat,
                       (void**)&shadowhook_smbc_orig_stat);
        smbc24_diag(@"INSTALL: stat");
    }
    sym = dlsym(RTLD_DEFAULT, "lstat");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_lstat,
                       (void**)&shadowhook_smbc_orig_lstat);
        smbc24_diag(@"INSTALL: lstat");
    }
    {
        Class cls = NSClassFromString(@"NSFileManager");
        if (cls) {
            SEL sel = @selector(fileExistsAtPath:);
            Method m = class_getInstanceMethod(cls, sel);
            if (m) {
                shadowhook_smbc_orig_fexists =
                    (shadowhook_smbc_fexists_imp_t)method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_smbc_block_fexists);
                smbc24_diag(@"INSTALL: -[NSFileManager fileExistsAtPath:]");
            }
            sel = @selector(fileExistsAtPath:isDirectory:);
            m = class_getInstanceMethod(cls, sel);
            if (m) {
                shadowhook_smbc_orig_fexists_isdir =
                    (shadowhook_smbc_fexists_isdir_imp_t)method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_smbc_block_fexists_isdir);
                smbc24_diag(@"INSTALL: -[NSFileManager fileExistsAtPath:isDirectory:]");
            }
        }
    }
    sym = dlsym(RTLD_DEFAULT, "open");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_open,
                       (void**)&shadowhook_smbc_orig_open);
        smbc24_diag(@"INSTALL: open");
    }
    // smbc80: NULL-safe strlen / strnlen.
    sym = dlsym(RTLD_DEFAULT, "strlen");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_strlen,
                       (void**)&shadowhook_smbc_orig_strlen);
        smbc24_diag(@"INSTALL: strlen NULL-safe");
    }
    sym = dlsym(RTLD_DEFAULT, "strnlen");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_strnlen,
                       (void**)&shadowhook_smbc_orig_strnlen);
        smbc24_diag(@"INSTALL: strnlen NULL-safe");
    }
    sym = dlsym(RTLD_DEFAULT, "fopen");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_fopen,
                       (void**)&shadowhook_smbc_orig_fopen);
        smbc24_diag(@"INSTALL: fopen");
    }
    sym = dlsym(RTLD_DEFAULT, "getenv");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_getenv,
                       (void**)&shadowhook_smbc_orig_getenv);
        smbc24_diag(@"INSTALL: getenv");
    }
    sym = dlsym(RTLD_DEFAULT, "dlopen");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_dlopen,
                       (void**)&shadowhook_smbc_orig_dlopen);
        smbc24_diag(@"INSTALL: dlopen");
    }
    sym = dlsym(RTLD_DEFAULT, "dlsym");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_dlsym,
                       (void**)&shadowhook_smbc_orig_dlsym);
        smbc24_diag(@"INSTALL: dlsym");
    }
    sym = dlsym(RTLD_DEFAULT, "dladdr");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_dladdr,
                       (void**)&shadowhook_smbc_orig_dladdr);
        smbc24_diag(@"INSTALL: dladdr");
    }
    // smbc62: task_info hook to block TASK_DYLD_INFO inventory.
    sym = dlsym(RTLD_DEFAULT, "task_info");
    if (sym) {
        MSHookFunction(sym, (void*)shadowhook_smbc_block_task_info,
                       (void**)&shadowhook_smbc_orig_task_info);
        smbc24_diag(@"INSTALL: task_info");
    }
    // smbc61: dyld_image_* hooks disabled. Trace from smbc60 confirmed
    // _dyld_image_count was never called by UI Bank during startup —
    // and merely installing these hooks regressed white-screen back
    // to 1s crash via a secondary BAD_ACCESS at pc=0x203d8ae44 whose
    // multi-frame pop succeeded in smbc59 but failed once the dyld
    // hook trampolines were present (likely a stack/PAC layout shift
    // in the unwinder). Code retained above so we can re-enable for a
    // controlled experiment, but install is gated off.
    (void)shadowhook_smbc_block_dyld_image_count;
    (void)shadowhook_smbc_block_dyld_get_image_name;
    (void)shadowhook_smbc_block_dyld_get_image_header;
    (void)shadowhook_smbc_block_dyld_get_image_vmaddr_slide;
    (void)shadowhook_smbc_block_dyld_register_func_for_add_image;
}

// smbc47: hook UIBank_PRO main exe's two Swift JB-detection functions
// directly, replacing them with a stub that returns 0 (false). The
// disassembly identified two functions:
//   - file offset 0x7afd0c — contains 5 +[NSException raise:format:]
//     calls with name "EcnaIN+rtCjxmB8V" (the obfuscated exception
//     name observed in our logs). 0xBA8 bytes / ~744 instructions.
//   - file offset 0x7b7824 — contains 2 raises with name
//     "fa/YjnlinS4WfJ1R33X27xCowx". 0x650 bytes.
// Both are reached via Swift function-pointer / witness-table dispatch
// (BR x16). Neither registered in __objc_methlist, so we cannot use
// the ObjC method-replacement path — must hook by absolute address.
//
// The stub is a naked function: MOV X0, #0; RET. ABI-agnostic — works
// for Swift Bool/void/Optional<T>/AnyObject? since Swift always uses
// x0 for the return value (and primary self register in legacy Swift)
// and we don't touch the stack so callers' frame is undisturbed.
__attribute__((naked, used))
static int shadowhook_smbc_jbcheck_returns_false(void) {
    __asm__ volatile(
        "mov x0, #0\n"
        "ret\n"
    );
}

__attribute__((unused))
static void shadowhook_smbc_install_jbcheck_hooks(HKSubstitutor* hooks) {
    static const struct {
        const char* name_substr;
        uintptr_t offsets[2];
    } targets = {
        "UIBank_PRO",
        { 0x7afd0c, 0x7b7824 }
    };
    uint32_t count = _dyld_image_count();
    intptr_t slide = 0;
    const struct mach_header* mh = NULL;
    const char* matched_name = NULL;
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (!name) continue;
        // Match the main exe ("UIBank_PRO" appears in path AND there's no
        // ".framework/" further along — frameworks named UIBank_PRO would
        // be unlikely but be defensive).
        if (strstr(name, "/UIBank_PRO") && !strstr(name, ".framework/")) {
            mh = _dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            matched_name = name;
            break;
        }
    }
    if (!mh) {
        smbc24_diag(@"INSTALL: JB-check fns - main exe UIBank_PRO not found in dyld images");
        return;
    }
    smbc24_diag([NSString stringWithFormat:
        @"INSTALL: matched main exe %s base=%p slide=0x%lx",
        matched_name, (void*)mh, (unsigned long)slide]);
    for (int i = 0; i < (int)(sizeof(targets.offsets)/sizeof(targets.offsets[0])); i++) {
        void* target = (void*)((uintptr_t)mh + targets.offsets[i]);
        void* orig = NULL;
        MSHookFunction(target,
            (void*)shadowhook_smbc_jbcheck_returns_false, &orig);
        smbc24_diag([NSString stringWithFormat:
            @"INSTALL: JB-check fn[%d] @ %p (file offset 0x%lx)",
            i, target, (unsigned long)targets.offsets[i]]);
    }
}

void shadowhook_smbc_terminators(HKSubstitutor* hooks) {
    // smbc47 was DISABLED in smbc48 (replacing the entry was too coarse —
    // it skipped legitimate Swift class-init too, crashing the app).
    // smbc49 retargets at the actual probes the JB-detection logic
    // queries: sysctlbyname/sysctl/access/open/fopen/getenv/dlopen/
    // dlsym/dladdr. Each is hooked to deny every JB indicator (and
    // log every call so we can see what fires).
    shadowhook_smbc_install_probe_hooks(hooks);

    // smbc45: install NULL page first, before anything else can fault.
    shadowhook_smbc_install_null_page();

    MSHookFunction((void*)exit,         (void*)shadowhook_smbc_block_exit,
                   (void**)&shadowhook_smbc_orig_exit);
    MSHookFunction((void*)_exit,        (void*)shadowhook_smbc_block__exit,
                   (void**)&shadowhook_smbc_orig__exit);
    MSHookFunction((void*)abort,        (void*)shadowhook_smbc_block_abort,
                   (void**)&shadowhook_smbc_orig_abort);
    MSHookFunction((void*)raise,        (void*)shadowhook_smbc_block_raise,
                   (void**)&shadowhook_smbc_orig_raise);
    MSHookFunction((void*)kill,         (void*)shadowhook_smbc_block_kill,
                   (void**)&shadowhook_smbc_orig_kill);
    MSHookFunction((void*)pthread_kill, (void*)shadowhook_smbc_block_pthread_kill,
                   (void**)&shadowhook_smbc_orig_pthread_kill);
    void* cxa_throw_addr = dlsym(RTLD_DEFAULT, "__cxa_throw");
    if (cxa_throw_addr) {
        MSHookFunction(cxa_throw_addr,  (void*)shadowhook_smbc_block_cxa_throw,
                       (void**)&shadowhook_smbc_orig_cxa_throw);
    }

    // ObjC-level: hook +[NSException raise:format:] so JB-related raises just
    // log and return instead of throwing. Stops the exception chain at the
    // source rather than trying to catch it after the fact (where _objc_terminate
    // would __builtin_trap us).
    {
        Class cls = [NSException class];
        SEL sel = @selector(raise:format:);
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_nsexception_raise =
                (shadowhook_smbc_nsexc_raise_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_nsexception_raise_replacement);
            NSLog(@"[Shadow/SMBC] hooked +[NSException raise:format:]");
        }
    }

    // Swift runtime fatal-error hooks (smbc35): UI Bank crashes ~1s after
    // splash via a path that bypasses libc.exit and ObjC NSException. The
    // most likely vector is Swift fatalError() / preconditionFailure() which
    // compile to BRK #1 (SIGTRAP) trap, not via libc. Hook the Swift runtime
    // reporting symbols that lead to the trap and replace with NOPs.
    // dlsym lookup so we don't link against libswiftCore directly.
    {
        const char* swift_fatal_syms[] = {
            "swift_runtime_on_report",
            "_swift_runtime_on_report",
            "swift_runtime_on_failure",
            "_swift_runtime_on_failure",
            "_swift_stdlib_reportFatalError",
            "_swift_stdlib_reportFatalErrorInFile",
            "_swift_assertionFailure",
            "_swift_unexpected",
            "_swift_fatalError",
            "_swift_arrayInitializeBufferWithTakeOfBuffer",
            NULL
        };
        for (int i = 0; swift_fatal_syms[i]; i++) {
            void* addr = dlsym(RTLD_DEFAULT, swift_fatal_syms[i]);
            if (addr) {
                void* orig = NULL;
                MSHookFunction(addr, (void*)shadowhook_smbc_block_swift_fatal,
                               &orig);
                NSLog(@"[Shadow/SMBC] hooked %s @ %p", swift_fatal_syms[i], addr);
                smbc24_diag([NSString stringWithFormat:
                    @"INSTALL: swift fatal sym %s", swift_fatal_syms[i]]);
            }
        }
    }

    // SIGTRAP/SIGILL/SIGBUS handler (smbc36) — kept as fallback after the
    // Mach exception handler. If anything bypasses Mach (e.g. host-level
    // exception was claimed by something else), the signal layer is the
    // last line.
    {
        struct sigaction sa = {0};
        sa.sa_sigaction = shadowhook_smbc_sigtrap_handler;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTRAP, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        NSLog(@"[Shadow/SMBC] installed SIGTRAP/SIGILL/SIGBUS handler");
        smbc24_diag(@"INSTALL: SIGTRAP/SIGILL/SIGBUS handler");
    }

    // Mach exception handler (smbc37) — catches BRK before signal layer.
    shadowhook_smbc_install_mach_exc_handler();

    // smbc38: extra termination paths that bypassed every previous hook.
    {
        void* sym = dlsym(RTLD_DEFAULT, "abort_with_reason");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_abort_with_reason,
                           (void**)&shadowhook_smbc_orig_abort_with_reason);
            smbc24_diag(@"INSTALL: abort_with_reason");
        }
        sym = dlsym(RTLD_DEFAULT, "abort_with_payload");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_abort_with_payload,
                           (void**)&shadowhook_smbc_orig_abort_with_payload);
            smbc24_diag(@"INSTALL: abort_with_payload");
        }
        sym = dlsym(RTLD_DEFAULT, "task_terminate");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_task_terminate,
                           (void**)&shadowhook_smbc_orig_task_terminate);
            smbc24_diag(@"INSTALL: task_terminate");
        }
        sym = dlsym(RTLD_DEFAULT, "posix_spawn");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_posix_spawn,
                           (void**)&shadowhook_smbc_orig_posix_spawn);
            smbc24_diag(@"INSTALL: posix_spawn");
        }
    }

    // smbc39: hook libsystem_kernel raw syscall wrappers. Code paths that
    // call directly into __exit / __kill / __pthread_kill (the kernel-side
    // wrappers, not the libc wrappers we already hook) skip every libc
    // hook above. Different addresses than libc symbols of similar name.
    {
        void* sym = dlsym(RTLD_DEFAULT, "__exit");
        if (sym && sym != (void*)_exit) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_kern_exit,
                           (void**)&shadowhook_smbc_orig_kern_exit);
            smbc24_diag(@"INSTALL: __exit [libsystem_kernel]");
        }
        sym = dlsym(RTLD_DEFAULT, "__kill");
        if (sym && sym != (void*)kill) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_kern_kill,
                           (void**)&shadowhook_smbc_orig_kern_kill);
            smbc24_diag(@"INSTALL: __kill [libsystem_kernel]");
        }
        sym = dlsym(RTLD_DEFAULT, "__pthread_kill");
        if (sym && sym != (void*)pthread_kill) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_kern_pthread_kill,
                           (void**)&shadowhook_smbc_orig_kern_pthread_kill);
            smbc24_diag(@"INSTALL: __pthread_kill [libsystem_kernel]");
        }
    }

    // smbc38: diagnostic-only signal handlers for SIGABRT/SIGSEGV/SIGTERM/
    // SIGPIPE — log which signal arrives then re-raise to default to keep
    // crash report intact.
    {
        struct sigaction sa = {0};
        sa.sa_sigaction = shadowhook_smbc_sigterm_diag;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESETHAND;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGABRT, &sa, NULL);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGPIPE, &sa, NULL);
        sigaction(SIGSYS, &sa, NULL);
        smbc24_diag(@"INSTALL: SIGABRT/SIGSEGV/SIGTERM/SIGPIPE/SIGSYS diag");
    }

    // smbc38: atexit fires before normal exit. If FIRE: atexit shows up,
    // exit() reached on a code path that wasn't caught by our libc.exit
    // hook (statically-linked exit somewhere, alternate entry, etc.).
    atexit(shadowhook_smbc_atexit_log);
    smbc24_diag(@"INSTALL: atexit logger");

    // smbc38: NSUncaughtException handler — fires for any ObjC exception
    // that escapes all @catch blocks before the runtime calls
    // _objc_terminate -> abort.
    NSSetUncaughtExceptionHandler(&shadowhook_smbc_uncaught_exc);
    smbc24_diag(@"INSTALL: NSUncaughtExceptionHandler");

    // smbc40: -[NSException raise] (instance method, no format). Separate
    // selector from class method +raise:format: — must hook independently.
    {
        Class cls = [NSException class];
        SEL sel = @selector(raise);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_nsexception_irraise =
                (shadowhook_smbc_nsexc_irraise_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_nsexception_irraise_replacement);
            smbc24_diag(@"INSTALL: -[NSException raise]");
        }
    }

    // smbc40: objc_exception_throw — low-level libobjc throw entry.
    {
        void* sym = dlsym(RTLD_DEFAULT, "objc_exception_throw");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_objc_throw,
                           (void**)&shadowhook_smbc_orig_objc_throw);
            smbc24_diag(@"INSTALL: objc_exception_throw");
        }
    }

    // smbc40: __assert_rtn — BSD assert.
    {
        void* sym = dlsym(RTLD_DEFAULT, "__assert_rtn");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_assert_rtn,
                           (void**)&shadowhook_smbc_orig_assert_rtn);
            smbc24_diag(@"INSTALL: __assert_rtn");
        }
    }

    // smbc40: heartbeat thread — survival time tracker.
    {
        pthread_t hb;
        pthread_create(&hb, NULL, shadowhook_smbc_heartbeat_thread, NULL);
        pthread_detach(hb);
        smbc24_diag(@"INSTALL: heartbeat thread (100ms)");
    }

    // smbc41: dispatch_after / NSTimer logging — diagnose the delayed kill
    // that fires ~1.3s after we swallow the JB exceptions.
    {
        void* sym = dlsym(RTLD_DEFAULT, "dispatch_after");
        if (sym) {
            MSHookFunction(sym, (void*)shadowhook_smbc_block_dispatch_after,
                           (void**)&shadowhook_smbc_orig_dispatch_after);
            smbc24_diag(@"INSTALL: dispatch_after");
        }
    }
    {
        Class cls = [NSTimer class];
        SEL sel = @selector(scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:);
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_nstimer =
                (shadowhook_smbc_nstimer_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_block_nstimer);
            smbc24_diag(@"INSTALL: +[NSTimer scheduledTimer...target:selector:]");
        }
        sel = @selector(scheduledTimerWithTimeInterval:repeats:block:);
        m = class_getClassMethod(cls, sel);
        if (m) {
            shadowhook_smbc_orig_nstimer_block =
                (shadowhook_smbc_nstimer_block_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_smbc_block_nstimer_block);
            smbc24_diag(@"INSTALL: +[NSTimer scheduledTimer...block:]");
        }
    }

    NSLog(@"[Shadow/SMBC] terminator chain blocked");
}

// ---------- (d) UI Bank specific (com.dnx.japan.ui.bank) ----------
//
// UI Bank kills the process at +load time inside
//   +[StockNewsdmManager loadProfileWithCache]
//      -> -[UpdateMIssuesManager viewDidUnload:Loader2:]
//         -> exit(0)
//
// Method names look like obfuscated business code; they are actually the
// jailbreak guard. Replacing the +load methods with no-ops short-circuits
// the kill before exit() is even reached.
//
// The actual security alert that the user sees on a non-frida launch is a
// JavaScript alert() raised inside a WMatrixWebView; the hook calls the
// completion handler immediately so no UI is shown and the JS continues
// without believing it told the user anything.
//
// We try the hook in a polling loop because at %ctor-time the ObjC classes
// from the main app binary may not be registered yet.

// Replacement returns id (empty NSDictionary) instead of void so that callers
// expecting a non-nil object reference get a usable empty container in x0
// rather than whatever garbage register state happened to be left behind.
// Without this, downstream Swift code in UIApplication delegate callbacks
// passes the garbage to __CFDictionaryCreateGeneric which raises NSException
// (observed in UIBank_PRO-2026-04-25-231009.ips, smbc17 on com.dnx.japan.ui.bank).
static IMP shadowhook_uibank_orig_loadprofile = NULL;
static id shadowhook_uibank_loadprofile_replacement(id self, SEL _cmd) {
    NSLog(@"[Shadow/UIBank] NOP +[StockNewsdmManager loadProfileWithCache] -> @{}");
    return @{};
}

static IMP shadowhook_uibank_orig_viewdidunload = NULL;
static id shadowhook_uibank_viewdidunload_replacement(
    id self, SEL _cmd, id arg1, id arg2) {
    NSLog(@"[Shadow/UIBank] NOP -[UpdateMIssuesManager viewDidUnload:Loader2:] -> @{}");
    return @{};
}

static IMP shadowhook_uibank_orig_jsalert = NULL;
static void shadowhook_uibank_jsalert_replacement(
    id self, SEL _cmd, id webView, NSString* message, id frame, void (^completion)(void)) {
    NSLog(@"[Shadow/UIBank] skip JS alert: %@", message);
    if (completion) completion();
}

// FIRCLSSettingsManager NOP (smbc25): UI Bank's RASP impersonates Firebase
// Crashlytics by reusing the FIRCLSSettingsManager class name and overrides
// -beginSettingsWithGoogleAppId:token: to assert with an encrypted message
// when it detects a tweak. Live syslog 2026-04-29 20:37:53 caught:
//   *** Assertion failure in -[FIRCLSSettingsManager beginSettingsWithGoogleAppId:token:]
//   *** Terminating app due to uncaught exception 'NSInternalInconsistencyException'
// Replace the impl with a no-op that returns @{}, same pattern as the
// frida full_bypass35 NOP that worked on this method.
static IMP shadowhook_uibank_orig_fircls_begin = NULL;
static id shadowhook_uibank_fircls_begin_replacement(
    id self, SEL _cmd, id googleAppId, id token) {
    NSLog(@"[Shadow/UIBank] NOP -[FIRCLSSettingsManager beginSettingsWithGoogleAppId:token:]");
    smbc24_diag(@"FIRE: NOP FIRCLSSettingsManager.beginSettingsWithGoogleAppId:token:");
    return @{};
}

// smbc80 functions moved to before shadowhook_smbc_install_probe_hooks
// (their forward declarations need to be visible at that install site).

// smbc77: binary-patch the cbz at file_off 0x7b7b70 in UIBank_PRO main
// exe to an unconditional branch with the same target. This bypasses
// raise 6 (Firebase Installations APIKey format error) entirely without
// needing to find the implementing class. The fn at 0x7b7a14 is Swift,
// not ObjC, so selector-based hooking does not work on it.
//
// Original instruction at 0x7b7b70: 0xb4000380  (cbz x0, +0x70)
// Patched: 0x1400001c  (b +0x70)  -- always take the branch
//
// Approach: locate main exe's mach_header (the one matching the bundle
// path, since dyld doesn't guarantee index 0), compute slide, mprotect
// the containing page to RW, write the new word, flush the i-cache,
// mprotect back to RX. roothide allows this.
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
static void shadowhook_uibank_install_uibank_patch(void) {
    static int patched = 0;
    if (patched) return;
    // Find main exe header
    uint32_t img_count = _dyld_image_count();
    const struct mach_header* main_mh = NULL;
    intptr_t main_slide = 0;
    for (uint32_t i = 0; i < img_count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "UIBank_PRO")) {
            main_mh = _dyld_get_image_header(i);
            main_slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!main_mh) {
        smbc24_diag(@"smbc77: could not find UIBank_PRO image");
        return;
    }
    // VA of cbz to patch = 0x100000000 + slide + 0x7b7b70
    // But we already have mh which is the loaded header pointer = 0x100000000 + slide
    // So target = (uintptr_t)mh + 0x7b7b70
    uintptr_t target = (uintptr_t)main_mh + 0x7b7b70;
    uint32_t* word = (uint32_t*)target;
    uint32_t before = *word;
    if (before != 0xb4000380) {
        smbc24_diag([NSString stringWithFormat:
            @"smbc77: unexpected bytes at 0x%lx -> 0x%08x (expected 0xb4000380), abort",
            target, before]);
        return;
    }
    // smbc77 v2: iOS denies plain mprotect RW on __TEXT pages.
    // Use Mach vm_protect with VM_PROT_COPY (creates a private CoW
    // copy of the page that we can then write to). This is the same
    // technique used by HookKit / MSHookFunction internally.
    long page_sz = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = target & ~(page_sz - 1);
    vm_address_t addr = (vm_address_t)page_start;
    kern_return_t kr = vm_protect(mach_task_self(), addr, page_sz, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        smbc24_diag([NSString stringWithFormat:
            @"smbc77: vm_protect RW|COPY failed kr=%d", kr]);
        return;
    }
    *word = 0x1400001c;  // b +0x70
    sys_icache_invalidate((void*)target, 4);
    kr = vm_protect(mach_task_self(), addr, page_sz, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        smbc24_diag([NSString stringWithFormat:
            @"smbc77: vm_protect RX failed kr=%d (still patched)", kr]);
    }
    patched = 1;
    smbc24_diag([NSString stringWithFormat:
        @"INSTALL: smbc77 patched cbz @ 0x%lx (slide=0x%lx)",
        target, main_slide]);
}

// smbc75: hook -validateAPIKey: globally to NOP. The method at file_off
// 0x7b7a14 (Firebase's APIKey validator) checks length==39, first char
// =='A', and charset, raising NSException via name=fa/Yjnli... if any
// fails. We confirmed our cached FIROptions has APIKey = AIzaSy... but
// raise 6 still fires - so either the receiver gets a different value
// or one of the checks fires on something we are not aware of. Skip the
// whole method: caller (0x7b79e4) ignores the return value.
typedef id (*shadowhook_uibank_validateAPIKey_imp_t)(id, SEL, id);
static id shadowhook_uibank_validateAPIKey_replacement(id self, SEL _cmd, id apiKey) {
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: NOP -[%@ validateAPIKey:%@]",
        NSStringFromClass([self class]), apiKey ?: @"(nil)"]);
    return nil;
}

// smbc76: heartbeat-callable swizzle pass for -validateAPIKey:.
void shadowhook_uibank_retry_validateAPIKey_swizzle(void) {
    SEL sel = NSSelectorFromString(@"validateAPIKey:");
    int classCount = objc_getClassList(NULL, 0);
    Class* classes = (Class*)malloc(sizeof(Class) * classCount);
    classCount = objc_getClassList(classes, classCount);
    int hooked_now = 0;
    for (int i = 0; i < classCount; i++) {
        Class c = classes[i];
        unsigned int n = 0;
        Method* methods = class_copyMethodList(c, &n);
        for (unsigned int j = 0; j < n; j++) {
            if (method_getName(methods[j]) == sel) {
                IMP cur = method_getImplementation(methods[j]);
                if (cur != (IMP)shadowhook_uibank_validateAPIKey_replacement) {
                    method_setImplementation(methods[j],
                        (IMP)shadowhook_uibank_validateAPIKey_replacement);
                    hooked_now++;
                }
                break;
            }
        }
        free(methods);
    }
    free(classes);
    if (hooked_now) {
        smbc24_diag([NSString stringWithFormat:
            @"INSTALL: -validateAPIKey: NOP retry hooked=%d", hooked_now]);
    }
}

// smbc73: hook -[NSCharacterSet isSupersetOfSet:] to always return YES.
// Raise 6 in fn at 0x7b7bd4 fires when this returns NO during Firebase
// Installations' APIKey character-set validation (the message being
// "APIKey doesn't match the expected format"). The allowed charset
// loaded into x19 may have been narrowed by UI Bank's RASP wrapper
// such that valid Firebase keys with `_` or `-` get rejected. Lying YES
// makes every isSupersetOfSet: pass. Risk: other code paths that
// rely on accurate isSupersetOfSet: results will be broken — but
// during startup we don't have any other heavy charset users, and
// the alternative (binary-patching the cbz at 0x7b7b70 via mprotect)
// is much riskier.
typedef BOOL (*shadowhook_uibank_supersetof_imp_t)(id, SEL, id);
__attribute__((unused))
static shadowhook_uibank_supersetof_imp_t shadowhook_uibank_orig_supersetof = NULL;
static BOOL shadowhook_uibank_supersetof_replacement(id self, SEL _cmd, id otherSet) {
    return YES;
}

// smbc69: hook -[FIRApp configureCore] to return YES. The disasm of fn
// at file_off 0x7b0608 (raise 4) shows the function calls
// [obj configureCore] and raises if result is NO. With smbc68's valid
// FIROptions in hand, configureCore presumably still does its own
// validation/init that returns NO under our environment. Force YES so
// the raise path is skipped and Firebase considers itself configured.
typedef BOOL (*shadowhook_uibank_configureCore_imp_t)(id, SEL);
static BOOL shadowhook_uibank_configureCore_replacement(id self, SEL _cmd) {
    // Returning YES makes the calling Swift code believe the FIRApp
    // configured successfully; downstream logic that uses [FIRApp
    // defaultApp] will see a valid app.
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: NOP -[%@ configureCore] -> YES",
        NSStringFromClass([self class])]);
    return YES;
}

// smbc66/68: hook +[FIROptions defaultOptions]. smbc66 confirmed the
// hypothesis (returns nil). smbc67 added an NSBundle bundle-whitelist
// to fix the upstream pathForResource breakage but defaultOptions
// still came back nil — likely because Firebase calls it during early
// init (FIRApp +load / static ctor) BEFORE our shadow.dylib's hooks
// are in place, the dispatch_once block caches nil, and every
// subsequent call returns the cache regardless of what we fix.
//
// smbc68: bypass the cache entirely. Build a fresh FIROptions from
// the plist on every call. Use [FIROptions alloc] +
// initInternalWithOptionsDictionary: which is what the dispatch_once
// path itself uses.
typedef id (*shadowhook_uibank_fir_defopts_imp_t)(Class, SEL);
static shadowhook_uibank_fir_defopts_imp_t shadowhook_uibank_orig_fir_defopts = NULL;
static id shadowhook_uibank_fir_defopts_cached = nil;
static id shadowhook_uibank_fir_defopts_replacement(Class self, SEL _cmd) {
    if (shadowhook_uibank_fir_defopts_cached) {
        return shadowhook_uibank_fir_defopts_cached;
    }
    NSString* plistPath = [[NSBundle mainBundle]
        pathForResource:@"GoogleService-Info" ofType:@"plist"];
    NSDictionary* dict = plistPath
        ? [NSDictionary dictionaryWithContentsOfFile:plistPath]
        : nil;
    id rv = nil;
    // smbc71: smbc70 confirmed initInternalWithOptionsDictionary: only
    // populated APIKey, leaving googleAppID/projectID/GCMSenderID/bundleID
    // as nil. Use the public initializer -initWithContentsOfFile: which
    // takes the plist path directly and properly maps every plist key.
    if (plistPath) {
        SEL initFile = NSSelectorFromString(@"initWithContentsOfFile:");
        id alloc = [(Class)self alloc];
        if (alloc && [alloc respondsToSelector:initFile]) {
            rv = ((id (*)(id, SEL, NSString*))objc_msgSend)(
                alloc, initFile, plistPath);
        }
        // Fallback: if -initWithContentsOfFile: missing or returned nil,
        // try the dictionary variant.
        if (!rv && dict) {
            SEL initDict = NSSelectorFromString(@"initInternalWithOptionsDictionary:");
            id alloc2 = [(Class)self alloc];
            if (alloc2 && [alloc2 respondsToSelector:initDict]) {
                rv = ((id (*)(id, SEL, NSDictionary*))objc_msgSend)(
                    alloc2, initDict, dict);
            }
        }
    }
    // smbc72: neither initInternalWithOptionsDictionary: nor
    // initWithContentsOfFile: populated the non-APIKey properties under
    // this Firebase build. Force-assign each field via KVC after init.
    if (rv && dict) {
        @try {
            NSString* val;
            if ((val = dict[@"GOOGLE_APP_ID"])) [rv setValue:val forKey:@"googleAppID"];
            if ((val = dict[@"GCM_SENDER_ID"])) [rv setValue:val forKey:@"GCMSenderID"];
            if ((val = dict[@"PROJECT_ID"])) [rv setValue:val forKey:@"projectID"];
            if ((val = dict[@"BUNDLE_ID"])) [rv setValue:val forKey:@"bundleID"];
            if ((val = dict[@"STORAGE_BUCKET"])) [rv setValue:val forKey:@"storageBucket"];
            if ((val = dict[@"API_KEY"])) [rv setValue:val forKey:@"APIKey"];
            if ((val = dict[@"CLIENT_ID"])) [rv setValue:val forKey:@"clientID"];
            if ((val = dict[@"DATABASE_URL"])) [rv setValue:val forKey:@"databaseURL"];
            if ((val = dict[@"TRACKING_ID"])) [rv setValue:val forKey:@"trackingID"];
            if ((val = dict[@"DEEP_LINK_SCHEME"])) [rv setValue:val forKey:@"deepLinkURLScheme"];
        } @catch (NSException* e) {
            smbc24_diag([NSString stringWithFormat:
                @"FIRE: defaultOptions setValue threw: %@", e]);
        }
    }
    NSString* gid_val = nil, *pid_val = nil, *api_val = nil, *gcm_val = nil, *bid_val = nil;
    if (rv) {
        @try {
            gid_val = [rv valueForKey:@"googleAppID"];
            pid_val = [rv valueForKey:@"projectID"];
            api_val = [rv valueForKey:@"APIKey"];
            gcm_val = [rv valueForKey:@"GCMSenderID"];
            bid_val = [rv valueForKey:@"bundleID"];
        } @catch (NSException* e) {
            smbc24_diag([NSString stringWithFormat:
                @"FIRE: defaultOptions valueForKey threw: %@", e]);
        }
    }
    smbc24_diag([NSString stringWithFormat:
        @"FIRE: defaultOptions REBUILD plist=%@ dict_keys=%lu rv=%p props={gid=%@ pid=%@ api=%@ gcm=%@ bid=%@}",
        plistPath ?: @"(nil)",
        (unsigned long)[dict count],
        rv,
        gid_val ?: @"(nil)", pid_val ?: @"(nil)",
        api_val ?: @"(nil)", gcm_val ?: @"(nil)", bid_val ?: @"(nil)"]);
    if (rv) {
        shadowhook_uibank_fir_defopts_cached = rv;
    }
    return rv;
}

// smbc28 attempt to also NOP FIRCLSReportManager startWithProfiling and
// beginSettingsWithToken: was reverted in smbc29. Empirically that made
// the crash happen earlier (immediate, not after 1s splash). Those methods
// are not pure RASP entry points — the real Firebase init relies on their
// side effects (queue setup, etc.) and our blanket @{} return left
// downstream callers with broken state. The leaf-level FIRCLSSettingsManager
// NOP is the right level to intercept; keep just that.

// FraudAlertSDK JailBreak_fa NOP (smbc31): FraudAlertSDK.framework binary
// (Caulis Inc. fraud SDK, jp.caulis.fraud.sdk) contains a class named
// JailBreak_fa with three void methods:
//   -[JailBreak_fa start]      // entry point that performs the JB check
//   -[JailBreak_fa getData]    // collects detection result for the manager
//   -[JailBreak_fa setDefault] // sets the no-JB baseline before start runs
// Strings in the same binary include "JailBreak result : %d",
// "/Applications/Cydia.app", "cydia://" — confirming this is the SDK's
// JB-detection function plugged into FunctionsManager_fa.execFunctions::.
// NOPing -[JailBreak_fa start] prevents the detection from ever running,
// leaving whatever setDefault initialised in place.
static IMP shadowhook_uibank_orig_jb_fa_start = NULL;
static void shadowhook_uibank_jb_fa_start_replacement(id self, SEL _cmd) {
    NSLog(@"[Shadow/UIBank] NOP -[JailBreak_fa start]");
    smbc24_diag(@"FIRE: NOP -[JailBreak_fa start]");
}

// WMatrixMobile RASP NOPs (smbc30): WMatrixMobile.framework binary analysis
// shows three short obfuscated ObjC selectors that look like JB detection:
//   checkSP5         (likely "Security Policy 5" check)
//   checkEngine:     (RASP engine state check)
//   checkRefreshUpdate: (paired with RefreshUpdateCheck class)
// The cstring section also has integrityPathArr — an array of paths the
// RASP scans for JB indicators. Without knowing the exact host class for
// each selector, walk objc_copyClassList() at install time and NOP any
// class that responds to one of these selectors.

static id shadowhook_uibank_wmatrix_nop_object(id self, SEL _cmd, ...) {
    NSString* name = NSStringFromClass([self class]);
    NSString* sel = NSStringFromSelector(_cmd);
    NSLog(@"[Shadow/UIBank] NOP -[%@ %@]", name, sel);
    smbc24_diag([NSString stringWithFormat:@"FIRE: NOP -[%@ %@]", name, sel]);
    return nil;
}

static BOOL shadowhook_uibank_wmatrix_nop_bool(id self, SEL _cmd, ...) {
    NSString* name = NSStringFromClass([self class]);
    NSString* sel = NSStringFromSelector(_cmd);
    NSLog(@"[Shadow/UIBank] NOP -[%@ %@] -> NO", name, sel);
    smbc24_diag([NSString stringWithFormat:@"FIRE: NOP -[%@ %@] -> NO", name, sel]);
    return NO;
}

static BOOL shadowhook_uibank_wmatrix_installed = NO;
static void shadowhook_uibank_install_wmatrix_nops(void) {
    if (shadowhook_uibank_wmatrix_installed) return;
    NSArray<NSString*>* targets = @[ @"checkSP5", @"checkEngine:", @"checkRefreshUpdate:" ];
    unsigned int outCount = 0;
    Class* classes = objc_copyClassList(&outCount);
    if (!classes) return;
    int hits = 0;
    for (unsigned int i = 0; i < outCount; i++) {
        Class cls = classes[i];
        // Skip system frameworks; WMatrixMobile classes start with "W" or are Swift-mangled
        const char* name = class_getName(cls);
        if (!name) continue;
        // Heuristic: only consider classes whose name suggests WMatrix or are 1-2 char weird names
        if (strncmp(name, "WMatrix", 7) != 0 &&
            strncmp(name, "RefreshUpdate", 13) != 0 &&
            strncmp(name, "Refresh", 7) != 0 &&
            strstr(name, "WMatrix") == NULL) continue;
        for (NSString* selName in targets) {
            SEL sel = NSSelectorFromString(selName);
            Method m = class_getInstanceMethod(cls, sel);
            if (!m) continue;
            const char* types = method_getTypeEncoding(m);
            // Pick replacement IMP based on declared return type (first char of types).
            IMP repl;
            if (types && types[0] == 'B') {
                repl = (IMP)shadowhook_uibank_wmatrix_nop_bool;
            } else {
                repl = (IMP)shadowhook_uibank_wmatrix_nop_object;
            }
            method_setImplementation(m, repl);
            NSLog(@"[Shadow/UIBank] hooked -[%s %@]", name, selName);
            smbc24_diag([NSString stringWithFormat:@"INSTALL: -[%s %@]", name, selName]);
            hits++;
        }
    }
    free(classes);
    smbc24_diag([NSString stringWithFormat:@"WMatrix NOPs hits=%d", hits]);
    if (hits > 0) shadowhook_uibank_wmatrix_installed = YES;
}

static BOOL shadowhook_uibank_install_once(void) {
    BOOL all_done = YES;

    if (!shadowhook_uibank_orig_loadprofile) {
        Class cls = NSClassFromString(@"StockNewsdmManager");
        if (cls) {
            Method m = class_getClassMethod(cls, NSSelectorFromString(@"loadProfileWithCache"));
            if (m) {
                shadowhook_uibank_orig_loadprofile = method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_uibank_loadprofile_replacement);
                NSLog(@"[Shadow/UIBank] hooked +[StockNewsdmManager loadProfileWithCache]");
            } else {
                all_done = NO;
            }
        } else {
            all_done = NO;
        }
    }

    if (!shadowhook_uibank_orig_viewdidunload) {
        Class cls = NSClassFromString(@"UpdateMIssuesManager");
        if (cls) {
            Method m = class_getInstanceMethod(cls, NSSelectorFromString(@"viewDidUnload:Loader2:"));
            if (m) {
                shadowhook_uibank_orig_viewdidunload = method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_uibank_viewdidunload_replacement);
                NSLog(@"[Shadow/UIBank] hooked -[UpdateMIssuesManager viewDidUnload:Loader2:]");
            } else {
                all_done = NO;
            }
        } else {
            all_done = NO;
        }
    }

    if (!shadowhook_uibank_orig_jsalert) {
        Class cls = NSClassFromString(@"WMatrixWebView");
        if (cls) {
            SEL sel = NSSelectorFromString(
                @"webView:runJavaScriptAlertPanelWithMessage:initiatedByFrame:completionHandler:");
            Method m = class_getInstanceMethod(cls, sel);
            if (m) {
                shadowhook_uibank_orig_jsalert = method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_uibank_jsalert_replacement);
                NSLog(@"[Shadow/UIBank] hooked WMatrixWebView JS alert");
            } else {
                all_done = NO;
            }
        } else {
            all_done = NO;
        }
    }

    // smbc64: FIRCLSSettingsManager NOP DISABLED. The smbc63 trace caught
    // the format string of the last (6th) raise: "Could not configure
    // Firebase Installations due to invalid FirebaseApp options.
    // FirebaseOptions.APIKey doesn't match the expected format". That's
    // genuine Firebase, complaining because OUR @{} return left it without
    // a usable settings dict. The 5 obfuscated raises before it are
    // downstream Optional unwraps that depend on Firebase being initialised.
    // Letting Firebase run unmolested should resolve all 6 raises.
    // The original smbc25 motivation (NSInternalInconsistencyException
    // from this method) was almost certainly a downstream cascade from
    // some OTHER bypass we had at the time, not a JB-detection trap on
    // the method itself.
    // smbc65: revert smbc64 — re-enable NOP. Without it, Firebase tries
    // real init (network/main-thread-blocking work), iOS watchdog kills
    // the process. The 6 raise:format: events fire identically regardless
    // of NOP state, confirming they are NOT caused by our @{} return —
    // those raises happen independently. The NOP is the right move for
    // stability; the 6 raises themselves must be addressed elsewhere.
    if (!shadowhook_uibank_orig_fircls_begin) {
        Class cls = NSClassFromString(@"FIRCLSSettingsManager");
        if (cls) {
            Method m = class_getInstanceMethod(
                cls, NSSelectorFromString(@"beginSettingsWithGoogleAppId:token:"));
            if (m) {
                shadowhook_uibank_orig_fircls_begin = method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_uibank_fircls_begin_replacement);
                NSLog(@"[Shadow/UIBank] hooked -[FIRCLSSettingsManager beginSettingsWithGoogleAppId:token:]");
                smbc24_diag(@"INSTALL: -[FIRCLSSettingsManager beginSettingsWithGoogleAppId:token:]");
            } else {
                all_done = NO;
            }
        } else {
            all_done = NO;
        }
    }

    // smbc84: smbc83 confirmed Core.m fix alone does NOT make Firebase
    // init naturally — all 6 raises came back. Re-enable workarounds.
    shadowhook_uibank_install_uibank_patch();

    // smbc76: walk all loaded classes, hook every -validateAPIKey:
    // instance method to NOP. smbc75 hooked=0 because the implementing
    // class isn't loaded yet at our CTOR_REACHED phase. Make the swizzle
    // retry-able from the heartbeat tick (or any later install pass)
    // until it actually finds the method. Idempotent: once we hook a
    // class, we skip it on subsequent passes.
    {
        SEL sel = NSSelectorFromString(@"validateAPIKey:");
        int classCount = objc_getClassList(NULL, 0);
        Class* classes = (Class*)malloc(sizeof(Class) * classCount);
        classCount = objc_getClassList(classes, classCount);
        int hooked_now = 0;
        for (int i = 0; i < classCount; i++) {
            Class c = classes[i];
            unsigned int n = 0;
            Method* methods = class_copyMethodList(c, &n);
            for (unsigned int j = 0; j < n; j++) {
                if (method_getName(methods[j]) == sel) {
                    IMP cur = method_getImplementation(methods[j]);
                    if (cur != (IMP)shadowhook_uibank_validateAPIKey_replacement) {
                        method_setImplementation(methods[j],
                            (IMP)shadowhook_uibank_validateAPIKey_replacement);
                        hooked_now++;
                    }
                    break;
                }
            }
            free(methods);
        }
        free(classes);
        static int validateAPIKey_total_hooked = 0;
        if (hooked_now) {
            validateAPIKey_total_hooked += hooked_now;
            smbc24_diag([NSString stringWithFormat:
                @"INSTALL: -validateAPIKey: NOP (now=%d total=%d)",
                hooked_now, validateAPIKey_total_hooked]);
        }
    }

    // smbc74: smbc73 hooked NSCharacterSet but the concrete subclass
    // (e.g., NSCFCharacterSet / __NSCFCharacterSet / NSMutableCharacterSet)
    // overrides isSupersetOfSet: so our parent-class swizzle didn't take
    // effect at the actual call site. Walk every loaded class, find any
    // that descends from NSCharacterSet AND defines its own
    // isSupersetOfSet:, and swizzle each.
    static int superset_done = 0;
    if (!superset_done) {
        Class baseCls = NSClassFromString(@"NSCharacterSet");
        SEL sel = NSSelectorFromString(@"isSupersetOfSet:");
        if (baseCls) {
            int classCount = objc_getClassList(NULL, 0);
            Class* classes = (Class*)malloc(sizeof(Class) * classCount);
            classCount = objc_getClassList(classes, classCount);
            int hooked = 0;
            for (int i = 0; i < classCount; i++) {
                Class c = classes[i];
                Class parent = c;
                BOOL isCharSet = NO;
                while (parent) {
                    if (parent == baseCls) { isCharSet = YES; break; }
                    parent = class_getSuperclass(parent);
                }
                if (!isCharSet) continue;
                unsigned int n = 0;
                Method* methods = class_copyMethodList(c, &n);
                for (unsigned int j = 0; j < n; j++) {
                    if (method_getName(methods[j]) == sel) {
                        method_setImplementation(methods[j],
                            (IMP)shadowhook_uibank_supersetof_replacement);
                        hooked++;
                        break;
                    }
                }
                free(methods);
            }
            free(classes);
            // Also patch the abstract base class entry as a backstop.
            Method m = class_getInstanceMethod(baseCls, sel);
            if (m) {
                method_setImplementation(m,
                    (IMP)shadowhook_uibank_supersetof_replacement);
                hooked++;
            }
            smbc24_diag([NSString stringWithFormat:
                @"INSTALL: NSCharacterSet+subclasses isSupersetOfSet: -> YES (hooked=%d)", hooked]);
            superset_done = 1;
        }
    }

    // smbc84: re-enable smbc69 configureCore force-YES.
    static int fircls_configureCore_done = 0;
    if (!fircls_configureCore_done) {
        Class fircls = NSClassFromString(@"FIRApp");
        if (fircls) {
            SEL sel = NSSelectorFromString(@"configureCore");
            Method m = class_getInstanceMethod(fircls, sel);
            if (m) {
                method_setImplementation(m, (IMP)shadowhook_uibank_configureCore_replacement);
                smbc24_diag(@"INSTALL: -[FIRApp configureCore] -> YES");
                fircls_configureCore_done = 1;
            }
        }
    }

    // smbc84: re-enable smbc66/68 defaultOptions REBUILD hook.
    if (!shadowhook_uibank_orig_fir_defopts) {
        Class cls = NSClassFromString(@"FIROptions");
        if (cls) {
            Method m = class_getClassMethod(
                cls, NSSelectorFromString(@"defaultOptions"));
            if (m) {
                shadowhook_uibank_orig_fir_defopts =
                    (shadowhook_uibank_fir_defopts_imp_t)method_getImplementation(m);
                method_setImplementation(m,
                    (IMP)shadowhook_uibank_fir_defopts_replacement);
                smbc24_diag(@"INSTALL: +[FIROptions defaultOptions]");
            }
        }
    }

    if (!shadowhook_uibank_orig_jb_fa_start) {
        Class cls = NSClassFromString(@"JailBreak_fa");
        if (cls) {
            Method m = class_getInstanceMethod(cls, NSSelectorFromString(@"start"));
            if (m) {
                shadowhook_uibank_orig_jb_fa_start = method_getImplementation(m);
                method_setImplementation(m, (IMP)shadowhook_uibank_jb_fa_start_replacement);
                NSLog(@"[Shadow/UIBank] hooked -[JailBreak_fa start]");
                smbc24_diag(@"INSTALL: -[JailBreak_fa start]");
            } else {
                all_done = NO;
            }
        } else {
            all_done = NO;
        }
    }

    // Walk every loaded class once we have at least the WMatrix runtime up,
    // and NOP any class that exposes the suspicious WMatrixMobile RASP
    // selectors. Idempotent — only runs once after first hit.
    shadowhook_uibank_install_wmatrix_nops();

    return all_done;
}

// (e) Defensive nil-handlers for UI Bank's RASP zombie-code chain
//
// After alert/exit hooks deflect the JB-detection self-kill, RASP code
// continues running with stale state, hits NSCharacterSet/NSDictionary
// creators with nil args, and segfaults inside CoreFoundation. Wrap them.

typedef id (*shadowhook_uibank_charset_imp_t)(Class self, SEL _cmd, NSString* str);
static shadowhook_uibank_charset_imp_t shadowhook_uibank_orig_charset = NULL;
static id shadowhook_uibank_charset_replacement(
    Class self, SEL _cmd, NSString* str) {
    if (str == nil) {
        NSLog(@"[Shadow/UIBank] charsetWithChars: nil -> empty");
        return [[NSCharacterSet alloc] init];
    }
    return shadowhook_uibank_orig_charset(self, _cmd, str);
}

typedef NSDictionary* (*shadowhook_uibank_dict_imp_t)(
    Class self, SEL _cmd, const id _Nonnull * objects, const id _Nonnull * keys, NSUInteger cnt);
static shadowhook_uibank_dict_imp_t shadowhook_uibank_orig_dict = NULL;
static NSDictionary* shadowhook_uibank_dict_replacement(
    Class self, SEL _cmd, const id _Nonnull * objects, const id _Nonnull * keys, NSUInteger cnt) {
    BOOL hasNil = NO;
    if (cnt > 0) {
        if (objects == NULL || keys == NULL) hasNil = YES;
        else for (NSUInteger i = 0; i < cnt && !hasNil; i++)
            if (objects[i] == nil || keys[i] == nil) hasNil = YES;
    }
    if (hasNil) {
        NSLog(@"[Shadow/UIBank] dictWithObjs nil-entries cnt=%lu -> empty",
              (unsigned long)cnt);
        return @{};
    }
    return shadowhook_uibank_orig_dict(self, _cmd, objects, keys, cnt);
}

static void shadowhook_uibank_install_safe_creators(void) {
    {
        Class cls = [NSCharacterSet class];
        SEL sel = @selector(characterSetWithCharactersInString:);
        Method m = class_getClassMethod(cls, sel);
        if (m && !shadowhook_uibank_orig_charset) {
            shadowhook_uibank_orig_charset =
                (shadowhook_uibank_charset_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_uibank_charset_replacement);
            NSLog(@"[Shadow/UIBank] hooked +[NSCharacterSet characterSetWithCharactersInString:]");
        }
    }
    {
        Class cls = [NSDictionary class];
        SEL sel = @selector(dictionaryWithObjects:forKeys:count:);
        Method m = class_getClassMethod(cls, sel);
        if (m && !shadowhook_uibank_orig_dict) {
            shadowhook_uibank_orig_dict =
                (shadowhook_uibank_dict_imp_t)method_getImplementation(m);
            method_setImplementation(m, (IMP)shadowhook_uibank_dict_replacement);
            NSLog(@"[Shadow/UIBank] hooked +[NSDictionary dictionaryWithObjects:forKeys:count:]");
        }
    }
}

void shadowhook_uibank(void) {
    // Defensive nil-handlers FIRST (always installable, no class lookup needed)
    shadowhook_uibank_install_safe_creators();

    // Best-effort: try once now, then poll for up to 5 seconds in case the
    // target classes register slightly later. The +load self-kill happens
    // very early (during dyld init), so the first attempt usually catches it.
    if (shadowhook_uibank_install_once()) return;

    __block int attempts = 0;
    dispatch_queue_t q = dispatch_get_main_queue();
    void (^retry)(void) = ^{
        attempts++;
        if (shadowhook_uibank_install_once() || attempts > 50) return;
        // schedule another retry in 100ms
    };
    dispatch_async(q, retry);
    // Background-thread loop as a parallel fallback
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        for (int i = 0; i < 200; i++) {
            if (shadowhook_uibank_install_once()) break;
            usleep(20 * 1000); // 20ms
        }
    });
}
