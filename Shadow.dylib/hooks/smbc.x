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

// ---------- diagnostics (smbc24) ----------
//
// NSLog from this dylib does not appear in idevicesyslog (presumably routed
// through a private os_log channel that requires Apple's logging profile).
// Append events to a file in the host app's NSDocumentDirectory so we can
// read it back via NewTerm:
//   sudo find /var/mobile/Containers/Data/Application -name "shadow_smbc24.log"
//   cat <found path>

void smbc24_diag(NSString* event) {
    @try {
        static NSString* path = nil;
        static dispatch_once_t once = 0;
        dispatch_once(&once, ^{
            NSArray* dirs = NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES);
            if (dirs.count == 0) return;
            path = [[dirs firstObject] stringByAppendingPathComponent:@"shadow_smbc24.log"];
            [[NSString stringWithFormat:@"=== smbc24 session %@ ===\n", [NSDate date]]
                writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:nil];
        });
        if (!path) return;
        NSString* line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], event];
        NSFileHandle* fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
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

// ---------- (a) UIAlertController.alertControllerWithTitle:message:preferredStyle: ----------

typedef UIAlertController* (*shadowhook_smbc_alert_imp_t)(
    Class self, SEL _cmd, NSString* title, NSString* message, UIAlertControllerStyle style);
static shadowhook_smbc_alert_imp_t shadowhook_smbc_orig_alert = NULL;

static UIAlertController* shadowhook_smbc_alert_replacement(
    Class self, SEL _cmd, NSString* title, NSString* message, UIAlertControllerStyle style) {
    smbc24_diag([NSString stringWithFormat:@"FIRE: +alertControllerWithTitle: title=%@ message=%@",
                 title ?: @"(nil)", message ?: @"(nil)"]);
    if (shadowhook_smbc_text_is_blocklisted(title) ||
        shadowhook_smbc_text_is_blocklisted(message)) {
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
    BOOL hit = (shadowhook_smbc_text_is_blocklisted(title) ||
                shadowhook_smbc_text_is_blocklisted(message));
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

static void (*shadowhook_smbc_orig_exit)(int) = NULL;
static void shadowhook_smbc_block_exit(int status) {
    NSLog(@"[Shadow/SMBC] blocked exit(%d)", status);
}

static void (*shadowhook_smbc_orig__exit)(int) = NULL;
static void shadowhook_smbc_block__exit(int status) {
    NSLog(@"[Shadow/SMBC] blocked _exit(%d)", status);
}

static void (*shadowhook_smbc_orig_abort)(void) = NULL;
static void shadowhook_smbc_block_abort(void) {
    NSLog(@"[Shadow/SMBC] blocked abort");
}

static int (*shadowhook_smbc_orig_raise)(int) = NULL;
static int shadowhook_smbc_block_raise(int sig) {
    NSLog(@"[Shadow/SMBC] blocked raise(%d)", sig);
    return 0;
}

static int (*shadowhook_smbc_orig_kill)(pid_t, int) = NULL;
static int shadowhook_smbc_block_kill(pid_t pid, int sig) {
    if (sig == 0) {
        // probe call (existence check) — let it through
        return shadowhook_smbc_orig_kill(pid, sig);
    }
    NSLog(@"[Shadow/SMBC] blocked kill(%d,%d)", pid, sig);
    return 0;
}

static int (*shadowhook_smbc_orig_pthread_kill)(pthread_t, int) = NULL;
static int shadowhook_smbc_block_pthread_kill(pthread_t t, int sig) {
    NSLog(@"[Shadow/SMBC] blocked pthread_kill(%d)", sig);
    return 0;
}

// __cxa_throw lives in libc++abi which shadow.dylib does not link against.
// Resolve at runtime via dlsym so we don't drag a hard link dependency.
static void (*shadowhook_smbc_orig_cxa_throw)(void*, void*, void (*)(void*)) = NULL;
static void shadowhook_smbc_block_cxa_throw(void* a, void* b, void (*c)(void*)) {
    NSLog(@"[Shadow/SMBC] blocked __cxa_throw");
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
#include <signal.h>
#include <ucontext.h>
#include <string.h>
static void shadowhook_smbc_sigtrap_handler(int sig, siginfo_t* info, void* context) {
    void* faddr = info ? info->si_addr : NULL;
    NSLog(@"[Shadow/SMBC] caught sig=%d at %p — advancing PC", sig, faddr);
    smbc24_diag([NSString stringWithFormat:@"FIRE: caught sig=%d at %p", sig, faddr]);
#if defined(__arm64__) || defined(__aarch64__)
    if (context) {
        ucontext_t* uc = (ucontext_t*)context;
        if (uc->uc_mcontext) {
            uc->uc_mcontext->__ss.__pc += 4;
        }
    }
#endif
}

// +[NSException raise:format:] — variadic, matched by ObjC selector
typedef void (*shadowhook_smbc_nsexc_raise_imp_t)(
    Class self, SEL _cmd, NSString* name, NSString* format, ...);
static shadowhook_smbc_nsexc_raise_imp_t shadowhook_smbc_orig_nsexception_raise = NULL;

static void shadowhook_smbc_nsexception_raise_replacement(
    Class self, SEL _cmd, NSString* name, NSString* format, ...) {
    NSLog(@"[Shadow/SMBC] swallowed NSException raise: name=%@ format=%@", name, format);
    // Don't call original — exception is silenced. Caller's __noreturn assumption
    // is violated but we return cleanly; if calling code does anything sane after
    // a raise: (which it shouldn't, but compilers vary) it just continues.
}

void shadowhook_smbc_terminators(HKSubstitutor* hooks) {
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

    // SIGTRAP/SIGILL/SIGBUS handler (smbc36) — catch direct BRK traps that
    // bypass swift_runtime_on_report/Fatal symbol hooks.
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
