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
    if (vc == nil) {
        NSLog(@"[Shadow/SMBC] skip present (nil vc)");
        if (completion) completion();
        return;
    }
    shadowhook_smbc_orig_present(self, _cmd, vc, animated, completion);
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

static IMP shadowhook_uibank_orig_loadprofile = NULL;
static void shadowhook_uibank_loadprofile_replacement(id self, SEL _cmd) {
    NSLog(@"[Shadow/UIBank] NOP +[StockNewsdmManager loadProfileWithCache]");
}

static IMP shadowhook_uibank_orig_viewdidunload = NULL;
static void shadowhook_uibank_viewdidunload_replacement(
    id self, SEL _cmd, id arg1, id arg2) {
    NSLog(@"[Shadow/UIBank] NOP -[UpdateMIssuesManager viewDidUnload:Loader2:]");
}

static IMP shadowhook_uibank_orig_jsalert = NULL;
static void shadowhook_uibank_jsalert_replacement(
    id self, SEL _cmd, id webView, NSString* message, id frame, void (^completion)(void)) {
    NSLog(@"[Shadow/UIBank] skip JS alert: %@", message);
    if (completion) completion();
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

    return all_done;
}

void shadowhook_uibank(void) {
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
