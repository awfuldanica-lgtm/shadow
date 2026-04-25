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
            @"セキュリティ", @"脱獄", @"改竄", @"改ざん",
            @"jailbreak", @"Jailbreak",
            @"システムエラー",
            @"本アプリを終了",
            @"終了させていただ",
            @"本アプリはご利用",
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

extern void __cxa_throw(void* thrown_exception, void* tinfo, void (*dest)(void*));
static void (*shadowhook_smbc_orig_cxa_throw)(void*, void*, void (*)(void*)) = NULL;
static void shadowhook_smbc_block_cxa_throw(void* a, void* b, void (*c)(void*)) {
    NSLog(@"[Shadow/SMBC] blocked __cxa_throw");
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
    MSHookFunction((void*)__cxa_throw,  (void*)shadowhook_smbc_block_cxa_throw,
                   (void**)&shadowhook_smbc_orig_cxa_throw);
    NSLog(@"[Shadow/SMBC] terminator chain blocked");
}
