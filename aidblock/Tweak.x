// aidblock 1.2.0: ultra-conservative version after 1.0.0 + 1.1.0 both
// caused SpringBoard safe-mode.
//
// Root cause of safe-mode: returning nil from
//   +[UIAlertController alertControllerWithTitle:message:preferredStyle:]
// or from -[UIViewController presentViewController:...] breaks callers
// that immediately dereference the return value. SpringBoard's BannerAuthAlert
// code does this and crashes.
//
// 1.2.0 strategy: NEVER return nil. Instead:
//   - Let alertController factory create a normal alert object.
//   - On the SAME instance, immediately set title=@"" message=@"" so the
//     resulting alert is empty.
//   - On presentation, if it's an Apple-ID-prompt-looking alert, present
//     to a hidden window or immediately dismiss after present.
//
// Also remove all %hook UIViewController to avoid pervasive perturbation
// of SpringBoard's view controllers.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static BOOL aidblock_text_looks_apple_id(NSString* s) {
    if (!s || ![s isKindOfClass:[NSString class]] || [s length] == 0) return NO;
    static NSArray<NSString*>* needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[
            @"Apple ID", @"验证 Apple", @"驗證 Apple",
            @"Apple Account", @"Apple ID 密码", @"Apple ID 密碼",
            @"@gmail.com", @"@icloud.com", @"@me.com",
            @"vtghuk13", @"iCloud", @"sign in to Apple",
            @"输入密码", @"輸入密碼"
        ];
    });
    for (NSString* n in needles) {
        if ([s rangeOfString:n options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static BOOL aidblock_alert_should_block(NSString* title, NSString* message) {
    return aidblock_text_looks_apple_id(title)
        || aidblock_text_looks_apple_id(message);
}

// Swizzle helper: replace [cls -sel] IMP with newImp, store old in *outOld.
static void aidblock_swizzle(Class cls, SEL sel, IMP newImp, IMP* outOld) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (outOld) *outOld = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

// (1) Hook +[UIAlertController alertControllerWithTitle:message:preferredStyle:]
// SAFELY: forward to original, but if title/message smell like Apple ID, clear
// them to @"" so user sees blank alert. Never return nil.
typedef id (*aidb_factory_imp_t)(Class, SEL, NSString*, NSString*, NSInteger);
static aidb_factory_imp_t aidb_orig_factory = NULL;
static id aidb_replaced_factory(Class self, SEL _cmd, NSString* title,
                                NSString* message, NSInteger style) {
    BOOL block = aidblock_alert_should_block(title, message);
    if (block) {
        NSLog(@"[aidblock] neutered alertController title=%@ message=%@", title, message);
        // Pass empty strings instead of nil to keep object well-formed.
        return aidb_orig_factory(self, _cmd, @"", @"", style);
    }
    return aidb_orig_factory(self, _cmd, title, message, style);
}

// (2) Best-effort: hook private SBSAlertItem-style classes via runtime
// swizzle on selectors that present. NULL-guarded throughout.
typedef void (*aidb_void_imp_t)(id, SEL, ...);
static aidb_void_imp_t aidb_orig_sbsalert_willpresent = NULL;
static void aidb_sbsalert_willpresent_replacement(id self, SEL _cmd, id alert) {
    if (alert && [alert isKindOfClass:[UIAlertController class]]) {
        UIAlertController* a = (UIAlertController*)alert;
        if (aidblock_alert_should_block(a.title, a.message)) {
            NSLog(@"[aidblock] swallowed SBSAlertItem willPresent");
            return;
        }
    }
    if (aidb_orig_sbsalert_willpresent) {
        aidb_orig_sbsalert_willpresent(self, _cmd, alert);
    }
}

%ctor {
    @autoreleasepool {
        // Hook UIAlertController factory class method.
        // For class methods we need the metaclass's instance method.
        Class uic = NSClassFromString(@"UIAlertController");
        if (uic) {
            Class metac = object_getClass(uic);
            SEL sel = NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:");
            Method m = class_getInstanceMethod(metac, sel);
            if (m) {
                aidb_orig_factory = (aidb_factory_imp_t)method_getImplementation(m);
                method_setImplementation(m, (IMP)aidb_replaced_factory);
                NSLog(@"[aidblock] hooked +alertControllerWithTitle:message:preferredStyle:");
            }
        }

        // Hook SBSAlertItem private class if present.
        Class sbsa = NSClassFromString(@"SBSAlertItem");
        if (sbsa) {
            SEL sel = NSSelectorFromString(@"willPresentAlertController:");
            aidblock_swizzle(sbsa, sel, (IMP)aidb_sbsalert_willpresent_replacement,
                             (IMP*)&aidb_orig_sbsalert_willpresent);
            NSLog(@"[aidblock] hooked SBSAlertItem willPresentAlertController:");
        }

        NSLog(@"[aidblock] 1.2.0 loaded into pid=%d", getpid());
    }
}
