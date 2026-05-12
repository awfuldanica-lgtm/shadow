// aidblock 1.3.0: minimum-viable hook to eliminate Apple ID popup.
//
// History of failures:
//  1.0.0: %hook UIViewController viewWillAppear: with recursive dismiss
//         -> SpringBoard safe-mode (broad hook on every system VC)
//  1.1.0: same broad VC hook + returning nil from factory
//         -> SpringBoard safe-mode (callers deref nil)
//  1.2.0: factory returns valid object with empty title/message
//         -> alert appears blank but still appears (user rejected:
//            wants alert GONE, not empty)
//
// 1.3.0 strategy: hook exactly ONE method on exactly ONE class (UIAlertController
// -viewDidAppear:). When the alert is fully on-screen we check title/message; if
// it smells like Apple ID prompt, dispatch_async a dismiss on next runloop tick.
// User sees the alert for 1-2 frames at most then it disappears. No nil
// returns, no broad VC hook, no factory perturbation.

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
            @"输入密码", @"輸入密碼", @"Verify"
        ];
    });
    for (NSString* n in needles) {
        if ([s rangeOfString:n options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

// Save original IMP.
typedef void (*aidb_vda_imp_t)(id, SEL, BOOL);
static aidb_vda_imp_t aidb_orig_vda = NULL;

static void aidb_uialert_vda_replacement(id self, SEL _cmd, BOOL animated) {
    // Always call original first so the alert is in a consistent state.
    if (aidb_orig_vda) aidb_orig_vda(self, _cmd, animated);
    // Now check this specific instance.
    UIAlertController* alert = (UIAlertController*)self;
    NSString* title = nil;
    NSString* message = nil;
    @try {
        title = alert.title;
        message = alert.message;
    } @catch (NSException* e) {
        return;
    }
    if (aidblock_text_looks_apple_id(title)
        || aidblock_text_looks_apple_id(message)) {
        NSLog(@"[aidblock] auto-dismiss alert title=%@ message=%@",
              title, message);
        // Dispatch on next runloop so we don't interrupt UIKit's
        // present transaction.
        __weak UIAlertController* weakAlert = alert;
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController* a = weakAlert;
            if (!a) return;
            @try {
                [a dismissViewControllerAnimated:NO completion:nil];
            } @catch (NSException* e) {
                NSLog(@"[aidblock] dismiss threw: %@", e);
            }
        });
    }
}

%ctor {
    @autoreleasepool {
        Class cls = NSClassFromString(@"UIAlertController");
        if (cls) {
            SEL sel = @selector(viewDidAppear:);
            Method m = class_getInstanceMethod(cls, sel);
            if (m) {
                aidb_orig_vda = (aidb_vda_imp_t)method_getImplementation(m);
                method_setImplementation(m, (IMP)aidb_uialert_vda_replacement);
                NSLog(@"[aidblock] 1.3.0 hooked -[UIAlertController viewDidAppear:]");
            } else {
                NSLog(@"[aidblock] 1.3.0 FAIL: no viewDidAppear: method on UIAlertController");
            }
        } else {
            NSLog(@"[aidblock] 1.3.0 FAIL: UIAlertController class not found");
        }
        NSLog(@"[aidblock] 1.3.0 loaded into pid=%d", getpid());
    }
}
