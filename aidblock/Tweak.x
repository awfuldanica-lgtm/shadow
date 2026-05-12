// aidblock 1.1.0: suppress recurring iOS Apple ID re-auth prompts in
// SpringBoard. 1.0.0 caused SpringBoard safe-mode crash because the
// broad -[UIViewController viewWillAppear:] hook + recursive dismiss
// was unsafe across every system VC. Removed that hook entirely.
//
// Layered defense, narrow to safe surfaces:
//  1. +[UIAlertController alertControllerWithTitle:message:preferredStyle:]
//     - kill the standard factory call when title/message smells like
//       an Apple ID prompt.
//  2. -[UIViewController presentViewController:animated:completion:]
//     - intercept presentation of any UIAlertController whose title/message
//       smells like Apple ID prompt (catches the alloc/init code path
//       that doesn't go through alertControllerWithTitle:).
//  3. SBSAlertItem / SBPasscodeAlertItem class hooks (best-effort) -
//     for SpringBoard-private alert classes if they exist on this iOS.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

static BOOL aidblock_text_is_apple_id_prompt(NSString* s) {
    if (!s || ![s isKindOfClass:[NSString class]]) return NO;
    if ([s length] == 0) return NO;
    static NSArray<NSString*>* needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[
            @"Apple ID",
            @"验证 Apple",
            @"驗證 Apple",
            @"Apple ID 密码",
            @"Apple ID 密碼",
            @"Apple ID password",
            @"Apple Account",
            @"@gmail.com",
            @"@icloud.com",
            @"@me.com",
            @"@yahoo",
            @"@outlook.com",
            @"@hotmail",
            @"vtghuk13",                // direct match for this account
            @"iCloud",
            @"sign in to",
            @"Sign in to",
            @"Sign In to",
            @"输入密码",
            @"輸入密碼"
        ];
    });
    for (NSString* n in needles) {
        if ([s rangeOfString:n options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static BOOL aidblock_alert_text_should_block(NSString* title, NSString* message) {
    return aidblock_text_is_apple_id_prompt(title)
        || aidblock_text_is_apple_id_prompt(message);
}

// (1) Standard UIAlertController factory.
%hook UIAlertController
+ (instancetype)alertControllerWithTitle:(NSString*)title
                                 message:(NSString*)message
                          preferredStyle:(UIAlertControllerStyle)style {
    if (aidblock_alert_text_should_block(title, message)) {
        NSLog(@"[aidblock] suppressed alertController title=%@ message=%@", title, message);
        return nil;
    }
    return %orig;
}
%end

// (2) Presentation backstop.
%hook UIViewController
- (void)presentViewController:(UIViewController*)vc
                     animated:(BOOL)animated
                   completion:(void (^)(void))completion {
    if (vc && [vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController* alert = (UIAlertController*)vc;
        if (aidblock_alert_text_should_block(alert.title, alert.message)) {
            NSLog(@"[aidblock] suppressed present UIAlertController title=%@ message=%@",
                  alert.title, alert.message);
            if (completion) completion();
            return;
        }
    }
    if (vc == nil) {
        if (completion) completion();
        return;
    }
    %orig;
}
%end

// (3) SpringBoard private alert classes. Many iOS versions present
// system passcode / Apple ID alerts via SBSAlertItem subclasses
// rather than UIAlertController. These do not exist on every iOS, so
// we look them up at runtime and only hook when present.
%group SBSAlertItem_grp
%hook SBSAlertItem
- (void)willPresentAlertController:(UIAlertController*)alert {
    if (alert && aidblock_alert_text_should_block(alert.title, alert.message)) {
        NSLog(@"[aidblock] SBSAlertItem swallow title=%@", alert.title);
        // Don't call %orig — let the alert never finish being shown.
        return;
    }
    %orig;
}
- (BOOL)shouldShowInLockScreen { return NO; }
%end
%end

%group SBPasswordAlertItem_grp
%hook SBPasswordAlertItem
- (void)willActivate {
    NSLog(@"[aidblock] SBPasswordAlertItem willActivate swallowed");
    return; // skip activation entirely
}
%end
%end

%ctor {
    %init;
    Class c = objc_getClass("SBSAlertItem");
    if (c) %init(SBSAlertItem_grp);
    c = objc_getClass("SBPasswordAlertItem");
    if (c) %init(SBPasswordAlertItem_grp);
    NSLog(@"[aidblock] 1.1.0 loaded into pid=%d", getpid());
}
