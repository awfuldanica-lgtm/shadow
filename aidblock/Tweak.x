// aidblock: suppress iOS "Verify Apple ID" / 验证 Apple ID popups in
// SpringBoard. The popup is triggered by accountsd / AuthKit when an
// iCloud service can't reauth an account whose state is "restricted".
// Users who own the account but can't sign in (account locked /
// restricted by Apple) get this popup repeatedly.
//
// Strategy: in SpringBoard, hook +[UIAlertController alertControllerWithTitle:
// message:preferredStyle:] AND -[UIViewController presentViewController:
// animated:completion:]. When the title/message looks like the Apple ID
// re-auth prompt (contains "Apple ID" + "密码"/"password"/"verify"/"verification"
// or contains the specific email substring "@"), suppress.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

static BOOL aidblock_text_is_apple_id_prompt(NSString* s) {
    if (!s || ![s isKindOfClass:[NSString class]]) return NO;
    if ([s length] == 0) return NO;
    // Match Chinese, Japanese, English, and generic patterns.
    static NSArray<NSString*>* needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[
            @"Apple ID",            // English / international
            @"验证 Apple",          // zh-Hans
            @"Apple 賬戶",
            @"Apple ID 密码",
            @"請在",                // zh-Hant + 設定 hint
            @"请在",                // zh-Hans hint
            @"输入密码",
            @"輸入密碼",
            @"Verify",
            @"Verification",
            @"sign in to",
            @"iCloud",
            @"@gmail.com",          // user's specific email contains this
            @"@icloud.com",
            @"@me.com",
            @"@yahoo",
            @"@outlook"
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

%hook UIViewController
- (void)presentViewController:(UIViewController*)vc
                     animated:(BOOL)animated
                   completion:(void (^)(void))completion {
    if ([vc isKindOfClass:[UIAlertController class]]) {
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

// In iOS 16+, accountsd uses a private AKAppleIDAuthenticationAlertViewController
// for some prompts. Best-effort guard: hook viewWillAppear: on any UIViewController
// whose class name contains "AppleID" or "AuthKit", and immediately dismiss it.
%hook UIViewController
- (void)viewWillAppear:(BOOL)animated {
    %orig;
    NSString* cn = NSStringFromClass([self class]);
    if (cn && (
        [cn rangeOfString:@"AppleID"  options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [cn rangeOfString:@"AuthKit"  options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [cn rangeOfString:@"PasswordAlert" options:NSCaseInsensitiveSearch].location != NSNotFound
    )) {
        NSLog(@"[aidblock] auto-dismiss VC class %@", cn);
        [self dismissViewControllerAnimated:NO completion:nil];
    }
}
%end
