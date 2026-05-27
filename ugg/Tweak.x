// Ugg 1.3.0 — %group/%init ensures hooks only apply to target apps
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

#define UGG_PLIST "/var/mobile/Library/Preferences/com.harry.ugg.plist"

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

static BOOL cfg_antiJailbreak    = NO;
static BOOL cfg_fakeIDFA         = NO;
static BOOL cfg_fakeIDFV         = NO;
static BOOL cfg_fakeSystemVer    = NO;
static BOOL cfg_fakeDeviceModel  = NO;

static NSString *cfg_valUDID        = nil;
static NSString *cfg_valSerial      = nil;
static NSString *cfg_valIDFA        = nil;
static NSString *cfg_valIDFV        = nil;
static NSString *cfg_valDeviceModel = nil;
static NSString *cfg_valSystemVer   = nil;

static BOOL ugg_load_config(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@UGG_PLIST];
    if (!d) return NO;

    NSString *myBundle = NSBundle.mainBundle.bundleIdentifier;
    NSArray *targets = d[@"targetApps"];
    if (!myBundle || !targets || ![targets containsObject:myBundle]) return NO;

    cfg_antiJailbreak   = [d[@"antiJailbreak"]   boolValue];
    cfg_fakeIDFA        = [d[@"fakeIDFA"]         boolValue];
    cfg_fakeIDFV        = [d[@"fakeIDFV"]         boolValue];
    cfg_fakeSystemVer   = [d[@"fakeSystemVer"]    boolValue];
    cfg_fakeDeviceModel = [d[@"fakeDeviceModel"]  boolValue];

    cfg_valUDID        = d[@"val_udid"]        ?: @"";
    cfg_valSerial      = d[@"val_serial"]      ?: @"";
    cfg_valIDFA        = d[@"val_idfa"]        ?: @"";
    cfg_valIDFV        = d[@"val_idfv"]        ?: @"";
    cfg_valDeviceModel = d[@"val_deviceModel"] ?: @"";
    cfg_valSystemVer   = d[@"val_systemVer"]   ?: @"";

    return YES;
}

// ---------------------------------------------------------------------------
// JB path / env helpers
// ---------------------------------------------------------------------------

static BOOL ugg_path_is_jb(const char *path) {
    if (!path) return NO;
    static const char *needles[] = {
        "/var/jb/", "/private/var/jb/",
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/Filza.app",
        "/usr/lib/libsubstrate.dylib", "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libhooker.dylib", "/usr/lib/TweakInject.dylib",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/lib/apt/", "/var/lib/cydia/",
        "/private/var/lib/apt/", "/etc/apt/",
        "/usr/sbin/frida-server", "/usr/lib/frida",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strstr(path, needles[i])) return YES;
    }
    return NO;
}

static BOOL ugg_env_is_jb(const char *name) {
    if (!name) return NO;
    static const char *exact[] = {
        "DYLD_INSERT_LIBRARIES", "_MSSafeMode",
        "_SubstrateUseSystemLogs", "JBPATHLOG", NULL
    };
    for (int i = 0; exact[i]; i++)
        if (strcmp(name, exact[i]) == 0) return YES;
    return NO;
}

// ---------------------------------------------------------------------------
// C hooks (installed only when antiJailbreak ON, only for target apps)
// ---------------------------------------------------------------------------

static int (*orig_access)(const char *, int) = NULL;
static int ugg_access(const char *p, int m) {
    if (ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_access(p, m);
}

static int (*orig_stat)(const char *, struct stat *) = NULL;
static int ugg_stat(const char *p, struct stat *b) {
    if (ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_stat(p, b);
}

static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int ugg_lstat(const char *p, struct stat *b) {
    if (ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_lstat(p, b);
}

static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *ugg_fopen(const char *p, const char *m) {
    if (ugg_path_is_jb(p)) { errno = ENOENT; return NULL; }
    return orig_fopen(p, m);
}

static void *(*orig_dlopen)(const char *, int) = NULL;
static void *ugg_dlopen(const char *p, int m) {
    if (p && strcasestr(p, "MobileSubstrate")) return NULL;
    return orig_dlopen(p, m);
}

static char *(*orig_getenv)(const char *) = NULL;
static char *ugg_getenv(const char *n) {
    if (ugg_env_is_jb(n)) return NULL;
    return orig_getenv(n);
}

// ---------------------------------------------------------------------------
// MobileGestalt hook
// ---------------------------------------------------------------------------

typedef CFTypeRef (*MGCopyAnswer_t)(CFStringRef);
static MGCopyAnswer_t orig_MGCopyAnswer = NULL;

static CFTypeRef ugg_MGCopyAnswer(CFStringRef key) {
    if (!key || !orig_MGCopyAnswer) return NULL;
    if (cfg_fakeDeviceModel) {
        if (CFEqual(key, CFSTR("UniqueDeviceID")))
            return CFStringCreateCopy(NULL, (__bridge CFStringRef)(cfg_valUDID.length ? cfg_valUDID : @"00000000000000000000000000000000000000000"));
        if (CFEqual(key, CFSTR("SerialNumber")))
            return CFStringCreateCopy(NULL, (__bridge CFStringRef)(cfg_valSerial.length ? cfg_valSerial : @"C02XG0ZXJG5J"));
        if (CFEqual(key, CFSTR("HardwareModel")) || CFEqual(key, CFSTR("ProductType")))
            return CFStringCreateCopy(NULL, (__bridge CFStringRef)(cfg_valDeviceModel.length ? cfg_valDeviceModel : @"iPhone14,3"));
    }
    return orig_MGCopyAnswer(key);
}

// ---------------------------------------------------------------------------
// ObjC hooks — wrapped in %group so they are ONLY installed for target apps
// ---------------------------------------------------------------------------

static BOOL ugg_text_is_jb(NSString *s) {
    if (!s || s.length == 0) return NO;
    static NSArray *needles;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ needles = @[
        @"脱獄", @"改竄", @"セキュリティ", @"システムエラー",
        @"탈옥", @"루팅", @"비정상", @"지원하지 않",
        @"jailbreak", @"Jailbreak", @"Jailbroken", @"Rooted", @"Security Alert",
    ]; });
    for (NSString *n in needles)
        if ([s rangeOfString:n options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

%group UggHooks

%hook UIDevice
- (NSString *)model {
    return cfg_fakeDeviceModel ? (cfg_valDeviceModel.length ? cfg_valDeviceModel : @"iPhone") : %orig;
}
- (NSString *)localizedModel { return self.model; }
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (cfg_antiJailbreak && path && ugg_path_is_jb(path.UTF8String)) return NO;
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    if (cfg_antiJailbreak && path && ugg_path_is_jb(path.UTF8String)) {
        if (isDir) *isDir = NO; return NO;
    }
    return %orig;
}
%end

%hook UIAlertController
+ (instancetype)alertControllerWithTitle:(NSString *)t message:(NSString *)m preferredStyle:(UIAlertControllerStyle)s {
    if (cfg_antiJailbreak && (ugg_text_is_jb(t) || ugg_text_is_jb(m))) return nil;
    return %orig;
}
%end

%hook UIViewController
- (void)presentViewController:(UIViewController *)vc animated:(BOOL)a completion:(void(^)(void))c {
    if (!vc) { %orig; return; }
    if (cfg_antiJailbreak && [vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *ac = (UIAlertController *)vc;
        if (ugg_text_is_jb(ac.title) || ugg_text_is_jb(ac.message)) { if (c) c(); return; }
    }
    %orig;
}
%end

%end // UggHooks

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

%ctor {
    if (!ugg_load_config()) return; // not a target app — install NOTHING

    // Install ObjC hooks only for target apps
    %init(UggHooks);

    NSLog(@"[Ugg] 1.3.0 active in %@", NSBundle.mainBundle.bundleIdentifier);

    if (cfg_antiJailbreak) {
        MSHookFunction((void *)access,  (void *)ugg_access,  (void **)&orig_access);
        MSHookFunction((void *)stat,    (void *)ugg_stat,    (void **)&orig_stat);
        MSHookFunction((void *)lstat,   (void *)ugg_lstat,   (void **)&orig_lstat);
        MSHookFunction((void *)fopen,   (void *)ugg_fopen,   (void **)&orig_fopen);
        MSHookFunction((void *)dlopen,  (void *)ugg_dlopen,  (void **)&orig_dlopen);
        MSHookFunction((void *)getenv,  (void *)ugg_getenv,  (void **)&orig_getenv);
    }

    if (cfg_fakeDeviceModel || cfg_fakeIDFA || cfg_fakeIDFV) {
        void *mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW | RTLD_NOLOAD);
        if (!mg) mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
        if (mg) {
            MGCopyAnswer_t fn = (MGCopyAnswer_t)dlsym(mg, "MGCopyAnswer");
            if (fn) MSHookFunction((void *)fn, (void *)ugg_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }
    }
}
