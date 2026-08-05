// Ugg 1.9.0 — App+Tweak, arm64-only. AMG-parity spoofing + live config reload.
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
#import <dirent.h>
#import <notify.h>

#define UGG_PLIST   "/var/mobile/Library/Preferences/com.harry.ugg.plist"
#define UGG_NOTIFY  "com.harry.ugg.reload"   // App posts this after saving config

// ---------------------------------------------------------------------------
// Config — reloaded live on Darwin notification (AMG-style "no restart")
// ---------------------------------------------------------------------------

static BOOL cfg_antiJailbreak    = NO;
static BOOL cfg_fakeIDFA         = NO;
static BOOL cfg_fakeIDFV         = NO;
static BOOL cfg_fakeName         = NO;
static BOOL cfg_fakeSystemVer    = NO;
static BOOL cfg_fakeDeviceModel  = NO;

static NSString *cfg_valUDID        = @"";
static NSString *cfg_valSerial      = @"";
static NSString *cfg_valIDFA        = @"";
static NSString *cfg_valIDFV        = @"";
static NSString *cfg_valDeviceName  = @"";
static NSString *cfg_valDeviceModel = @"";
static NSString *cfg_valSystemVer   = @"";

// Whether the current process is a configured target. Set once at ctor; the
// notification reload only refreshes values for processes already targeted.
static BOOL ugg_is_target = NO;

static BOOL ugg_load_config(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@UGG_PLIST];
    if (!d) return NO;

    NSString *myBundle = NSBundle.mainBundle.bundleIdentifier;
    NSArray *targets = d[@"targetApps"];
    if (!myBundle || !targets || ![targets containsObject:myBundle]) return NO;

    cfg_antiJailbreak   = [d[@"antiJailbreak"]   boolValue];
    cfg_fakeIDFA        = [d[@"fakeIDFA"]         boolValue];
    cfg_fakeIDFV        = [d[@"fakeIDFV"]         boolValue];
    cfg_fakeName        = [d[@"fakeName"]         boolValue];
    cfg_fakeSystemVer   = [d[@"fakeSystemVer"]    boolValue];
    cfg_fakeDeviceModel = [d[@"fakeDeviceModel"]  boolValue];

    cfg_valUDID        = d[@"val_udid"]        ?: @"";
    cfg_valSerial      = d[@"val_serial"]      ?: @"";
    cfg_valIDFA        = d[@"val_idfa"]        ?: @"";
    cfg_valIDFV        = d[@"val_idfv"]        ?: @"";
    cfg_valDeviceName  = d[@"val_deviceName"]  ?: @"";
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

// All C hooks are installed unconditionally for target apps, but gate their
// behaviour on cfg_antiJailbreak so the toggle takes effect live (no restart).

static int (*orig_access)(const char *, int) = NULL;
static int ugg_access(const char *p, int m) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_access(p, m);
}

static int (*orig_faccessat)(int, const char *, int, int) = NULL;
static int ugg_faccessat(int fd, const char *p, int m, int flag) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_faccessat(fd, p, m, flag);
}

static int (*orig_stat)(const char *, struct stat *) = NULL;
static int ugg_stat(const char *p, struct stat *b) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_stat(p, b);
}

static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int ugg_lstat(const char *p, struct stat *b) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_lstat(p, b);
}

static int (*orig_fstatat)(int, const char *, struct stat *, int) = NULL;
static int ugg_fstatat(int fd, const char *p, struct stat *b, int flag) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_fstatat(fd, p, b, flag);
}

static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *ugg_fopen(const char *p, const char *m) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return NULL; }
    return orig_fopen(p, m);
}

static FILE *(*orig_freopen)(const char *, const char *, FILE *) = NULL;
static FILE *ugg_freopen(const char *p, const char *m, FILE *s) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return NULL; }
    return orig_freopen(p, m, s);
}

static int (*orig_open)(const char *, int, ...) = NULL;
static int ugg_open(const char *p, int flags, mode_t mode) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_open(p, flags, mode);
}

static int (*orig_openat)(int, const char *, int, ...) = NULL;
static int ugg_openat(int fd, const char *p, int flags, mode_t mode) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return -1; }
    return orig_openat(fd, p, flags, mode);
}

static DIR *(*orig_opendir)(const char *) = NULL;
static DIR *ugg_opendir(const char *p) {
    if (cfg_antiJailbreak && ugg_path_is_jb(p)) { errno = ENOENT; return NULL; }
    return orig_opendir(p);
}

static void *(*orig_dlopen)(const char *, int) = NULL;
static void *ugg_dlopen(const char *p, int m) {
    if (cfg_antiJailbreak && p && strcasestr(p, "MobileSubstrate")) return NULL;
    return orig_dlopen(p, m);
}

static char *(*orig_getenv)(const char *) = NULL;
static char *ugg_getenv(const char *n) {
    if (cfg_antiJailbreak && ugg_env_is_jb(n)) return NULL;
    return orig_getenv(n);
}

// hw.machine device-model spoof (sysctlbyname path used by many SDKs)
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int ugg_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (cfg_fakeDeviceModel && cfg_valDeviceModel.length && name && strcmp(name, "hw.machine") == 0) {
        const char *m = cfg_valDeviceModel.UTF8String;
        size_t need = strlen(m) + 1;
        if (!oldp && oldlenp) { *oldlenp = need; return 0; }
        if (oldp && oldlenp) {
            if (*oldlenp < need) { errno = ENOMEM; return -1; }
            memcpy(oldp, m, need); *oldlenp = need; return 0;
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
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

// UUID from a stored string, nil if invalid/empty (so we fall back to %orig)
static NSUUID *ugg_uuid(NSString *s) {
    if (!s.length) return nil;
    return [[NSUUID alloc] initWithUUIDString:s];
}

%group UggHooks

%hook UIDevice
// model returns the generic family ("iPhone"); the model identifier
// (iPhone11,8) is spoofed via sysctl hw.machine + MobileGestalt.
- (NSString *)model        { return cfg_fakeDeviceModel ? @"iPhone" : %orig; }
- (NSString *)localizedModel { return cfg_fakeDeviceModel ? @"iPhone" : %orig; }
- (NSString *)name {
    return (cfg_fakeName && cfg_valDeviceName.length) ? cfg_valDeviceName : %orig;
}
- (NSString *)systemVersion {
    return (cfg_fakeSystemVer && cfg_valSystemVer.length) ? cfg_valSystemVer : %orig;
}
- (NSUUID *)identifierForVendor {
    if (cfg_fakeIDFV) { NSUUID *u = ugg_uuid(cfg_valIDFV); if (u) return u; }
    return %orig;
}
%end

%hook NSProcessInfo
- (NSOperatingSystemVersion)operatingSystemVersion {
    if (cfg_fakeSystemVer && cfg_valSystemVer.length) {
        NSOperatingSystemVersion v = {0, 0, 0};
        NSArray<NSString *> *p = [cfg_valSystemVer componentsSeparatedByString:@"."];
        if (p.count > 0) v.majorVersion = p[0].integerValue;
        if (p.count > 1) v.minorVersion = p[1].integerValue;
        if (p.count > 2) v.patchVersion = p[2].integerValue;
        return v;
    }
    return %orig;
}
- (NSString *)operatingSystemVersionString {
    if (cfg_fakeSystemVer && cfg_valSystemVer.length)
        return [NSString stringWithFormat:@"Version %@ (Build 20D67)", cfg_valSystemVer];
    return %orig;
}
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

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (cfg_antiJailbreak && url.scheme) {
        NSString *s = url.scheme.lowercaseString;
        static NSArray *schemes;
        static dispatch_once_t t;
        dispatch_once(&t, ^{ schemes = @[@"cydia", @"sileo", @"zbra", @"filza",
            @"undecimus", @"activator", @"installer", @"apt-repo"]; });
        if ([schemes containsObject:s]) return NO;
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

// IDFA lives in AdSupport; hooked in its own group, only initialised when the
// class is actually present (banking apps may not link AdSupport).
%group UggAS
%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    if (cfg_fakeIDFA) { NSUUID *u = ugg_uuid(cfg_valIDFA); if (u) return u; }
    return %orig;
}
%end
%end // UggAS

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

%ctor {
    // Hard-exclude SpringBoard — never touch it regardless of config
    NSString *bundle = NSBundle.mainBundle.bundleIdentifier;
    if (!bundle) return;
    if ([bundle isEqualToString:@"com.apple.springboard"] ||
        [bundle isEqualToString:@"com.apple.SpringBoard"]) return;

    if (!ugg_load_config()) return; // not a target app — install NOTHING
    ugg_is_target = YES;

    // ObjC hooks (behaviour gated per-call by cfg, so toggles apply live)
    %init(UggHooks);
    if (NSClassFromString(@"ASIdentifierManager")) %init(UggAS);

    NSLog(@"[Ugg] 1.9.0 active in %@", bundle);

    // C hooks installed unconditionally; each gates on cfg internally so the
    // anti-JB / model toggles take effect without relaunching the app.
    MSHookFunction((void *)access,    (void *)ugg_access,    (void **)&orig_access);
    MSHookFunction((void *)faccessat, (void *)ugg_faccessat, (void **)&orig_faccessat);
    MSHookFunction((void *)stat,      (void *)ugg_stat,      (void **)&orig_stat);
    MSHookFunction((void *)lstat,     (void *)ugg_lstat,     (void **)&orig_lstat);
    MSHookFunction((void *)fstatat,   (void *)ugg_fstatat,   (void **)&orig_fstatat);
    MSHookFunction((void *)fopen,     (void *)ugg_fopen,     (void **)&orig_fopen);
    MSHookFunction((void *)freopen,   (void *)ugg_freopen,   (void **)&orig_freopen);
    MSHookFunction((void *)open,      (void *)ugg_open,      (void **)&orig_open);
    MSHookFunction((void *)openat,    (void *)ugg_openat,    (void **)&orig_openat);
    MSHookFunction((void *)opendir,   (void *)ugg_opendir,   (void **)&orig_opendir);
    MSHookFunction((void *)dlopen,    (void *)ugg_dlopen,    (void **)&orig_dlopen);
    MSHookFunction((void *)getenv,    (void *)ugg_getenv,    (void **)&orig_getenv);
    MSHookFunction((void *)sysctlbyname, (void *)ugg_sysctlbyname, (void **)&orig_sysctlbyname);

    void *mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW | RTLD_NOLOAD);
    if (!mg) mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    if (mg) {
        MGCopyAnswer_t fn = (MGCopyAnswer_t)dlsym(mg, "MGCopyAnswer");
        if (fn) MSHookFunction((void *)fn, (void *)ugg_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
    }

    // Live reload: App posts UGG_NOTIFY after saving config -> refresh values
    // in every running target process, so "一键新机" applies without restart.
    int token;
    notify_register_dispatch(UGG_NOTIFY, &token, dispatch_get_main_queue(), ^(int t) {
        if (ugg_is_target) ugg_load_config();
    });
}
