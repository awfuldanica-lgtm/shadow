// Ugg 1.1.0 — jailbreak detection bypass
// Safer rewrite: removed NSObject hook and class-enumeration NOP.
// Modules:
//   A. C-level probes  : access/faccessat/stat/lstat/fopen/open/dlopen/getenv/sysctl
//   B. MobileGestalt   : MGCopyAnswer — fake UDID/serial/model
//   C. UIDevice        : model / localizedModel
//   D. NSFileManager   : fileExistsAtPath variants
//   E. UIAlert block   : suppress JB-warning alerts

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

// ---------------------------------------------------------------------------
// JB path / env / dylib detection helpers
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
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/var/lib/apt/", "/var/lib/cydia/", "/var/cache/apt/",
        "/private/var/lib/apt/", "/etc/apt/",
        "/var/checkra1n.dmg", "/.bootstrapped_electra", "/.installed_unc0ver",
        "/usr/sbin/frida-server", "/usr/local/frida-server",
        "/usr/lib/frida", "/bin/bash",
        "cydia://", "sileo://",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strstr(path, needles[i])) return YES;
    }
    return NO;
}

static BOOL ugg_dylib_is_jb(const char *path) {
    if (!path) return NO;
    static const char *needles[] = {
        "MobileSubstrate", "TweakInject", "substitute",
        "libhooker", "CydiaSubstrate", "frida", "cynject",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strcasestr(path, needles[i])) return YES;
    }
    return NO;
}

static BOOL ugg_env_is_jb(const char *name) {
    if (!name) return NO;
    static const char *exact[] = {
        "DYLD_INSERT_LIBRARIES", "_MSSafeMode",
        "_SubstrateUseSystemLogs", "JBPATHLOG",
        NULL
    };
    for (int i = 0; exact[i]; i++) {
        if (strcmp(name, exact[i]) == 0) return YES;
    }
    return NO;
}

// ---------------------------------------------------------------------------
// A. C-level probes
// ---------------------------------------------------------------------------

static int (*orig_access)(const char *, int) = NULL;
static int ugg_access(const char *path, int mode) {
    if (ugg_path_is_jb(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int (*orig_faccessat)(int, const char *, int, int) = NULL;
static int ugg_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (ugg_path_is_jb(path)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode, flags);
}

static int (*orig_stat)(const char *, struct stat *) = NULL;
static int ugg_stat(const char *path, struct stat *buf) {
    if (ugg_path_is_jb(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int ugg_lstat(const char *path, struct stat *buf) {
    if (ugg_path_is_jb(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *ugg_fopen(const char *path, const char *mode) {
    if (ugg_path_is_jb(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static void *(*orig_dlopen)(const char *, int) = NULL;
static void *ugg_dlopen(const char *path, int mode) {
    if (ugg_dylib_is_jb(path)) return NULL;
    return orig_dlopen(path, mode);
}

static char *(*orig_getenv)(const char *) = NULL;
static char *ugg_getenv(const char *name) {
    if (ugg_env_is_jb(name)) return NULL;
    return orig_getenv(name);
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int ugg_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                             void *newp, size_t newlen) {
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ---------------------------------------------------------------------------
// B. MobileGestalt
// ---------------------------------------------------------------------------

typedef CFTypeRef (*MGCopyAnswer_t)(CFStringRef key);
static MGCopyAnswer_t orig_MGCopyAnswer = NULL;

static CFTypeRef ugg_MGCopyAnswer(CFStringRef key) {
    if (!key || !orig_MGCopyAnswer) return NULL;
    if (CFEqual(key, CFSTR("UniqueDeviceID")) ||
        CFEqual(key, CFSTR("UniqueDeviceIDData")))
        return CFStringCreateCopy(NULL, CFSTR("00000000000000000000000000000000000000000"));
    if (CFEqual(key, CFSTR("SerialNumber")))
        return CFStringCreateCopy(NULL, CFSTR("C02XG0ZXJG5J"));
    if (CFEqual(key, CFSTR("HardwareModel")) ||
        CFEqual(key, CFSTR("ProductType")))
        return CFStringCreateCopy(NULL, CFSTR("iPhone14,3"));
    if (CFEqual(key, CFSTR("marketing-name")))
        return CFStringCreateCopy(NULL, CFSTR("iPhone 13 Pro Max"));
    return orig_MGCopyAnswer(key);
}

// ---------------------------------------------------------------------------
// C. UIDevice
// ---------------------------------------------------------------------------

%hook UIDevice

- (NSString *)model { return @"iPhone"; }
- (NSString *)localizedModel { return @"iPhone"; }

%end

// ---------------------------------------------------------------------------
// D. NSFileManager
// ---------------------------------------------------------------------------

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && ugg_path_is_jb(path.UTF8String)) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && ugg_path_is_jb(path.UTF8String)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (path && ugg_path_is_jb(path.UTF8String)) return NO;
    return %orig;
}

%end

// ---------------------------------------------------------------------------
// E. UIAlert block
// ---------------------------------------------------------------------------

static BOOL ugg_text_is_jb_alert(NSString *s) {
    if (!s || s.length == 0) return NO;
    static NSArray *needles = nil;
    static dispatch_once_t t = 0;
    dispatch_once(&t, ^{
        needles = @[
            @"脱獄", @"改竄", @"改ざん", @"セキュリティ", @"システムエラー",
            @"本アプリを終了", @"終了させていただ", @"本アプリはご利用",
            @"탈옥", @"루팅", @"비정상", @"지원하지 않",
            @"jailbreak", @"Jailbreak", @"Jailbroken",
            @"rooted", @"Rooted", @"Security Alert",
        ];
    });
    for (NSString *n in needles) {
        if ([s rangeOfString:n options:NSCaseInsensitiveSearch].location != NSNotFound)
            return YES;
    }
    return NO;
}

%hook UIAlertController

+ (instancetype)alertControllerWithTitle:(NSString *)title
                                 message:(NSString *)message
                          preferredStyle:(UIAlertControllerStyle)style {
    if (ugg_text_is_jb_alert(title) || ugg_text_is_jb_alert(message))
        return nil;
    return %orig;
}

%end

%hook UIViewController

- (void)presentViewController:(UIViewController *)vc
                      animated:(BOOL)animated
                    completion:(void (^)(void))completion {
    if (!vc) { if (completion) completion(); return; }
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *ac = (UIAlertController *)vc;
        if (ugg_text_is_jb_alert(ac.title) || ugg_text_is_jb_alert(ac.message)) {
            if (completion) completion();
            return;
        }
    }
    %orig;
}

%end

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

%ctor {
    NSLog(@"[Ugg] 1.1.0 loaded into %@", NSBundle.mainBundle.bundleIdentifier);

    MSHookFunction((void *)access,       (void *)ugg_access,       (void **)&orig_access);
    MSHookFunction((void *)faccessat,    (void *)ugg_faccessat,    (void **)&orig_faccessat);
    MSHookFunction((void *)stat,         (void *)ugg_stat,         (void **)&orig_stat);
    MSHookFunction((void *)lstat,        (void *)ugg_lstat,        (void **)&orig_lstat);
    MSHookFunction((void *)fopen,        (void *)ugg_fopen,        (void **)&orig_fopen);
    MSHookFunction((void *)dlopen,       (void *)ugg_dlopen,       (void **)&orig_dlopen);
    MSHookFunction((void *)getenv,       (void *)ugg_getenv,       (void **)&orig_getenv);
    MSHookFunction((void *)sysctlbyname, (void *)ugg_sysctlbyname, (void **)&orig_sysctlbyname);

    // MobileGestalt — runtime load only, no link-time dep
    void *mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW | RTLD_NOLOAD);
    if (!mg) mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    if (mg) {
        MGCopyAnswer_t fn = (MGCopyAnswer_t)dlsym(mg, "MGCopyAnswer");
        if (fn) MSHookFunction((void *)fn, (void *)ugg_MGCopyAnswer,
                               (void **)&orig_MGCopyAnswer);
    }

    NSLog(@"[Ugg] hooks installed");
}
