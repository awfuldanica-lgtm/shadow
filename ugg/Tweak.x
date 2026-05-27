// Ugg 1.0.0 — jailbreak detection bypass
// Reverse-engineered hook set, personal use only.
//
// Modules:
//   A. C-level probes  : access/stat/fopen/dlopen/getenv/sysctl/sysctlbyname
//   B. MobileGestalt   : MGCopyAnswer — fake device model, serial, UDID
//   C. UIDevice        : model / name / identifierForVendor
//   D. NSFileManager   : fileExistsAtPath variants
//   E. ObjC JB methods : isJailBreak / isJailBroken / jailbreakStatus / etc.
//   F. DFP bypass      : isDFPHookedDetecedByVOS / isJailBrokenDetectedByVOS
//   G. UIAlert block   : suppress JB-warning alerts

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
#import <pthread.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static BOOL ugg_path_is_jb(const char *path) {
    if (!path) return NO;
    static const char *needles[] = {
        "/var/jb/",
        "/private/var/jb/",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/TweakInject.dylib",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/var/lib/apt/",
        "/var/lib/cydia/",
        "/var/cache/apt/",
        "/private/var/lib/apt/",
        "/etc/apt/",
        "/var/checkra1n.dmg",
        "/.bootstrapped_electra",
        "/.installed_unc0ver",
        "/usr/sbin/frida-server",
        "/usr/local/frida-server",
        "/var/usr/lib/frida",
        "/usr/lib/frida",
        "/bin/bash",
        "/bin/sh",
        "cydia://",
        "sileo://",
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
        "libhooker", "CydiaSubstrate", "Substrate",
        "frida", "cynject", NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strcasestr(path, needles[i])) return YES;
    }
    return NO;
}

static BOOL ugg_env_is_jb(const char *name) {
    if (!name) return NO;
    static const char *exact[] = {
        "DYLD_INSERT_LIBRARIES",
        "_MSSafeMode",
        "_SubstrateUseSystemLogs",
        "JBPATHLOG",
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

static int (*orig_open)(const char *, int, ...) = NULL;
static int ugg_open(const char *path, int flags, ...) {
    if (ugg_path_is_jb(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    return orig_open(path, flags, mode);
}

static void *(*orig_dlopen)(const char *, int) = NULL;
static void *ugg_dlopen(const char *path, int mode) {
    if (ugg_dylib_is_jb(path)) return NULL;
    return orig_dlopen(path, mode);
}

static int (*orig_dlopen_preflight)(const char *) = NULL;
static int ugg_dlopen_preflight(const char *path) {
    if (ugg_dylib_is_jb(path)) return 0;
    return orig_dlopen_preflight(path);
}

static char *(*orig_getenv)(const char *) = NULL;
static char *ugg_getenv(const char *name) {
    if (ugg_env_is_jb(name)) return NULL;
    return orig_getenv(name);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int ugg_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                      void *newp, size_t newlen) {
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int ugg_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                             void *newp, size_t newlen) {
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ---------------------------------------------------------------------------
// B. MobileGestalt — MGCopyAnswer
// ---------------------------------------------------------------------------

typedef CFTypeRef (*MGCopyAnswer_t)(CFStringRef key);
static MGCopyAnswer_t orig_MGCopyAnswer = NULL;

// Keys that reveal JB/device truth — we return clean values
static CFTypeRef ugg_MGCopyAnswer(CFStringRef key) {
    if (!key) return orig_MGCopyAnswer(key);
    CFStringRef k = key;

    // Unique device identifier — return a stable but non-real UDID
    if (CFEqual(k, CFSTR("UniqueDeviceID")) ||
        CFEqual(k, CFSTR("UniqueDeviceIDData"))) {
        // Return a deterministic placeholder; real apps don't check format strictly
        return CFStringCreateCopy(NULL, CFSTR("00000000000000000000000000000000000000000"));
    }

    // Serial number — return generic-looking clean serial
    if (CFEqual(k, CFSTR("SerialNumber"))) {
        return CFStringCreateCopy(NULL, CFSTR("C02XG0ZXJG5J"));
    }

    // Hardware model — return plain "iPhone" to avoid model-specific JB lists
    if (CFEqual(k, CFSTR("HardwareModel")) ||
        CFEqual(k, CFSTR("ProductType"))) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone14,3"));
    }

    // Marketing name
    if (CFEqual(k, CFSTR("marketing-name"))) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone 13 Pro Max"));
    }

    CFTypeRef result = orig_MGCopyAnswer(key);
    return result;
}

// ---------------------------------------------------------------------------
// C. UIDevice
// ---------------------------------------------------------------------------

%hook UIDevice

- (NSString *)model {
    return @"iPhone";
}

- (NSString *)localizedModel {
    return @"iPhone";
}

%end

// ---------------------------------------------------------------------------
// D. NSFileManager
// ---------------------------------------------------------------------------

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && ugg_path_is_jb([path UTF8String])) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && ugg_path_is_jb([path UTF8String])) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (path && ugg_path_is_jb([path UTF8String])) return NO;
    return %orig;
}

%end

// ---------------------------------------------------------------------------
// E. ObjC JB detection method NOPs
// Hooks any ObjC method named isJailBreak/isJailBroken/jailbreakStatus etc.
// regardless of which class it lives on.
// ---------------------------------------------------------------------------

static void ugg_nop_jb_methods(void) {
    // Selector names that always mean "am I jailbroken?" — return NO / 0
    static const char *sels[] = {
        "isJailBreak", "isJailBroken", "isJailBreakon", "isJailbreak",
        "isJailbroken", "jailbreakStatus", "checkJailBreak",
        "checkJailbreak", "isDeviceJailbroken", "jailBreakCheck",
        NULL
    };

    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    if (!classes) return;

    for (unsigned int i = 0; i < classCount; i++) {
        Class cls = classes[i];
        for (int j = 0; sels[j]; j++) {
            SEL sel = sel_getUid(sels[j]);
            Method m = class_getInstanceMethod(cls, sel);
            if (!m) m = class_getClassMethod(cls, sel);
            if (!m) continue;

            // Replace with IMP that always returns 0/NO
            IMP nop = imp_implementationWithBlock(^id(id _self) {
                return @NO;
            });
            method_setImplementation(m, nop);
        }
    }
    free(classes);
}

// ---------------------------------------------------------------------------
// F. DFP / VOS bypass
// ---------------------------------------------------------------------------

%hook NSObject

- (BOOL)isDFPHookedDetecedByVOS {
    return NO;
}

- (BOOL)isJailBrokenDetectedByVOS {
    return NO;
}

- (BOOL)isDFPHooked {
    return NO;
}

%end

// ---------------------------------------------------------------------------
// G. UIAlert block — suppress JB-warning dialogs
// ---------------------------------------------------------------------------

static BOOL ugg_text_is_jb_alert(NSString *s) {
    if (!s || s.length == 0) return NO;
    static NSArray *needles = nil;
    static dispatch_once_t t = 0;
    dispatch_once(&t, ^{
        needles = @[
            // Japanese
            @"脱獄", @"改竄", @"改ざん", @"セキュリティ", @"システムエラー",
            @"本アプリを終了", @"終了させていただ", @"本アプリはご利用",
            // Korean
            @"탈옥", @"루팅", @"비정상", @"지원하지 않",
            // English
            @"jailbreak", @"Jailbreak", @"Jailbroken", @"rooted", @"Rooted",
            @"Security Alert", @"device has been modified",
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
// Constructor — install C-level hooks via MSHookFunction
// ---------------------------------------------------------------------------

%ctor {
    NSLog(@"[Ugg] 1.0.0 loaded into %@", NSBundle.mainBundle.bundleIdentifier);

    // A. C probes
    MSHookFunction((void *)access,            (void *)ugg_access,            (void **)&orig_access);
    MSHookFunction((void *)faccessat,         (void *)ugg_faccessat,         (void **)&orig_faccessat);
    MSHookFunction((void *)stat,              (void *)ugg_stat,              (void **)&orig_stat);
    MSHookFunction((void *)lstat,             (void *)ugg_lstat,             (void **)&orig_lstat);
    MSHookFunction((void *)fopen,             (void *)ugg_fopen,             (void **)&orig_fopen);
    MSHookFunction((void *)open,              (void *)ugg_open,              (void **)&orig_open);
    MSHookFunction((void *)dlopen,            (void *)ugg_dlopen,            (void **)&orig_dlopen);
    MSHookFunction((void *)dlopen_preflight,  (void *)ugg_dlopen_preflight,  (void **)&orig_dlopen_preflight);
    MSHookFunction((void *)getenv,            (void *)ugg_getenv,            (void **)&orig_getenv);
    MSHookFunction((void *)sysctl,            (void *)ugg_sysctl,            (void **)&orig_sysctl);
    MSHookFunction((void *)sysctlbyname,      (void *)ugg_sysctlbyname,      (void **)&orig_sysctlbyname);

    // B. MobileGestalt
    void *mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW | RTLD_NOLOAD);
    if (!mg) mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    if (mg) {
        MGCopyAnswer_t fn = (MGCopyAnswer_t)dlsym(mg, "MGCopyAnswer");
        if (fn) MSHookFunction((void *)fn, (void *)ugg_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
    }

    // E. NOP ObjC JB detection methods
    dispatch_async(dispatch_get_main_queue(), ^{
        ugg_nop_jb_methods();
    });

    NSLog(@"[Ugg] hooks installed");
}
