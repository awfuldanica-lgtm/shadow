#import "UggConfig.h"
#import <sys/utsname.h>
#import <notify.h>

#define UGG_NOTIFY "com.harry.ugg.reload"

static NSString *randomHex(int bytes) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < bytes; i++)
        [s appendFormat:@"%02x", arc4random_uniform(256)];
    return s;
}

static NSString *randomMac(void) {
    return [NSString stringWithFormat:@"%@:%@:%@:%@:%@:%@",
        randomHex(1), randomHex(1), randomHex(1),
        randomHex(1), randomHex(1), randomHex(1)];
}

static NSString *randomUUID(void) {
    return [[NSUUID UUID] UUIDString];
}

static NSString *randomSerial(void) {
    // Apple serial format: e.g. C02XG0ZXJG5J (12 chars)
    NSString *chars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString stringWithString:@"C0"];
    for (int i = 0; i < 10; i++)
        [s appendFormat:@"%C", [chars characterAtIndex:arc4random_uniform((uint32_t)chars.length)]];
    return s;
}

static NSString *randomUDID(void) {
    return [NSString stringWithFormat:@"%08X-%04X%04X%04X%04X%08X",
        arc4random(), arc4random_uniform(0xFFFF), arc4random_uniform(0xFFFF),
        arc4random_uniform(0xFFFF), arc4random_uniform(0xFFFF), arc4random()];
}

@implementation UggConfig

+ (instancetype)shared {
    static UggConfig *inst;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ inst = [UggConfig new]; [inst load]; });
    return inst;
}

- (void)load {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:UGG_PLIST] ?: @{};

    self.antiJailbreak    = [d[kAntiJailbreak]    boolValue];
    self.deepAntiJailbreak= [d[kDeepAntiJailbreak] boolValue];
    self.fakeIDFA         = [d[kFakeIDFA]          boolValue];
    self.fakeIDFV         = [d[kFakeIDFV]          boolValue];
    self.fakeName         = [d[kFakeName]          boolValue];
    self.fakeWifi         = [d[kFakeWifi]          boolValue];
    self.fakeMAC          = [d[kFakeMAC]           boolValue];
    self.fakeDeviceToken  = [d[kFakeDeviceToken]   boolValue];
    self.fakeSystemVer    = [d[kFakeSystemVer]     boolValue];
    self.fakeDeviceModel  = [d[kFakeDeviceModel]   boolValue];
    self.fakeUptime       = [d[kFakeUptime]        boolValue];
    self.fakeBrightness   = [d[kFakeBrightness]    boolValue];
    self.fakeIP           = [d[kFakeIP]            boolValue];
    self.fakeDiskMemory   = [d[kFakeDiskMemory]    boolValue];
    self.fakeBattery      = [d[kFakeBattery]       boolValue];
    self.blockVPN         = [d[kBlockVPN]          boolValue];
    self.blockHTTPProxy   = [d[kBlockHTTPProxy]    boolValue];
    self.fakeHardwareID   = [d[kFakeHardwareID]    boolValue];

    self.valUDID        = d[kValUDID]        ?: @"";
    self.valSerial      = d[kValSerial]      ?: @"";
    self.valWifiAddr    = d[kValWifiAddr]    ?: @"";
    self.valBlueAddr    = d[kValBlueAddr]    ?: @"";
    self.valIDFA        = d[kValIDFA]        ?: @"";
    self.valIDFV        = d[kValIDFV]        ?: @"";
    self.valDeviceName  = d[kValDeviceName]  ?: @"";
    self.valDeviceModel = d[kValDeviceModel] ?: @"";
    self.valSystemVer   = d[kValSystemVer]   ?: @"";

    NSArray *apps = d[kTargetApps];
    self.targetApps = apps ? [NSMutableSet setWithArray:apps] : [NSMutableSet set];
}

- (void)save {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];

    d[kAntiJailbreak]    = @(self.antiJailbreak);
    d[kDeepAntiJailbreak]= @(self.deepAntiJailbreak);
    d[kFakeIDFA]         = @(self.fakeIDFA);
    d[kFakeIDFV]         = @(self.fakeIDFV);
    d[kFakeName]         = @(self.fakeName);
    d[kFakeWifi]         = @(self.fakeWifi);
    d[kFakeMAC]          = @(self.fakeMAC);
    d[kFakeDeviceToken]  = @(self.fakeDeviceToken);
    d[kFakeSystemVer]    = @(self.fakeSystemVer);
    d[kFakeDeviceModel]  = @(self.fakeDeviceModel);
    d[kFakeUptime]       = @(self.fakeUptime);
    d[kFakeBrightness]   = @(self.fakeBrightness);
    d[kFakeIP]           = @(self.fakeIP);
    d[kFakeDiskMemory]   = @(self.fakeDiskMemory);
    d[kFakeBattery]      = @(self.fakeBattery);
    d[kBlockVPN]         = @(self.blockVPN);
    d[kBlockHTTPProxy]   = @(self.blockHTTPProxy);
    d[kFakeHardwareID]   = @(self.fakeHardwareID);

    d[kValUDID]        = self.valUDID        ?: @"";
    d[kValSerial]      = self.valSerial      ?: @"";
    d[kValWifiAddr]    = self.valWifiAddr    ?: @"";
    d[kValBlueAddr]    = self.valBlueAddr    ?: @"";
    d[kValIDFA]        = self.valIDFA        ?: @"";
    d[kValIDFV]        = self.valIDFV        ?: @"";
    d[kValDeviceName]  = self.valDeviceName  ?: @"";
    d[kValDeviceModel] = self.valDeviceModel ?: @"";
    d[kValSystemVer]   = self.valSystemVer   ?: @"";

    d[kTargetApps] = self.targetApps.allObjects;

    [d writeToFile:UGG_PLIST atomically:YES];

    // Tell every running target app to reload config live (no relaunch needed)
    notify_post(UGG_NOTIFY);
}

- (void)applyNewDevice {
    self.antiJailbreak   = YES;
    self.fakeIDFA        = YES;
    self.fakeIDFV        = YES;
    self.fakeName        = YES;
    self.fakeWifi        = YES;
    self.fakeMAC         = YES;
    self.fakeSystemVer   = YES;
    self.fakeDeviceModel = YES;
    self.fakeUptime      = YES;
    self.fakeDiskMemory  = YES;
    self.fakeBattery     = YES;

    self.valUDID        = randomUDID();
    self.valSerial      = randomSerial();
    self.valWifiAddr    = randomMac();
    self.valBlueAddr    = randomMac();
    self.valIDFA        = randomUUID();
    self.valIDFV        = randomUUID();
    self.valDeviceName  = @"iPhone";
    self.valDeviceModel = @"iPhone14,3";
    self.valSystemVer   = @"16.3.1";

    [self save];
}

- (void)applyOriginal {
    self.antiJailbreak   = NO;
    self.fakeIDFA = self.fakeIDFV = self.fakeName = self.fakeWifi = NO;
    self.fakeMAC = self.fakeSystemVer = self.fakeDeviceModel = NO;
    self.fakeUptime = self.fakeDiskMemory = self.fakeBattery = NO;

    self.valUDID = self.valSerial = self.valWifiAddr = self.valBlueAddr = @"";
    self.valIDFA = self.valIDFV = self.valDeviceName = @"";
    self.valDeviceModel = self.valSystemVer = @"";

    [self save];
}

- (BOOL)isTargetApp:(NSString *)bundleID {
    return [self.targetApps containsObject:bundleID];
}

@end
