#import <Foundation/Foundation.h>

// Plist path shared between App and Tweak
#define UGG_PLIST @"/var/mobile/Library/Preferences/com.harry.ugg.plist"

// Feature toggle keys
#define kAntiJailbreak      @"antiJailbreak"
#define kDeepAntiJailbreak  @"deepAntiJailbreak"
#define kFakeIDFA           @"fakeIDFA"
#define kFakeIDFV           @"fakeIDFV"
#define kFakeName           @"fakeName"
#define kFakeWifi           @"fakeWifi"
#define kFakeMAC            @"fakeMAC"
#define kFakeDeviceToken    @"fakeDeviceToken"
#define kFakeSystemVer      @"fakeSystemVer"
#define kFakeDeviceModel    @"fakeDeviceModel"
#define kFakeUptime         @"fakeUptime"
#define kFakeBrightness     @"fakeBrightness"
#define kFakeIP             @"fakeIP"
#define kFakeDiskMemory     @"fakeDiskMemory"
#define kFakeBattery        @"fakeBattery"
#define kBlockVPN           @"blockVPN"
#define kBlockHTTPProxy     @"blockHTTPProxy"
#define kFakeHardwareID     @"fakeHardwareID"

// Fake value keys
#define kValUDID            @"val_udid"
#define kValSerial          @"val_serial"
#define kValWifiAddr        @"val_wifiAddr"
#define kValBlueAddr        @"val_blueAddr"
#define kValIDFA            @"val_idfa"
#define kValIDFV            @"val_idfv"
#define kValDeviceName      @"val_deviceName"
#define kValDeviceModel     @"val_deviceModel"
#define kValSystemVer       @"val_systemVer"

// Target apps key
#define kTargetApps         @"targetApps"

@interface UggConfig : NSObject

+ (instancetype)shared;

// Feature toggles
@property (nonatomic) BOOL antiJailbreak;
@property (nonatomic) BOOL deepAntiJailbreak;
@property (nonatomic) BOOL fakeIDFA;
@property (nonatomic) BOOL fakeIDFV;
@property (nonatomic) BOOL fakeName;
@property (nonatomic) BOOL fakeWifi;
@property (nonatomic) BOOL fakeMAC;
@property (nonatomic) BOOL fakeDeviceToken;
@property (nonatomic) BOOL fakeSystemVer;
@property (nonatomic) BOOL fakeDeviceModel;
@property (nonatomic) BOOL fakeUptime;
@property (nonatomic) BOOL fakeBrightness;
@property (nonatomic) BOOL fakeIP;
@property (nonatomic) BOOL fakeDiskMemory;
@property (nonatomic) BOOL fakeBattery;
@property (nonatomic) BOOL blockVPN;
@property (nonatomic) BOOL blockHTTPProxy;
@property (nonatomic) BOOL fakeHardwareID;

// Fake values
@property (nonatomic, strong) NSString *valUDID;
@property (nonatomic, strong) NSString *valSerial;
@property (nonatomic, strong) NSString *valWifiAddr;
@property (nonatomic, strong) NSString *valBlueAddr;
@property (nonatomic, strong) NSString *valIDFA;
@property (nonatomic, strong) NSString *valIDFV;
@property (nonatomic, strong) NSString *valDeviceName;
@property (nonatomic, strong) NSString *valDeviceModel;
@property (nonatomic, strong) NSString *valSystemVer;

// Target apps (set of bundle IDs)
@property (nonatomic, strong) NSMutableSet<NSString *> *targetApps;

- (void)load;
- (void)save;
- (void)applyNewDevice;   // 一键新机
- (void)applyOriginal;    // 原始机器
- (BOOL)isTargetApp:(NSString *)bundleID;

@end
