#import "SettingsViewController.h"
#import "UggConfig.h"

// Each setting row: label + UggConfig property name
static NSArray<NSArray *> *sections(void) {
    return @[
        // Section 0: 伪装信息配置
        @[
            @[@"伪装 IDFA",        @"fakeIDFA"],
            @[@"伪装 IDFV",        @"fakeIDFV"],
            @[@"伪装名称",          @"fakeName"],
            @[@"伪装 Wi-Fi 信息",   @"fakeWifi"],
            @[@"伪装 MAC 地址",     @"fakeMAC"],
            @[@"伪装 DeviceToken",  @"fakeDeviceToken"],
            @[@"伪装系统版本号",     @"fakeSystemVer"],
            @[@"伪装设备机型",       @"fakeDeviceModel"],
            @[@"伪装系统启动时间",   @"fakeUptime"],
            @[@"伪装屏幕亮度",       @"fakeBrightness"],
            @[@"伪装内网 IP 信息",   @"fakeIP"],
            @[@"伪装磁盘和内存",     @"fakeDiskMemory"],
            @[@"伪装电池和音量",     @"fakeBattery"],
        ],
        // Section 1: 高级选项
        @[
            @[@"反越狱检测",        @"antiJailbreak"],
            @[@"深度反越狱检测",    @"deepAntiJailbreak"],
            @[@"屏蔽 VPN 检测",     @"blockVPN"],
            @[@"屏蔽 HTTP 代理检测", @"blockHTTPProxy"],
            @[@"伪装硬件 ID",       @"fakeHardwareID"],
        ],
    ];
}

static NSString *sectionTitles[] = { @"伪装信息配置", @"高级选项" };

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"设置";
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv { return sections().count; }

- (NSString *)tableView:(UITableView *)tv titleForHeaderInSection:(NSInteger)s {
    return sectionTitles[s];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return sections()[s].count;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    NSArray *row = sections()[ip.section][ip.row];
    cell.textLabel.text = row[0];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;

    UISwitch *sw = [[UISwitch alloc] init];
    NSString *key = row[1];
    sw.on = [[UggConfig.shared valueForKey:key] boolValue];
    sw.tag = ip.section * 100 + ip.row;
    [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = sw;
    return cell;
}

- (void)switchChanged:(UISwitch *)sw {
    NSInteger section = sw.tag / 100;
    NSInteger row = sw.tag % 100;
    NSArray *r = sections()[section][row];
    NSString *key = r[1];
    [UggConfig.shared setValue:@(sw.isOn) forKey:key];
    [UggConfig.shared save];
}

@end
