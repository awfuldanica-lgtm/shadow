#import "DeviceInfoViewController.h"
#import "UggConfig.h"
#import <UIKit/UIKit.h>

@interface DeviceInfoViewController ()
@property (nonatomic, strong) NSArray<NSArray *> *rows; // [[label, value, key]]
@end

@implementation DeviceInfoViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"设备信息";
    UggConfig *cfg = UggConfig.shared;

    // Show current fake values (or placeholder if empty)
    NSString *udid    = cfg.valUDID.length     ? cfg.valUDID     : @"(未设置)";
    NSString *serial  = cfg.valSerial.length   ? cfg.valSerial   : @"(未设置)";
    NSString *wifi    = cfg.valWifiAddr.length ? cfg.valWifiAddr : @"(未设置)";
    NSString *blue    = cfg.valBlueAddr.length ? cfg.valBlueAddr : @"(未设置)";
    NSString *idfa    = cfg.valIDFA.length     ? cfg.valIDFA     : @"(未设置)";
    NSString *idfv    = cfg.valIDFV.length     ? cfg.valIDFV     : @"(未设置)";
    NSString *name    = cfg.valDeviceName.length ? cfg.valDeviceName : @"(未设置)";
    NSString *model   = cfg.valDeviceModel.length ? cfg.valDeviceModel : @"(未设置)";
    NSString *sysver  = cfg.valSystemVer.length ? cfg.valSystemVer : @"(未设置)";

    self.rows = @[
        @[@"WifiAddress",  wifi,   kValWifiAddr],
        @[@"SerialNumber", serial, kValSerial],
        @[@"UDID",         udid,   kValUDID],
        @[@"Name",         name,   kValDeviceName],
        @[@"BlueAddress",  blue,   kValBlueAddr],
        @[@"Model",        model,  kValDeviceModel],
        @[@"SystemVer",    sysver, kValSystemVer],
        @[@"IDFA",         idfa,   kValIDFA],
        @[@"IDFV",         idfv,   kValIDFV],
    ];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.rows.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    NSArray *row = self.rows[indexPath.row];
    cell.textLabel.text = row[0];
    cell.detailTextLabel.text = row[1];
    cell.detailTextLabel.numberOfLines = 1;
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSArray *row = self.rows[indexPath.row];
    NSString *label = row[0], *val = row[1], *key = row[2];

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:label message:nil
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.text = [val isEqualToString:@"(未设置)"] ? @"" : val;
        tf.placeholder = label;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *newVal = alert.textFields.firstObject.text ?: @"";
        NSString *prop = [self propForKey:key];
        if (prop) [UggConfig.shared setValue:newVal forKey:prop];
        [UggConfig.shared save];
        [self viewDidLoad];
        [self.tableView reloadData];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (NSString *)propForKey:(NSString *)key {
    NSDictionary *map = @{
        kValUDID: @"valUDID", kValSerial: @"valSerial",
        kValWifiAddr: @"valWifiAddr", kValBlueAddr: @"valBlueAddr",
        kValIDFA: @"valIDFA", kValIDFV: @"valIDFV",
        kValDeviceName: @"valDeviceName", kValDeviceModel: @"valDeviceModel",
        kValSystemVer: @"valSystemVer",
    };
    return map[key];
}

@end
