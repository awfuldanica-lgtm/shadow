#import "MainViewController.h"
#import "UggConfig.h"
#import "DeviceInfoViewController.h"
#import "TargetAppsViewController.h"
#import "BackupViewController.h"
#import "SettingsViewController.h"
#import "AboutViewController.h"

typedef NS_ENUM(NSInteger, MainRow) {
    MainRowDeviceInfo = 0,
    MainRowTargetApps,
    MainRowBackup,
    MainRowNewDevice,
    MainRowOriginal,
    MainRowSettings,
    MainRowAbout,
};

@interface MainViewController ()
@property (nonatomic, strong) NSString *externalIP;
@end

@implementation MainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Ugg";
    self.tableView.backgroundColor = [UIColor systemGroupedBackgroundColor];
    [self fetchExternalIP];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (void)fetchExternalIP {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSURL *url = [NSURL URLWithString:@"https://api.ipify.org"];
        NSString *ip = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.externalIP = ip ?: @"--";
            [self.tableView reloadData];
        });
    });
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 4; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case 0: return 3; // 设备信息 目标应用 备份记录
        case 1: return 2; // 一键新机 原始机器
        case 2: return 1; // 设置
        case 3: return 1; // 关于
    }
    return 0;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    cell.textLabel.textColor = [UIColor labelColor];

    if (indexPath.section == 0) {
        switch (indexPath.row) {
            case 0:
                cell.textLabel.text = @"设备信息";
                break;
            case 1: {
                cell.textLabel.text = @"目标应用";
                NSUInteger n = UggConfig.shared.targetApps.count;
                if (n > 0) cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu 个", (unsigned long)n];
                break;
            }
            case 2:
                cell.textLabel.text = @"备份记录";
                break;
        }
    } else if (indexPath.section == 1) {
        cell.accessoryType = UITableViewCellAccessoryNone;
        cell.textLabel.textColor = [UIColor systemBlueColor];
        cell.textLabel.text = indexPath.row == 0 ? @"一键新机" : @"原始机器";
    } else if (indexPath.section == 2) {
        cell.textLabel.text = @"设置";
    } else {
        cell.textLabel.text = @"关于";
    }
    return cell;
}

- (UIView *)tableView:(UITableView *)tableView viewForFooterInSection:(NSInteger)section {
    if (section != 3) return nil;
    UILabel *lbl = [[UILabel alloc] init];
    lbl.text = self.externalIP ? [NSString stringWithFormat:@"IP: %@", self.externalIP] : @"";
    lbl.textColor = [UIColor systemRedColor];
    lbl.font = [UIFont systemFontOfSize:13];
    lbl.textAlignment = NSTextAlignmentCenter;
    lbl.numberOfLines = 1;
    return lbl;
}

- (CGFloat)tableView:(UITableView *)tableView heightForFooterInSection:(NSInteger)section {
    return section == 3 ? 44 : 0;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == 0) {
        UIViewController *vc;
        switch (indexPath.row) {
            case 0: vc = [[DeviceInfoViewController alloc] init]; break;
            case 1: vc = [[TargetAppsViewController alloc] init]; break;
            case 2: vc = [[BackupViewController alloc] init]; break;
        }
        [self.navigationController pushViewController:vc animated:YES];
    } else if (indexPath.section == 1) {
        if (indexPath.row == 0) {
            [self confirmNewDevice];
        } else {
            [self confirmOriginal];
        }
    } else if (indexPath.section == 2) {
        [self.navigationController pushViewController:[[SettingsViewController alloc] init] animated:YES];
    } else {
        [self.navigationController pushViewController:[[AboutViewController alloc] init] animated:YES];
    }
}

- (void)confirmNewDevice {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"一键新机"
        message:@"将生成随机设备信息并启用全部伪装，确认？"
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确认" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [UggConfig.shared applyNewDevice];
        [self.tableView reloadData];
        [self showToast:@"一键新机完成，重启目标App生效"];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)confirmOriginal {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"原始机器"
        message:@"将关闭全部伪装，恢复真实设备信息，确认？"
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确认" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [UggConfig.shared applyOriginal];
        [self.tableView reloadData];
        [self showToast:@"已还原原始机器"];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showToast:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:nil message:msg preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:a animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [a dismissViewControllerAnimated:YES completion:nil];
    });
}

@end
