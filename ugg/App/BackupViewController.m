#import "BackupViewController.h"
#import "UggConfig.h"

static NSString *const kBackupDir = @"/var/mobile/Media/Ugg/backups";
static NSString *const kActiveBackup = @"/var/mobile/Media/Ugg/active_backup";

@interface BackupViewController ()
@property NSMutableArray<NSString *> *backups; // file names
@property NSString *activeBackup;
@end

@implementation BackupViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = [NSString stringWithFormat:@"备份记录"];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:@"编辑" style:UIBarButtonItemStylePlain
        target:self action:@selector(toggleEdit)];
    [[NSFileManager defaultManager] createDirectoryAtPath:kBackupDir
        withIntermediateDirectories:YES attributes:nil error:nil];
    self.activeBackup = [NSString stringWithContentsOfFile:kActiveBackup
        encoding:NSUTF8StringEncoding error:nil];
    [self reloadBackups];
}

- (void)reloadBackups {
    NSArray *files = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:kBackupDir error:nil] ?: @[];
    self.backups = [[files filteredArrayUsingPredicate:
        [NSPredicate predicateWithFormat:@"self ENDSWITH '.plist'"]] mutableCopy];
    [self.backups sortUsingSelector:@selector(compare:)];
    self.title = [NSString stringWithFormat:@"备份记录 (%lu/%lu)",
        (unsigned long)self.backups.count, (unsigned long)self.backups.count];
    [self.tableView reloadData];
}

- (void)toggleEdit {
    [self setEditing:!self.editing animated:YES];
    self.navigationItem.rightBarButtonItem.title = self.editing ? @"完成" : @"编辑";
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv { return 2; }

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return s == 0 ? self.backups.count : 1;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    if (ip.section == 0) {
        NSString *name = [self.backups[ip.row] stringByDeletingPathExtension];
        cell.textLabel.text = name;
        BOOL active = [name isEqualToString:self.activeBackup];
        if (active) {
            cell.accessoryType = UITableViewCellAccessoryCheckmark;
            cell.detailTextLabel.text = @"当前使用";
        }
    } else {
        cell.textLabel.text = @"原始机器";
        cell.textLabel.textColor = [UIColor systemBlueColor];
        BOOL active = [@"原始机器" isEqualToString:self.activeBackup];
        if (active) cell.accessoryType = UITableViewCellAccessoryCheckmark;
    }
    return cell;
}

- (UITableViewCell *)tableView:(UITableView *)tv titleForDeleteConfirmationButtonForRowAtIndexPath:(NSIndexPath *)ip {
    return @"删除";
}

- (BOOL)tableView:(UITableView *)tv canEditRowAtIndexPath:(NSIndexPath *)ip {
    return ip.section == 0;
}

- (void)tableView:(UITableView *)tv commitEditingStyle:(UITableViewCellEditingStyle)es forRowAtIndexPath:(NSIndexPath *)ip {
    if (es == UITableViewCellEditingStyleDelete) {
        NSString *file = [kBackupDir stringByAppendingPathComponent:self.backups[ip.row]];
        [[NSFileManager defaultManager] removeItemAtPath:file error:nil];
        [self.backups removeObjectAtIndex:ip.row];
        [tv deleteRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationAutomatic];
    }
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    if (ip.section == 1) {
        [UggConfig.shared applyOriginal];
        self.activeBackup = @"原始机器";
        [self.activeBackup writeToFile:kActiveBackup atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        NSString *name = [self.backups[ip.row] stringByDeletingPathExtension];
        NSString *path = [kBackupDir stringByAppendingPathComponent:self.backups[ip.row]];
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path];
        if (d) {
            [[NSFileManager defaultManager] copyItemAtPath:path toPath:UGG_PLIST error:nil];
            [UggConfig.shared load];
        }
        self.activeBackup = name;
        [self.activeBackup writeToFile:kActiveBackup atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    [self reloadBackups];
}

- (UIView *)tableView:(UITableView *)tv viewForFooterInSection:(NSInteger)s {
    if (s != 1) return nil;
    NSFileSystemAttributes *attr = [[NSFileManager defaultManager]
        attributesOfFileSystemForPath:kBackupDir error:nil];
    long long free = [attr[NSFileSystemFreeSize] longLongValue];
    UILabel *lbl = [[UILabel alloc] init];
    lbl.text = [NSString stringWithFormat:@"剩余空间: %.2fGB",
        free / 1024.0 / 1024.0 / 1024.0];
    lbl.textColor = [UIColor secondaryLabelColor];
    lbl.font = [UIFont systemFontOfSize:13];
    lbl.textAlignment = NSTextAlignmentCenter;
    return lbl;
}

- (CGFloat)tableView:(UITableView *)tv heightForFooterInSection:(NSInteger)s {
    return s == 1 ? 36 : 0;
}

- (void)saveCurrentAsBackup {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyy-MM-dd-HH-mm-ss";
    NSString *name = [f stringFromDate:[NSDate date]];
    NSString *path = [[kBackupDir stringByAppendingPathComponent:name] stringByAppendingPathExtension:@"plist"];
    [[NSFileManager defaultManager] copyItemAtPath:UGG_PLIST toPath:path error:nil];
    [self reloadBackups];
}

@end
