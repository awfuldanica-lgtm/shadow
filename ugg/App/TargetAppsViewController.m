#import "TargetAppsViewController.h"
#import "UggConfig.h"

@interface AppItem : NSObject
@property NSString *name, *bundleID;
@end
@implementation AppItem @end

@interface TargetAppsViewController ()
@property NSArray<AppItem *> *apps;
@end

@implementation TargetAppsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"选择目标应用";
    [self loadApps];
}

- (void)loadApps {
    NSMutableArray *result = [NSMutableArray array];
    @try {
        Class ws = NSClassFromString(@"LSApplicationWorkspace");
        id workspace = [ws performSelector:@selector(defaultWorkspace)];
        NSArray *all = [workspace performSelector:@selector(allInstalledApplications)];
        for (id proxy in all) {
            NSString *bid  = [proxy performSelector:@selector(applicationIdentifier)];
            NSString *name = [proxy performSelector:@selector(localizedName)];
            if (!bid || !name) continue;
            AppItem *item  = [AppItem new];
            item.bundleID  = bid;
            item.name      = name;
            [result addObject:item];
        }
        [result sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"name" ascending:YES]]];
    } @catch (id e) {}
    self.apps = result;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.apps.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    AppItem *item = self.apps[indexPath.row];
    cell.textLabel.text = item.name;
    cell.detailTextLabel.text = item.bundleID;
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    BOOL selected = [UggConfig.shared isTargetApp:item.bundleID];
    cell.accessoryType = selected ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    AppItem *item = self.apps[indexPath.row];
    UggConfig *cfg = UggConfig.shared;
    if ([cfg isTargetApp:item.bundleID]) {
        [cfg.targetApps removeObject:item.bundleID];
    } else {
        [cfg.targetApps addObject:item.bundleID];
    }
    [cfg save];
    [tableView reloadRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationNone];
}

@end
