#import "AppDelegate.h"
#import "MainViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    MainViewController *main = [[MainViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:main];
    nav.navigationBar.prefersLargeTitles = NO;
    self.window.rootViewController = nav;
    self.window.backgroundColor = [UIColor systemBackgroundColor];
    [self.window makeKeyAndVisible];
    return YES;
}

@end
