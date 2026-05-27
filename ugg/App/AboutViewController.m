#import "AboutViewController.h"

@implementation AboutViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"关于";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *nameLbl = [[UILabel alloc] init];
    nameLbl.text = @"Ugg";
    nameLbl.font = [UIFont systemFontOfSize:60 weight:UIFontWeightBold];
    nameLbl.textAlignment = NSTextAlignmentCenter;
    nameLbl.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *verLbl = [[UILabel alloc] init];
    verLbl.text = @"Ugg 1.2.0";
    verLbl.font = [UIFont systemFontOfSize:15];
    verLbl.textColor = [UIColor secondaryLabelColor];
    verLbl.textAlignment = NSTextAlignmentCenter;
    verLbl.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *descLbl = [[UILabel alloc] init];
    descLbl.text = @"越狱检测绕过工具\n个人使用";
    descLbl.font = [UIFont systemFontOfSize:13];
    descLbl.textColor = [UIColor secondaryLabelColor];
    descLbl.textAlignment = NSTextAlignmentCenter;
    descLbl.numberOfLines = 2;
    descLbl.translatesAutoresizingMaskIntoConstraints = NO;

    [self.view addSubview:nameLbl];
    [self.view addSubview:verLbl];
    [self.view addSubview:descLbl];

    [NSLayoutConstraint activateConstraints:@[
        [nameLbl.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [nameLbl.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-60],
        [verLbl.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [verLbl.topAnchor constraintEqualToAnchor:nameLbl.bottomAnchor constant:8],
        [descLbl.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [descLbl.topAnchor constraintEqualToAnchor:verLbl.bottomAnchor constant:4],
    ]];
}

@end
