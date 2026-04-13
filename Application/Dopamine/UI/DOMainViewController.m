//
//  DOMainViewController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOMainViewController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOJailbreaker.h"
#import "DOGlobalAppearance.h"
#import "DOActionMenuButton.h"
#import "DOUpdateViewController.h"
#import "DOLogCrashViewController.h"
#import <pthread.h>
#import <libjailbreak/libjailbreak.h>

#define CUSTOM_BG_IMAGE_PATH [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"custom_background.jpg"]

@interface DOMainViewController () <UIImagePickerControllerDelegate, UINavigationControllerDelegate>

@property DOJailbreakButton *jailbreakBtn;
@property NSArray<NSLayoutConstraint *> *jailbreakButtonConstraints;
@property DOActionMenuButton *updateButton;
@property(nonatomic) BOOL hideStatusBar;
@property(nonatomic) BOOL hideHomeIndicator;

@property (nonatomic, strong) UIImageView *backgroundImageView;
@property (nonatomic, strong) DOActionMenuView *actionView;

@end

@implementation DOMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Background Init
    self.backgroundImageView = [[UIImageView alloc] init];
    self.backgroundImageView.translatesAutoresizingMaskIntoConstraints = NO;
    self.backgroundImageView.contentMode = UIViewContentModeScaleAspectFill;
    self.backgroundImageView.clipsToBounds = YES;
    [self.view addSubview:self.backgroundImageView];
    [self.view sendSubviewToBack:self.backgroundImageView];
    [NSLayoutConstraint activateConstraints:@[
        [self.backgroundImageView.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [self.backgroundImageView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [self.backgroundImageView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.backgroundImageView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor]
    ]];
    
    [self setupStack];
    
    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPress:)];
    longPress.minimumPressDuration = 0.5;
    [self.view addGestureRecognizer:longPress];

    [self loadSavedBackground];
}

- (void)loadSavedBackground {
    if ([[NSFileManager defaultManager] fileExistsAtPath:CUSTOM_BG_IMAGE_PATH]) {
        self.backgroundImageView.image = [UIImage imageWithContentsOfFile:CUSTOM_BG_IMAGE_PATH];
    } else {
        self.backgroundImageView.image = nil;
    }
    [self updateUITransparency];
}

- (void)updateUITransparency {
    BOOL hasBG = (self.backgroundImageView.image != nil);
    CGFloat targetAlpha = hasBG ? 0.0 : 1.0;
    
    [UIView animateWithDuration:0.3 animations:^{
        if (self.actionView) {
            self.actionView.backgroundColor = hasBG ? [UIColor clearColor] : [UIColor colorWithWhite:1.0 alpha:0.05];
            for (UIView *v in self.actionView.subviews) {
                if ([NSStringFromClass([v class]) containsString:@"Material"]) v.alpha = targetAlpha;
            }
        }
        if (self.jailbreakBtn) {
            for (UIView *v in self.jailbreakBtn.subviews) {
                if ([NSStringFromClass([v class]) containsString:@"Material"]) v.alpha = targetAlpha;
            }
        }
    }];
}

- (void)handleLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Customization" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
        [alert addAction:[UIAlertAction actionWithTitle:@"Select Background" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            UIImagePickerController *picker = [[UIImagePickerController alloc] init];
            picker.delegate = self;
            picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
            [self presentViewController:picker animated:YES completion:nil];
        }]];
        if (self.backgroundImageView.image) {
            [alert addAction:[UIAlertAction actionWithTitle:@"Reset" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
                [[NSFileManager defaultManager] removeItemAtPath:CUSTOM_BG_IMAGE_PATH error:nil];
                [self loadSavedBackground];
            }]];
        }
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary<UIImagePickerControllerInfoKey,id> *)info {
    [picker dismissViewControllerAnimated:YES completion:nil];
    UIImage *img = info[UIImagePickerControllerOriginalImage];
    if (img) {
        [UIImageJPEGRepresentation(img, 0.8) writeToFile:CUSTOM_BG_IMAGE_PATH atomically:YES];
        [self loadSavedBackground];
    }
}

-(void)setupStack {
    UIStackView *stackView = [[UIStackView alloc] init];
    stackView.axis = UILayoutConstraintAxisVertical;
    stackView.alignment = UIStackViewAlignmentTrailing;
    stackView.distribution = UIStackViewDistributionEqualSpacing;
    stackView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stackView];

    int statusBarHeight = fmax(15, [[UIApplication sharedApplication] keyWindow].safeAreaInsets.top - 20);
    [NSLayoutConstraint activateConstraints:@[
        [stackView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:statusBarHeight],
        [stackView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor multiplier:[DOGlobalAppearance isHomeButtonDevice] ? 0.78 : 0.73]
    ]];

    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad) {
        [NSLayoutConstraint activateConstraints:@[
            [stackView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.8],
            [stackView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor]
        ]];
    } else {
        [NSLayoutConstraint activateConstraints:@[
            [stackView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:UI_PADDING],
            [stackView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-UI_PADDING],
        ]];
    }

    DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage: [UIImage imageNamed:@"Dopamine"] subtitles: @[
        [DOGlobalAppearance mainSubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],
        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"Credits_Made_By") withAlpha:0.8],
        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"AAAA") withAlpha:0.6],
        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"AAAB") withAlpha:0.6],
        [DOGlobalAppearance secondarySubtitleString:@" " withAlpha:0.8]
    ]];
    [stackView addArrangedSubview:headerView];
    [NSLayoutConstraint activateConstraints:@[[headerView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:5], [headerView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor]]];
    
    self.actionView = [[DOActionMenuView alloc] initWithActions:@[
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Settings_Title") image:[UIImage systemImageNamed:@"gearshape"] identifier:@"settings" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOSettingsController alloc] init] animated:YES];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Restart_SpringBoard_Title") image:[UIImage systemImageNamed:@"arrow.clockwise"] identifier:@"respring" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{ [[DOEnvironmentManager sharedManager] respring]; }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Reboot_Userspace_Title") image:[UIImage systemImageNamed:@"arrow.clockwise.circle"] identifier:@"reboot-userspace" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{ [[DOEnvironmentManager sharedManager] rebootUserspace]; }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Credits_Title") image:[UIImage systemImageNamed:@"info.circle"] identifier:@"credits" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOCreditsViewController alloc] init] animated:YES];
        }]
    ] delegate:self];
    [stackView addArrangedSubview: self.actionView];
    [NSLayoutConstraint activateConstraints:@[[self.actionView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor], [self.actionView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor]]];
    
    UIView *ph = [[UIView alloc] init];
    ph.translatesAutoresizingMaskIntoConstraints = NO;
    [stackView addArrangedSubview:ph];
    [NSLayoutConstraint activateConstraints:@[[ph.heightAnchor constraintEqualToConstant:60]]];
    
    BOOL isJ = [[DOEnvironmentManager sharedManager] isJailbroken];
    BOOL isS = [[DOEnvironmentManager sharedManager] isSupported];
    self.jailbreakBtn = [[DOJailbreakButton alloc] initWithAction: [UIAction actionWithTitle:[self jailbreakButtonTitle] image:[UIImage systemImageNamed:isS?@"lock.open":@"lock.slash"] identifier:@"jailbreak" handler:^(__kindof UIAction * _Nonnull action) {
        if(otherJailbreakActived(false)) return;
        [self.actionView hide];
        [self.jailbreakBtn expandButton: self.jailbreakButtonConstraints];
        [UIView animateWithDuration:0.75 animations:^{ [headerView setTransform:CGAffineTransformMakeTranslation(0, -25)]; }];
        [self startJailbreak];
    }]];
    self.jailbreakBtn.enabled = !isJ && isS;
    [self.view addSubview:self.jailbreakBtn];
    [NSLayoutConstraint activateConstraints:(self.jailbreakButtonConstraints = @[
        [self.jailbreakBtn.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [self.jailbreakBtn.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
        [self.jailbreakBtn.heightAnchor constraintEqualToConstant:60],
        [self.jailbreakBtn.centerYAnchor constraintEqualToAnchor:ph.centerYAnchor]
    ])];
}

- (NSString *)jailbreakButtonTitle {
    if (![[DOEnvironmentManager sharedManager] isSupported]) return DOLocalizedString(@"Unsupported");
    if ([[DOEnvironmentManager sharedManager] isJailbroken]) return DOLocalizedString(@"Status_Title_Jailbroken");
    if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO]) return DOLocalizedString(@"Button_Remove_Jailbreak");
    return DOLocalizedString(@"Button_Jailbreak_Title");
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.jailbreakBtn.button setTitle:[self jailbreakButtonTitle] forState:UIControlStateNormal];
}

- (void)startJailbreak {
    DOJailbreaker *jb = [[DOJailbreaker alloc] init];
    [[DOUIManager sharedInstance] startLogCapture];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self.jailbreakBtn lockMutex];
        dispatch_async(dispatch_get_main_queue(), ^{ self.hideHomeIndicator = YES; });
        NSError *err; BOOL didR = NO; BOOL showL = YES;
        [jb runWithError:&err didRemoveJailbreak:&didR showLogs:&showL];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (err) [self.navigationController pushViewController:[[DOLogCrashViewController alloc] initWithTitle:[err localizedDescription]] animated:YES];
            else if (didR) exit(0);
            else { [[DOUIManager sharedInstance] completeJailbreak]; [self fadeToBlack: ^{ [jb finalize]; }]; }
        });
        [self.jailbreakBtn unlockMutex];
    });
}

-(void)setupUpdateAvailable:(BOOL)env {
    self.updateButton = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:DOLocalizedString(@"Button_Update_Available") image:[UIImage systemImageNamed:@"arrow.down.circle"] identifier:@"upd" handler:^(__kindof UIAction * _Nonnull action) {
        [self.navigationController pushViewController:[[DOUpdateViewController alloc] initFromTag:@"0" toTag:@"1"] animated:YES];
    }] chevron:NO];
    self.updateButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.updateButton];
    [NSLayoutConstraint activateConstraints:@[[self.updateButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor], [self.updateButton.bottomAnchor constraintEqualToAnchor:self.jailbreakBtn.topAnchor constant:-20]]];
}

- (void)fadeToBlack:(void (^)(void))comp {
    [UIView animateWithDuration:0.5 animations:^{ self.view.alpha = 0; } completion:^(BOOL s) { comp(); }];
}

- (BOOL)actionMenuShowsChevronForAction:(UIAction *)act { return ([act.identifier isEqualToString:@"settings"] || [act.identifier isEqualToString:@"credits"]); }
- (BOOL)actionMenuActionIsEnabled:(UIAction *)act { return YES; }
- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
- (BOOL)prefersStatusBarHidden { return self.hideStatusBar; }
- (BOOL)prefersHomeIndicatorAutoHidden { return self.hideHomeIndicator; }
- (void)setHideStatusBar:(BOOL)h { _hideStatusBar = h; [self setNeedsStatusBarAppearanceUpdate]; }
- (void)setHideHomeIndicator:(BOOL)h { _hideHomeIndicator = h; [self setNeedsUpdateOfHomeIndicatorAutoHidden]; }
- (void)imagePickerControllerDidCancel:(UIImagePickerController *)p { [p dismissViewControllerAnimated:YES completion:nil]; }

@end
