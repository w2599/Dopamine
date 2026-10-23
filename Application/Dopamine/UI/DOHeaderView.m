//
//  DOHeaderView.m
//  Dopamine
//
//  Created by tomt000 on 04/01/2024.
//

#import "DOHeaderView.h"
#import "DOThemeManager.h"

@interface DOHeaderView ()

@property (nonatomic) UIImageView *logoView;
@property (nonatomic) UIStackView *subtitleStack;
@property (nonatomic) UILabel *informationTitleLabel;

@end

@implementation DOHeaderView

// 创建标志与统一对齐的紧凑信息列。
-(id)initWithImage:(UIImage *)image subtitles:(NSArray<NSAttributedString *> *)subtitles {
    if (self = [super init]) {
        UIStackView *stackView = [[UIStackView alloc] init];
        stackView.axis = UILayoutConstraintAxisVertical;
        stackView.spacing = 2;
        stackView.translatesAutoresizingMaskIntoConstraints = NO;
        stackView.alignment = UIStackViewAlignmentLeading;
        self.subtitleStack = stackView;

        [self addSubview:stackView];

        [NSLayoutConstraint activateConstraints:@[
            [stackView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
            [stackView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
            [stackView.topAnchor constraintEqualToAnchor:self.topAnchor],
            [stackView.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
        ]];

        //1 - Add the logo to our stack
        self.logoView = [[UIImageView alloc] init];
        self.logoView.translatesAutoresizingMaskIntoConstraints = NO;
        self.logoView.image = [image imageWithAlignmentRectInsets:UIEdgeInsetsMake(7, 0, -7, 0)];
        [stackView addArrangedSubview:self.logoView];

        [NSLayoutConstraint activateConstraints:@[
            [self.logoView.heightAnchor constraintEqualToConstant:40],
            [self.logoView.widthAnchor constraintEqualToAnchor:self.logoView.heightAnchor multiplier:image.size.width / image.size.height],
        ]];

        //3 - Add our subtitles to our stack
        [subtitles enumerateObjectsUsingBlock:^(NSAttributedString *formatedText, NSUInteger idx, BOOL *stop) {
            [self addSubtitle:formatedText];
        }];

        self.translatesAutoresizingMaskIntoConstraints = NO;

        DOTheme *theme = [[DOThemeManager sharedInstance] enabledTheme];
        if (theme.titleShadow)
        {
            self.layer.shadowColor = [UIColor blackColor].CGColor;
            self.layer.shadowOffset = CGSizeZero;
            self.layer.shadowRadius = 30;
            self.layer.shadowOpacity = 0.3;
        }

    }
    return self;
}

// 新增可刷新的信息行，与作者行左对齐并按可用宽度换行。
- (UILabel *)addSubtitle:(NSAttributedString *)subtitle
{
    UILabel *label = [[UILabel alloc] init];
    label.attributedText = subtitle;
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentLeft;
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [self.subtitleStack addArrangedSubview:label];
    [label.widthAnchor constraintEqualToAnchor:self.subtitleStack.widthAnchor].active = YES;
    return label;
}

// 标题共用列宽，内容使用剩余宽度并与标题的首行基线对齐。
- (UILabel *)addInformationRowWithTitle:(NSAttributedString *)title
{
    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.attributedText = title;
    titleLabel.textAlignment = NSTextAlignmentLeft;
    [titleLabel setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    [titleLabel setContentHuggingPriority:UILayoutPriorityDefaultHigh forAxis:UILayoutConstraintAxisHorizontal];

    UILabel *valueLabel = [[UILabel alloc] init];
    valueLabel.numberOfLines = 0;
    valueLabel.textAlignment = NSTextAlignmentLeft;

    UIStackView *row = [[UIStackView alloc] initWithArrangedSubviews:@[titleLabel, valueLabel]];
    row.axis = UILayoutConstraintAxisHorizontal;
    row.alignment = UIStackViewAlignmentFirstBaseline;
    row.spacing = 4;
    row.translatesAutoresizingMaskIntoConstraints = NO;
    [self.subtitleStack addArrangedSubview:row];
    [row.widthAnchor constraintEqualToAnchor:self.subtitleStack.widthAnchor].active = YES;

    if (self.informationTitleLabel) {
        [titleLabel.widthAnchor constraintEqualToAnchor:self.informationTitleLabel.widthAnchor].active = YES;
    } else {
        self.informationTitleLabel = titleLabel;
    }
    return valueLabel;
}

@end
