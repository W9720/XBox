#import <UIKit/UIKit.h>

// 设置面板：对应原插件 X_MenuViewController 的四个分类
// 所有开关直接使用逆向确证的真实键；未实现行为的开关仅存储值，不影响现有逻辑。

static NSString *const kXBEShowEntryKey = @"XHSR_ShowEntry";

@interface XBEKeyRow : NSObject
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *key;
@property (nonatomic, assign) BOOL defaultValue;
+ (instancetype)row:(NSString *)title key:(NSString *)key on:(BOOL)on;
@end

@implementation XBEKeyRow
+ (instancetype)row:(NSString *)title key:(NSString *)key on:(BOOL)on {
    XBEKeyRow *r = [XBEKeyRow new];
    r.title = title;
    r.key = key;
    r.defaultValue = on;
    return r;
}
@end

static NSArray<NSString *> *XBESectionTitles(void) {
    return @[@"下载", @"界面", @"外观"];
}

static NSArray<NSArray<XBEKeyRow *> *> *XBESectionRows(void) {
    static NSArray *sections;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        sections = @[
            @[
                [XBEKeyRow row:@"无水印保存图片视频" key:@"XHS_SaveMediaWithoutWatermark" on:YES],
                [XBEKeyRow row:@"图片视频独立保存" key:@"XHS_SeparateMediaAlbums" on:NO],
                [XBEKeyRow row:@"保存文件自动命名" key:@"XHS_AutomaticFileNaming" on:NO],
                [XBEKeyRow row:@"评论区图片·实况下载" key:@"XHS_EnableCommentsImageDownload" on:YES],
                [XBEKeyRow row:@"评论区视频无水印保存" key:@"XHS_EnableCommentsVideoDownload" on:YES],
                [XBEKeyRow row:@"开启评论语音下载" key:@"XHS_EnableCommentsVoiceDownload" on:NO],
                [XBEKeyRow row:@"评论区表情下载" key:@"XHS_EnableCommentsEmojiDownload" on:NO],
            ],
            @[
                [XBEKeyRow row:@"移除板块赞助·广告" key:@"XHS_RemoveAdsAndSponsors" on:YES],
                [XBEKeyRow row:@"移除底栏热门板块" key:@"XHS_RemoveBottomTabHot" on:NO],
                [XBEKeyRow row:@"移除底栏购物板块" key:@"XHS_RemoveBottomTabShop" on:NO],
                [XBEKeyRow row:@"移除底栏消息板块" key:@"XHS_RemoveBottomTabMessage" on:NO],
                [XBEKeyRow row:@"移除底栏加号板块" key:@"XHS_RemoveBottomTabPlus" on:NO],
                [XBEKeyRow row:@"移除首页消息红点" key:@"XHS_RemoveHomeMessageBadge" on:NO],
                [XBEKeyRow row:@"移除首页关注红点" key:@"XHS_RemoveHomeFollowBadge" on:NO],
                [XBEKeyRow row:@"自定义聊天背景" key:@"XHS_ChatBackgroundEnabled" on:NO],
                [XBEKeyRow row:@"自定义消息页面背景" key:@"XHSR_ChatPageBackground" on:NO],
            ],
            @[
                [XBEKeyRow row:@"启用自定义字体" key:@"XHS_CustomFontEnabled" on:NO],
                [XBEKeyRow row:@"显示悬浮入口" key:kXBEShowEntryKey on:YES],
            ],
        ];
    });
    return sections;
}

@interface XBEFloatingEntry : NSObject
+ (void)install;
+ (void)setHidden:(BOOL)hidden;
+ (void)openMenu;
+ (void)handleTwoFingerLongPress:(UILongPressGestureRecognizer *)gesture;
+ (void)handlePan:(UIPanGestureRecognizer *)pan;
@end

@interface XBEMenuViewController : UITableViewController
@end

@implementation XBEMenuViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        self.title = @"XBook Enhancer";
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                      target:self
                                                      action:@selector(close)];
}

- (void)close {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return XBESectionRows().count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return XBESectionTitles()[section];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return XBESectionRows()[section].count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"XBEKeyCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellID];
        UISwitch *sw = [UISwitch new];
        [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = sw;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.textLabel.font = [UIFont systemFontOfSize:15];
    }
    XBEKeyRow *row = XBESectionRows()[indexPath.section][indexPath.row];
    cell.textLabel.text = row.title;

    UISwitch *sw = (UISwitch *)cell.accessoryView;
    sw.tag = indexPath.section * 1000 + indexPath.row;
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    id stored = [d objectForKey:row.key];
    sw.on = stored ? [d boolForKey:row.key] : row.defaultValue;
    return cell;
}

- (void)switchChanged:(UISwitch *)sender {
    NSInteger section = sender.tag / 1000;
    NSInteger rowIndex = sender.tag % 1000;
    XBEKeyRow *row = XBESectionRows()[section][rowIndex];

    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setBool:sender.on forKey:row.key];
    [d synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"XHSRSettingsChanged" object:row.key];

    if ([row.key isEqualToString:kXBEShowEntryKey]) {
        [XBEFloatingEntry setHidden:!sender.on];
    }
}

@end

static UIWindow *gEntryWindow;
static UIButton *gEntryButton;

@implementation XBEFloatingEntry

+ (void)install {
    if (gEntryWindow) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        id stored = [d objectForKey:kXBEShowEntryKey];
        BOOL show = stored ? [d boolForKey:kXBEShowEntryKey] : YES;
        if (!show) return;

        UIWindow *window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        window.windowLevel = UIWindowLevelAlert + 5;
        window.backgroundColor = [UIColor clearColor];
        UIViewController *root = [UIViewController new];
        root.view.backgroundColor = [UIColor clearColor];
        window.rootViewController = root;

        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.frame = CGRectMake(0, 0, 46, 46);
        button.layer.cornerRadius = 23;
        button.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.65];
        [button setImage:[UIImage systemImageNamed:@"gearshape.fill"] forState:UIControlStateNormal];
        button.tintColor = [UIColor whiteColor];
        [button addTarget:self action:@selector(openMenu) forControlEvents:UIControlEventTouchUpInside];

        UILongPressGestureRecognizer *twoFinger = [[UILongPressGestureRecognizer alloc]
            initWithTarget:self action:@selector(handleTwoFingerLongPress:)];
        twoFinger.numberOfTouchesRequired = 2;
        twoFinger.minimumPressDuration = 0.5;
        twoFinger.allowableMovement = 24.0;
        [button addGestureRecognizer:twoFinger];

        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
        [button addGestureRecognizer:pan];

        CGFloat savedX = [d doubleForKey:@"XHSR_EntryX"];
        CGFloat savedY = [d doubleForKey:@"XHSR_EntryY"];
        CGRect screen = [UIScreen mainScreen].bounds;
        if (savedX <= 0 && savedY <= 0) {
            savedX = screen.size.width - 58.0;
            savedY = screen.size.height * 0.62;
        }
        button.center = CGPointMake(savedX, savedY);

        [root.view addSubview:button];
        window.hidden = NO;
        gEntryWindow = window;
        gEntryButton = button;
    });
}

+ (void)setHidden:(BOOL)hidden {
    gEntryWindow.hidden = hidden;
}

+ (void)openMenu {
    UIViewController *top = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:[XBEMenuViewController new]];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [top presentViewController:nav animated:YES completion:nil];
}

+ (void)handleTwoFingerLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) [self openMenu];
}

+ (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIView *v = pan.view;
    CGPoint p = [pan translationInView:v.superview];
    v.center = CGPointMake(v.center.x + p.x, v.center.y + p.y);
    [pan setTranslation:CGPointZero inView:v.superview];
    if (pan.state == UIGestureRecognizerStateEnded) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setDouble:v.center.x forKey:@"XHSR_EntryX"];
        [d setDouble:v.center.y forKey:@"XHSR_EntryY"];
        [d synchronize];
    }
}

@end
