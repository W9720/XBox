// XBookEnhancer - 小红书 (com.xingin.discover 9.55) 功能复刻
// 仅使用逆向确证的真实类名 / selector，未确证部分以 TODO 标注。
// 环境：Dopamine rootless / iOS 15+ / arm64 / Theos

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Photos/Photos.h>

// 设置面板（Menu.m）
@interface XBEFloatingEntry : NSObject
+ (void)install;
@end
#import <AVFoundation/AVFoundation.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>

#pragma mark - 反注入检测：对 App 隐藏本插件镜像

// 实测：原插件与复刻插件在同一台设备/同一版本 App 上都会被判为“版本过低/无网络”，
// 说明触发点是“运行时有第三方 dylib 被加载”，而不是某个具体 Hook。
// 这里把本插件从 dyld 镜像枚举中摘掉（真实符号，内联 Hook，不依赖 symbol rebinding）。

typedef uint32_t (*XBEImageCountFn)(void);
typedef const char *(*XBEImageNameFn)(uint32_t);
typedef const struct mach_header *(*XBEImageHeaderFn)(uint32_t);
typedef intptr_t (*XBEImageSlideFn)(uint32_t);
typedef void (*XBEHookFunctionFn)(void *symbol, void *replace, void **result);

static XBEImageCountFn XBEOrigCount = NULL;
static XBEImageNameFn XBEOrigName = NULL;
static XBEImageHeaderFn XBEOrigHeader = NULL;
static XBEImageSlideFn XBEOrigSlide = NULL;
static int XBEHiddenIndex = -1;
static BOOL XBEHiderInstalled = NO;

// objc_copyImageNames 拦截（App 实测走这条路能看到本插件）
typedef const char **(*XBECopyImageNamesFn)(unsigned int *);
static XBECopyImageNamesFn XBEOrigCopyImageNames = NULL;
static volatile NSUInteger gXBEObjcScanCount = 0;

static const char **XBECopyImageNamesProxy(unsigned int *outCount) {
    gXBEObjcScanCount++;
    unsigned int total = 0;
    const char **original = XBEOrigCopyImageNames ? XBEOrigCopyImageNames(&total) : NULL;
    if (!original) {
        if (outCount) *outCount = 0;
        return NULL;
    }
    // 返回全新分配的数组/字符串，符合 objc_copyImageNames 的调用方释放契约，同时过滤自身
    const char **filtered = (const char **)calloc((size_t)total + 1, sizeof(char *));
    unsigned int kept = 0;
    for (unsigned int i = 0; i < total; i++) {
        const char *path = original[i];
        if (!path) continue;
        if (strstr(path, "XBookEnhancer") || strstr(path, "XHS.J")) continue;
        filtered[kept++] = strdup(path);
    }
    filtered[kept] = NULL;
    if (outCount) *outCount = kept;
    return filtered;
}

// 越狱路径探测（只统计，不改变返回值）
static volatile NSUInteger gXBEPathProbeCount = 0;
static volatile BOOL gXBEDiagSuppress = NO;
static char gXBEPathProbeLast[512] = {0};

static BOOL XBEPathLooksSuspicious(const char *path) {
    if (!path) return NO;
    static const char *needles[] = {
        "/var/jb", "MobileSubstrate", "libsubstrate", "libhooker", "ellekit",
        "Cydia", "Sileo", "cycript", "frida", "/etc/apt", "/var/lib/dpkg",
        "/bin/bash", "/usr/sbin/sshd", "TweakInject", "DynamicLibraries"
    };
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
        if (strstr(path, needles[i])) return YES;
    }
    return NO;
}

static void XBERecordPathProbe(const char *path) {
    if (gXBEDiagSuppress || !XBEPathLooksSuspicious(path)) return;
    gXBEPathProbeCount++;
    size_t len = strlen(path);
    if (len > sizeof(gXBEPathProbeLast) - 1) len = sizeof(gXBEPathProbeLast) - 1;
    memcpy(gXBEPathProbeLast, path, len);
    gXBEPathProbeLast[len] = 0;
}

typedef int (*XBEStatFn)(const char *, struct stat *);
typedef int (*XBEAccessFn)(const char *, int);
static XBEStatFn XBEOrigStat = NULL;
static XBEStatFn XBEOrigLstat = NULL;
static XBEAccessFn XBEOrigAccess = NULL;

static int XBEStatProxy(const char *path, struct stat *buf) {
    XBERecordPathProbe(path);
    if (XBEPathLooksSuspicious(path)) { errno = ENOENT; return -1; }
    return XBEOrigStat ? XBEOrigStat(path, buf) : -1;
}

static int XBELstatProxy(const char *path, struct stat *buf) {
    XBERecordPathProbe(path);
    if (XBEPathLooksSuspicious(path)) { errno = ENOENT; return -1; }
    return XBEOrigLstat ? XBEOrigLstat(path, buf) : -1;
}

static int XBEAccessProxy(const char *path, int mode) {
    XBERecordPathProbe(path);
    if (XBEPathLooksSuspicious(path)) { errno = ENOENT; return -1; }
    return XBEOrigAccess ? XBEOrigAccess(path, mode) : -1;
}

// 运行时探测数据（设置页“诊断”分区展示）
static volatile NSUInteger gXBEDyldScanCount = 0;
static volatile NSUInteger gXBEDetectCalls[8] = {0};
static NSString *const kXBEDetectLabels[8] = {
    @"MOBFDevice.hasJailBroken",
    @"XYDevice.isJailbroken",
    @"XYDevice.onceJailbroken",
    @"XYFoundationTools.jailBreaked",
    @"XYFoundationTools.isRooted",
    @"XYFoundationTools.isBeingDebug",
    @"KeychainStore.readJailBreakFile",
    @"SVCMSecverify.setIs_jail",
};

static uint32_t XBEMappedImageIndex(uint32_t index) {
    if (XBEHiddenIndex < 0) return index;
    return (index >= (uint32_t)XBEHiddenIndex) ? index + 1 : index;
}

static uint32_t XBEImageCountProxy(void) {
    gXBEDyldScanCount++;
    uint32_t count = XBEOrigCount ? XBEOrigCount() : 0;
    return (XBEHiddenIndex >= 0 && count > 0) ? count - 1 : count;
}

static const char *XBEImageNameProxy(uint32_t index) {
    return XBEOrigName ? XBEOrigName(XBEMappedImageIndex(index)) : NULL;
}

static const struct mach_header *XBEImageHeaderProxy(uint32_t index) {
    return XBEOrigHeader ? XBEOrigHeader(XBEMappedImageIndex(index)) : NULL;
}

static intptr_t XBEImageSlideProxy(uint32_t index) {
    return XBEOrigSlide ? XBEOrigSlide(XBEMappedImageIndex(index)) : 0;
}

static void XBEInstallImageHider(void) {
    if (XBEHiderInstalled) return;

    void *symCount = dlsym(RTLD_DEFAULT, "_dyld_image_count");
    void *symName = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    void *symHeader = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    void *symSlide = dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
    XBEHookFunctionFn hookFn = (XBEHookFunctionFn)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!hookFn || !symCount || !symName) {
        NSLog(@"[XBookEnhancer] image hider unavailable (hook=%p count=%p name=%p)", hookFn, symCount, symName);
        return;
    }

    // 先定位自己的镜像下标（此时还未 Hook）
    uint32_t total = ((XBEImageCountFn)symCount)();
    for (uint32_t i = 0; i < total; i++) {
        const char *path = ((XBEImageNameFn)symName)(i);
        if (!path) continue;
        if (strstr(path, "XBookEnhancer") || strstr(path, "XHS.J")) {
            XBEHiddenIndex = (int)i;
            break;
        }
    }
    if (XBEHiddenIndex < 0) {
        NSLog(@"[XBookEnhancer] own image not found, skip hiding");
        return;
    }

    hookFn(symCount, (void *)XBEImageCountProxy, (void **)&XBEOrigCount);
    hookFn(symName, (void *)XBEImageNameProxy, (void **)&XBEOrigName);
    if (symHeader) hookFn(symHeader, (void *)XBEImageHeaderProxy, (void **)&XBEOrigHeader);
    if (symSlide) hookFn(symSlide, (void *)XBEImageSlideProxy, (void **)&XBEOrigSlide);
    void *symObjcNames = dlsym(RTLD_DEFAULT, "objc_copyImageNames");
    if (symObjcNames) hookFn(symObjcNames, (void *)XBECopyImageNamesProxy, (void **)&XBEOrigCopyImageNames);

    // 越狱路径探测（只观察，不改返回值）
    void *symStat = dlsym(RTLD_DEFAULT, "stat");
    void *symLstat = dlsym(RTLD_DEFAULT, "lstat");
    void *symAccess = dlsym(RTLD_DEFAULT, "access");
    if (symStat) hookFn(symStat, (void *)XBEStatProxy, (void **)&XBEOrigStat);
    if (symLstat) hookFn(symLstat, (void *)XBELstatProxy, (void **)&XBEOrigLstat);
    if (symAccess) hookFn(symAccess, (void *)XBEAccessProxy, (void **)&XBEOrigAccess);

    XBEHiderInstalled = YES;
    NSLog(@"[XBookEnhancer] own image hidden at dyld index %d", XBEHiddenIndex);
}

#pragma mark - 运行时探测（设置页“诊断”分区使用）

NSArray<NSArray<NSString *> *> *XBEDiagRuntimeItems(void) {
    NSMutableArray *items = [NSMutableArray array];

    void *hookFn = dlsym(RTLD_DEFAULT, "MSHookFunction");
    [items addObject:@[@"MSHookFunction", hookFn ? @"可用" : @"不可用"]];
    [items addObject:@[@"镜像隐藏", XBEHiderInstalled ? @"已生效" : @"未生效"]];

    uint32_t realCount = XBEOrigCount ? XBEOrigCount() : _dyld_image_count();
    uint32_t appCount = _dyld_image_count();
    [items addObject:@[@"dyld 真实镜像数", [NSString stringWithFormat:@"%u", realCount]]];
    [items addObject:@[@"App 可见镜像数", [NSString stringWithFormat:@"%u", appCount]]];
    [items addObject:@[@"App 枚举 dyld 次数", [NSString stringWithFormat:@"%lu", (unsigned long)gXBEDyldScanCount]]];
    [items addObject:@[@"App 枚举 objc 次数", [NSString stringWithFormat:@"%lu", (unsigned long)gXBEObjcScanCount]]];

    BOOL dyldVisible = NO;
    for (uint32_t i = 0; i < appCount; i++) {
        const char *path = _dyld_get_image_name(i);
        if (path && strstr(path, "XBookEnhancer")) { dyldVisible = YES; break; }
    }
    [items addObject:@[@"dyld 列表含本插件", dyldVisible ? @"是（异常）" : @"否"]];

    unsigned int objcCount = 0;
    const char **objcNames = objc_copyImageNames(&objcCount);
    BOOL objcVisible = NO;
    if (objcNames) {
        for (unsigned int i = 0; i < objcCount; i++) {
            if (objcNames[i] && strstr(objcNames[i], "XBookEnhancer")) { objcVisible = YES; break; }
        }
    }
    [items addObject:@[@"objc 列表含本插件", objcVisible ? @"是（异常）" : @"否"]];

    NSFileManager *fm = [NSFileManager defaultManager];
    gXBEDiagSuppress = YES;
    [items addObject:@[@"/var/jb 存在", [fm fileExistsAtPath:@"/var/jb"] ? @"是" : @"否"]];
    BOOL substrate = [fm fileExistsAtPath:@"/var/jb/usr/lib/libsubstrate.dylib"] ||
                     [fm fileExistsAtPath:@"/usr/lib/libsubstrate.dylib"];
    [items addObject:@[@"libsubstrate 存在", substrate ? @"是" : @"否"]];
    gXBEDiagSuppress = NO;

    [items addObject:@[@"App 查越狱路径次数", [NSString stringWithFormat:@"%lu", (unsigned long)gXBEPathProbeCount]]];
    NSString *lastProbe = gXBEPathProbeLast[0] ? [NSString stringWithUTF8String:gXBEPathProbeLast] : @"无";
    [items addObject:@[@"最后一次可疑路径", lastProbe.length ? lastProbe : @"无"]];

    for (NSUInteger i = 0; i < 8; i++) {
        [items addObject:@[[NSString stringWithFormat:@"%@ 被调用", kXBEDetectLabels[i]],
                           [NSString stringWithFormat:@"%lu", (unsigned long)gXBEDetectCalls[i]]]];
    }
    return items;
}

#pragma mark - 通用工具

static BOOL XHSREnabled(NSString *key) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    id v = [d objectForKey:key];
    if (!v) return YES; // 默认开启
    return [d boolForKey:key];
}

// 逆向确证：保存/去水印总开关为 XHS_SaveMediaWithoutWatermark（运行时异或解密得到）
static BOOL XHSRSaveWithoutWatermark(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    id v = [d objectForKey:@"XHS_SaveMediaWithoutWatermark"];
    if (v) return [d boolForKey:@"XHS_SaveMediaWithoutWatermark"];
    return XHSREnabled(@"XHSR_SaveBypass");
}

static NSURL *XHSRURLFromObject(id obj, int depth);

// 从对象候选属性里找语音/媒体 URL（用于评论语音、表情等）
static NSURL *XHSRURLByProbingObject(id obj, NSArray<NSString *> *keys) {
    if (!obj) return nil;
    for (NSString *key in keys) {
        id v = nil;
        @try { v = [obj valueForKey:key]; } @catch (__unused NSException *e) {}
        NSURL *u = XHSRURLFromObject(v, 0);
        if (u) return u;
    }
    return nil;
}

// 在视图层级里找最近的 UIImageView 图片
static UIImage *XHSRImageInHierarchy(UIView *view, int depth) {
    if (!view || depth > 5) return nil;
    if ([view isKindOfClass:[UIImageView class]] && ((UIImageView *)view).image) {
        return ((UIImageView *)view).image;
    }
    for (UIView *sub in view.subviews) {
        UIImage *img = XHSRImageInHierarchy(sub, depth + 1);
        if (img) return img;
    }
    return nil;
}

// 给任意视图挂一个“保存”小按钮（评论语音/表情共用）
static const NSInteger kXBEInlineSaveTag = 0x58424531;

static void XHSRAttachInlineSaveButton(UIView *host, id target, SEL action) {
    if (!host || [host viewWithTag:kXBEInlineSaveTag]) return;
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.tag = kXBEInlineSaveTag;
    [button setImage:[UIImage systemImageNamed:@"arrow.down.circle"] forState:UIControlStateNormal];
    button.tintColor = [UIColor whiteColor];
    button.frame = CGRectMake(host.bounds.size.width - 28.0, (host.bounds.size.height - 24.0) / 2.0, 24.0, 24.0);
    button.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    [button addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    [host addSubview:button];
}

// 破坏性开关（隐藏 Tab）默认关闭
static BOOL XHSREnabledDefaultNo(NSString *key) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    id v = [d objectForKey:key];
    if (!v) return NO;
    return [d boolForKey:key];
}

// 广告/开屏清理：会改动 App 自身的模型装配，必须严格受开关控制
static BOOL XHSRAdsRemovalEnabled(void) {
    return XHSREnabledDefaultNo(@"XHS_RemoveAdsAndSponsors");
}

// 自动命名时间戳（对应 XHS_AutomaticFileNaming）
static NSString *XHSRDateName(void) {
    static NSDateFormatter *fmt;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [NSDateFormatter new];
        fmt.dateFormat = @"yyyyMMdd_HHmmss";
    });
    return [fmt stringFromDate:[NSDate date]];
}

// 从任意对象（NSString/NSDictionary/NSArray）里递归找第一个 http(s) URL
static NSURL *XHSRURLFromObject(id obj, int depth) {
    if (!obj || depth > 6) return nil;
    if ([obj isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)obj;
        if ([s hasPrefix:@"http://"] || [s hasPrefix:@"https://"]) return [NSURL URLWithString:s];
        NSData *data = [s dataUsingEncoding:NSUTF8StringEncoding];
        if (data.length && ([s hasPrefix:@"{"] || [s hasPrefix:@"["])) {
            id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json) return XHSRURLFromObject(json, depth + 1);
        }
        return nil;
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        for (id key in (NSDictionary *)obj) {
            NSURL *u = XHSRURLFromObject(((NSDictionary *)obj)[key], depth + 1);
            if (u) return u;
        }
        return nil;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        for (id v in (NSArray *)obj) {
            NSURL *u = XHSRURLFromObject(v, depth + 1);
            if (u) return u;
        }
    }
    return nil;
}

static id XHSRSafeValue(id obj, NSString *key) {
    if (!obj) return nil;
    @try {
        return [obj valueForKey:key];
    } @catch (__unused NSException *e) {
        return nil;
    }
}

static NSArray *XHSRSafeArray(id obj, NSString *key) {
    id v = XHSRSafeValue(obj, key);
    return [v isKindOfClass:[NSArray class]] ? v : nil;
}

static NSURL *XHSRURL(id v) {
    if (!v) return nil;
    if ([v isKindOfClass:[NSURL class]]) return v;
    if ([v isKindOfClass:[NSString class]]) return [NSURL URLWithString:v];
    @try {
        if ([v respondsToSelector:@selector(absoluteString)]) {
            return [NSURL URLWithString:[v absoluteString]];
        }
        NSString *s = [v description];
        if (s.length) return [NSURL URLWithString:s];
    } @catch (__unused NSException *e) {}
    return nil;
}

static NSString *XHSRSafeFileName(NSString *name, NSString *fallback) {
    NSString *base = name.length ? name : fallback;
    if (!base.length) base = [[NSUUID UUID] UUIDString];
    NSCharacterSet *bad = [NSCharacterSet characterSetWithCharactersInString:@"/\\:*?\"<>|"];
    base = [[base componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@"_"];
    return base;
}

#pragma mark - 悬浮下载通知（行为等价于原版 XHSDownloadNotice）

@interface XBookEnhancerNotice : NSObject
+ (instancetype)shared;
- (void)beginWithTitle:(NSString *)title cancellation:(void (^)(void))cancellation;
- (void)updateTitle:(NSString *)title progress:(double)progress detail:(NSString *)detail;
- (void)finishSuccess:(BOOL)success message:(NSString *)message;
- (void)dismiss;
@end

@implementation XBookEnhancerNotice {
    UIWindow *_window;
    UIView *_card;
    UILabel *_titleLabel;
    UILabel *_detailLabel;
    UIProgressView *_progressView;
    UIButton *_cancelButton;
    void (^_cancelHandler)(void);
}

+ (instancetype)shared {
    static XBookEnhancerNotice *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [XBookEnhancerNotice new]; });
    return s;
}

- (void)buildIfNeeded {
    if (_window) return;
    CGRect screen = [UIScreen mainScreen].bounds;
    _window = [[UIWindow alloc] initWithFrame:screen];
    _window.windowLevel = UIWindowLevelAlert + 10;
    _window.backgroundColor = [UIColor clearColor];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor clearColor];
    _window.rootViewController = root;

    CGFloat w = MIN(320.0, screen.size.width - 48.0);
    _card = [[UIView alloc] initWithFrame:CGRectMake((screen.size.width - w) / 2.0,
                                                    screen.size.height - 160.0,
                                                    w, 96.0)];
    _card.backgroundColor = [UIColor colorWithWhite:0.12 alpha:0.94];
    _card.layer.cornerRadius = 18.0;
    _card.layer.cornerCurve = kCACornerCurveContinuous;
    _card.layer.masksToBounds = YES;

    _titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 12, w - 80, 20)];
    _titleLabel.textColor = [UIColor whiteColor];
    _titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    _titleLabel.text = @"下载中";
    [_card addSubview:_titleLabel];

    _detailLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, w - 32, 16)];
    _detailLabel.textColor = [UIColor colorWithWhite:1.0 alpha:0.6];
    _detailLabel.font = [UIFont systemFontOfSize:12];
    _detailLabel.text = @"";
    [_card addSubview:_detailLabel];

    _progressView = [[UIProgressView alloc] initWithFrame:CGRectMake(16, 60, w - 32, 4)];
    _progressView.progressTintColor = [UIColor colorWithRed:1.0 green:0.24 blue:0.33 alpha:1.0];
    _progressView.trackTintColor = [UIColor colorWithWhite:1.0 alpha:0.15];
    [_card addSubview:_progressView];

    _cancelButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _cancelButton.frame = CGRectMake(w - 64, 8, 56, 28);
    [_cancelButton setTitle:@"取消" forState:UIControlStateNormal];
    [_cancelButton setTitleColor:[UIColor colorWithWhite:1.0 alpha:0.85] forState:UIControlStateNormal];
    _cancelButton.titleLabel.font = [UIFont systemFontOfSize:13];
    [_cancelButton addTarget:self action:@selector(cancelTapped) forControlEvents:UIControlEventTouchUpInside];
    [_card addSubview:_cancelButton];

    [root.view addSubview:_card];
    _window.hidden = NO;
}

- (void)beginWithTitle:(NSString *)title cancellation:(void (^)(void))cancellation {
    dispatch_async(dispatch_get_main_queue(), ^{
        _cancelHandler = [cancellation copy];
        [self buildIfNeeded];
        _titleLabel.text = title.length ? title : @"下载中";
        _detailLabel.text = @"";
        _progressView.progress = 0.0;
        _cancelButton.hidden = NO;
        _card.alpha = 1.0;
        _window.hidden = NO;
    });
}

- (void)updateTitle:(NSString *)title progress:(double)progress detail:(NSString *)detail {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!_window) return;
        if (title.length) _titleLabel.text = title;
        if (detail.length) _detailLabel.text = detail;
        [_progressView setProgress:(float)MAX(0.0, MIN(1.0, progress)) animated:YES];
    });
}

- (void)finishSuccess:(BOOL)success message:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!_window) return;
        _titleLabel.text = success ? @"已完成" : @"下载失败";
        _detailLabel.text = message.length ? message : @"";
        _progressView.progress = success ? 1.0 : 0.0;
        _cancelButton.hidden = YES;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self dismiss];
        });
    });
}

- (void)dismiss {
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:0.2 animations:^{
            _card.alpha = 0.0;
        } completion:^(BOOL finished) {
            _window.hidden = YES;
            _window = nil;
            _card = nil;
        }];
    });
}

- (void)cancelTapped {
    void (^h)(void) = _cancelHandler;
    _cancelHandler = nil;
    if (h) h();
    [self dismiss];
}

@end

#pragma mark - 下载引擎（行为等价于原版 MyDownload + XHSVideoDownloadJob）

typedef void (^XHSRDownloadCompletion)(NSURL *fileURL, NSError *error);
typedef void (^XHSRSaveCompletion)(BOOL success, NSError *error);

@interface XHSRTaskInfo : NSObject
@property (nonatomic, strong) NSURL *destination;
@property (nonatomic, copy) XHSRDownloadCompletion completion;
@end
@implementation XHSRTaskInfo
@end

@interface XBookEnhancerDownloader : NSObject <NSURLSessionDownloadDelegate>
+ (NSString *)downloadDirectory;
+ (BOOL)isImageFileWithExtension:(NSString *)ext;
+ (BOOL)isVideoFileWithExtension:(NSString *)ext;
+ (PHAssetCollection *)albumWithTitle:(NSString *)title;
+ (void)downloadURL:(NSURL *)url preferredName:(NSString *)name completion:(XHSRDownloadCompletion)completion;
+ (void)saveImage:(UIImage *)image preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion;
+ (void)saveImageAtFileURL:(NSURL *)fileURL preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion;
+ (void)saveVideoAtFileURL:(NSURL *)fileURL preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion;
+ (void)saveLivePhotoWithImageURL:(NSURL *)imageURL videoURL:(NSURL *)videoURL preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion;
@end

static NSURLSession *gXHSRSession = nil;
static XBookEnhancerDownloader *gXHSRDelegate = nil;
static NSMutableDictionary<NSNumber *, XHSRTaskInfo *> *gXHSRTasks = nil;

@implementation XBookEnhancerDownloader

+ (void)initializeSessionIfNeeded {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gXHSRTasks = [NSMutableDictionary dictionary];
        gXHSRDelegate = [XBookEnhancerDownloader new];
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
        cfg.timeoutIntervalForRequest = 60.0;
        cfg.timeoutIntervalForResource = 600.0;
        gXHSRSession = [NSURLSession sessionWithConfiguration:cfg
                                                     delegate:gXHSRDelegate
                                                delegateQueue:nil];
    });
}

+ (NSString *)downloadDirectory {
    NSString *dir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"XBookEnhancerDownloads"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    return dir;
}

+ (BOOL)isImageFileWithExtension:(NSString *)ext {
    static NSSet *set;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        set = [NSSet setWithObjects:@"jpg", @"jpeg", @"png", @"heic", @"heif", @"webp", @"gif", nil];
    });
    return ext.length ? [set containsObject:[ext lowercaseString]] : NO;
}

+ (BOOL)isVideoFileWithExtension:(NSString *)ext {
    static NSSet *set;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        set = [NSSet setWithObjects:@"mp4", @"mov", @"m4v", @"mkv", @"webm", nil];
    });
    return ext.length ? [set containsObject:[ext lowercaseString]] : NO;
}

+ (void)downloadURL:(NSURL *)url preferredName:(NSString *)name completion:(XHSRDownloadCompletion)completion {
    if (!url) {
        if (completion) completion(nil, [NSError errorWithDomain:@"XBookEnhancer" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"无效 URL"}]);
        return;
    }
    [self initializeSessionIfNeeded];

    NSString *ext = url.pathExtension.length ? url.pathExtension : @"bin";
    NSString *base = XHSRSafeFileName(name, url.lastPathComponent.stringByDeletingPathExtension);
    if (![base.pathExtension length]) base = [base stringByAppendingPathExtension:ext];
    if (XHSREnabledDefaultNo(@"XHS_AutomaticFileNaming")) {
        base = [NSString stringWithFormat:@"%@_%@", XHSRDateName(), base];
    }
    NSURL *dest = [NSURL fileURLWithPath:[[self downloadDirectory] stringByAppendingPathComponent:base]];

    XHSRTaskInfo *info = [XHSRTaskInfo new];
    info.destination = dest;
    info.completion = completion;

    NSURLSessionDownloadTask *task = [gXHSRSession downloadTaskWithURL:url];
    if (!task) {
        if (completion) completion(nil, [NSError errorWithDomain:@"XBookEnhancer" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"创建任务失败"}]);
        return;
    }
    @synchronized (gXHSRTasks) {
        gXHSRTasks[@(task.taskIdentifier)] = info;
    }

    [[XBookEnhancerNotice shared] beginWithTitle:@"下载中" cancellation:^{
        [task cancel];
    }];
    [task resume];
}

+ (void)handleFinishedTask:(NSURLSessionDownloadTask *)task location:(NSURL *)location error:(NSError *)error {
    XHSRTaskInfo *info = nil;
    @synchronized (gXHSRTasks) {
        info = gXHSRTasks[@(task.taskIdentifier)];
        [gXHSRTasks removeObjectForKey:@(task.taskIdentifier)];
    }
    if (!info) return;

    if (error || !location) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [[XBookEnhancerNotice shared] finishSuccess:NO message:error.localizedDescription];
        });
        if (info.completion) info.completion(nil, error ?: [NSError errorWithDomain:@"XBookEnhancer" code:-2 userInfo:nil]);
        return;
    }

    NSURL *dest = info.destination;
    NSError *moveError = nil;
    [[NSFileManager defaultManager] removeItemAtURL:dest error:nil];
    BOOL ok = [[NSFileManager defaultManager] moveItemAtURL:location toURL:dest error:&moveError];
    if (!ok) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [[XBookEnhancerNotice shared] finishSuccess:NO message:moveError.localizedDescription];
        });
        if (info.completion) info.completion(nil, moveError);
        return;
    }

    NSString *ext = dest.pathExtension;
    if ([self isImageFileWithExtension:ext]) {
        [self saveImageAtFileURL:dest preferredName:nil completion:^(BOOL success, NSError *e) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[XBookEnhancerNotice shared] finishSuccess:success message:success ? @"已保存到相册" : e.localizedDescription];
            });
        }];
    } else if ([self isVideoFileWithExtension:ext]) {
        [self saveVideoAtFileURL:dest preferredName:nil completion:^(BOOL success, NSError *e) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[XBookEnhancerNotice shared] finishSuccess:success message:success ? @"已保存到相册" : e.localizedDescription];
            });
        }];
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            [[XBookEnhancerNotice shared] finishSuccess:YES message:dest.lastPathComponent];
        });
    }
    if (info.completion) info.completion(dest, nil);
}

#pragma mark NSURLSessionDownloadDelegate

- (void)URLSession:(NSURLSession *)session
      downloadTask:(NSURLSessionDownloadTask *)downloadTask
      didWriteData:(int64_t)bytesWritten
 totalBytesWritten:(int64_t)totalBytesWritten
totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite {
    if (totalBytesExpectedToWrite <= 0) return;
    double p = (double)totalBytesWritten / (double)totalBytesExpectedToWrite;
    dispatch_async(dispatch_get_main_queue(), ^{
        [[XBookEnhancerNotice shared] updateTitle:nil progress:p detail:nil];
    });
}

- (void)URLSession:(NSURLSession *)session
      downloadTask:(NSURLSessionDownloadTask *)downloadTask
didFinishDownloadingToURL:(NSURL *)location {
    // location 仅在本回调内有效，必须在返回前完成移动
    [XBookEnhancerDownloader handleFinishedTask:downloadTask location:location error:nil];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {
    if (!error) return;
    if ([error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorCancelled) return;
    [XBookEnhancerDownloader handleFinishedTask:(NSURLSessionDownloadTask *)task location:nil error:error];
}

#pragma mark 相册保存

+ (void)saveImage:(UIImage *)image preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion {
    if (!image) {
        if (completion) completion(NO, [NSError errorWithDomain:@"XBookEnhancer" code:-3 userInfo:nil]);
        return;
    }
    NSString *fn = XHSRSafeFileName(name, [[NSUUID UUID] UUIDString]);
    if (![fn.pathExtension length]) fn = [fn stringByAppendingPathExtension:@"jpg"];
    NSString *path = [[self downloadDirectory] stringByAppendingPathComponent:fn];
    NSData *data = UIImageJPEGRepresentation(image, 0.98);
    [data writeToFile:path atomically:YES];
    [self saveImageAtFileURL:[NSURL fileURLWithPath:path] preferredName:nil completion:completion];
}

// 独立相册（对应 XHS_SeparateMediaAlbums）
+ (PHAssetCollection *)albumWithTitle:(NSString *)title {
    PHFetchOptions *options = [PHFetchOptions new];
    options.predicate = [NSPredicate predicateWithFormat:@"title = %@", title];
    PHFetchResult *result = [PHAssetCollection fetchAssetCollectionsWithType:PHAssetCollectionTypeAlbum
                                                                    subtype:PHAssetCollectionSubtypeAny
                                                                    options:options];
    if (result.count > 0) return result.firstObject;

    __block PHObjectPlaceholder *placeholder = nil;
    [[PHPhotoLibrary sharedPhotoLibrary] performChangesAndWait:^{
        PHAssetCollectionChangeRequest *request =
            [PHAssetCollectionChangeRequest creationRequestForAssetCollectionWithTitle:title];
        placeholder = request.placeholderForCreatedAssetCollection;
    } error:nil];
    if (!placeholder) return nil;
    PHFetchResult *created = [PHAssetCollection fetchAssetCollectionsWithLocalIdentifiers:@[placeholder.localIdentifier]
                                                                                  options:nil];
    return created.firstObject;
}

+ (void)saveImageAtFileURL:(NSURL *)fileURL preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion {
    if (!fileURL) {
        if (completion) completion(NO, [NSError errorWithDomain:@"XBookEnhancer" code:-3 userInfo:nil]);
        return;
    }
    PHAssetCollection *album = XHSREnabledDefaultNo(@"XHS_SeparateMediaAlbums") ? [self albumWithTitle:@"小红书"] : nil;
    [[PHPhotoLibrary sharedPhotoLibrary] performChanges:^{
        PHAssetChangeRequest *request = [PHAssetChangeRequest creationRequestForAssetFromImageAtFileURL:fileURL];
        if (album) {
            PHAssetCollectionChangeRequest *albumRequest = [PHAssetCollectionChangeRequest changeRequestForAssetCollection:album];
            [albumRequest addAssets:@[request.placeholderForCreatedAsset]];
        }
    } completionHandler:^(BOOL success, NSError *error) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(success, error); });
    }];
}

+ (void)saveVideoAtFileURL:(NSURL *)fileURL preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion {
    if (!fileURL) {
        if (completion) completion(NO, [NSError errorWithDomain:@"XBookEnhancer" code:-3 userInfo:nil]);
        return;
    }
    PHAssetCollection *album = XHSREnabledDefaultNo(@"XHS_SeparateMediaAlbums") ? [self albumWithTitle:@"小红书"] : nil;
    [[PHPhotoLibrary sharedPhotoLibrary] performChanges:^{
        PHAssetChangeRequest *request = [PHAssetChangeRequest creationRequestForAssetFromVideoAtFileURL:fileURL];
        if (album) {
            PHAssetCollectionChangeRequest *albumRequest = [PHAssetCollectionChangeRequest changeRequestForAssetCollection:album];
            [albumRequest addAssets:@[request.placeholderForCreatedAsset]];
        }
    } completionHandler:^(BOOL success, NSError *error) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(success, error); });
    }];
}

+ (void)saveLivePhotoWithImageURL:(NSURL *)imageURL videoURL:(NSURL *)videoURL preferredName:(NSString *)name completion:(XHSRSaveCompletion)completion {
    if (!imageURL || !videoURL) {
        if (completion) completion(NO, [NSError errorWithDomain:@"XBookEnhancer" code:-4 userInfo:@{NSLocalizedDescriptionKey: @"LivePhoto 资源缺失"}]);
        return;
    }
    PHAssetCollection *album = XHSREnabledDefaultNo(@"XHS_SeparateMediaAlbums") ? [self albumWithTitle:@"小红书"] : nil;
    [[PHPhotoLibrary sharedPhotoLibrary] performChanges:^{
        PHAssetCreationRequest *request = [PHAssetCreationRequest creationRequestForAsset];
        [request addResourceWithType:PHAssetResourceTypePhoto fileURL:imageURL options:nil];
        PHAssetResourceCreationOptions *options = [PHAssetResourceCreationOptions new];
        options.originalFilename = @"livephoto.mov";
        [request addResourceWithType:PHAssetResourceTypePairedVideo fileURL:videoURL options:options];
        if (album) {
            PHAssetCollectionChangeRequest *albumRequest = [PHAssetCollectionChangeRequest changeRequestForAssetCollection:album];
            [albumRequest addAssets:@[request.placeholderForCreatedAsset]];
        }
    } completionHandler:^(BOOL success, NSError *error) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(success, error); });
    }];
}

@end

#pragma mark - 模块一：下载 / 保存入口

// 字体替换（对应原插件 UIViewController.viewDidAppear: -> XHSFontManager）
@interface XBookEnhancerFont : NSObject
+ (BOOL)isEnabled;
+ (void)applyToView:(UIView *)view;
@end

@implementation XBookEnhancerFont

+ (BOOL)isEnabled {
    return XHSREnabledDefaultNo(@"XHS_CustomFontEnabled");
}

+ (UIFont *)replacementFontFor:(UIFont *)font {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    CGFloat size = [d objectForKey:@"XHSR_FontSize"] ? [d doubleForKey:@"XHSR_FontSize"] : 15.0;
    NSString *name = [d stringForKey:@"XHSR_FontName"];
    UIFont *f = name.length ? [UIFont fontWithName:name size:size] : nil;
    if (!f) f = [UIFont systemFontOfSize:size];
    return f ?: font;
}

+ (void)applyToView:(UIView *)view {
    if (!view) return;
    if ([view isKindOfClass:[UILabel class]]) {
        UILabel *label = (UILabel *)view;
        if (label.font) label.font = [self replacementFontFor:label.font];
    } else if ([view isKindOfClass:[UIButton class]]) {
        UIButton *button = (UIButton *)view;
        if (button.titleLabel.font) button.titleLabel.font = [self replacementFontFor:button.titleLabel.font];
    } else if ([view isKindOfClass:[UITextField class]]) {
        UITextField *field = (UITextField *)view;
        if (field.font) field.font = [self replacementFontFor:field.font];
    } else if ([view isKindOfClass:[UITextView class]]) {
        UITextView *textView = (UITextView *)view;
        if (textView.font) textView.font = [self replacementFontFor:textView.font];
    }
    for (UIView *sub in view.subviews) {
        [self applyToView:sub];
    }
}

@end

%hook XYPBPhotoBrowser

- (BOOL)shouldShowDownloadButton {
    if (!XHSREnabled(@"XHSR_Download")) return %orig;
    return YES;
}

- (void)downloadButtonTapped:(id)sender {
    if (!XHSREnabled(@"XHSR_Download")) { %orig; return; }

    NSArray *cells = XHSRSafeArray(XHSRSafeValue(self, @"viewModel"), @"cellViewModelList");
    if (!cells.count) {
        NSURL *u = XHSRURL(XHSRSafeValue(self, @"photoURL"));
        if (u) [XBookEnhancerDownloader downloadURL:u preferredName:nil completion:nil];
        return;
    }
    for (id cell in cells) {
        NSURL *u = XHSRURL(XHSRSafeValue(cell, @"photoURL"));
        if (!u) continue;
        [XBookEnhancerDownloader downloadURL:u preferredName:nil completion:nil];
    }
}

- (void)viewDidAppear:(BOOL)animated {
    %orig;
}

%end

// 详情页保存按钮：原插件通过 class_addMethod 注入 addSaveButton / handleSaveButtonTapped
// 注意：Swift 类在运行时的真实类名为 _TtC15XYOldNoteModule19VTBaseContainerView
%hook _TtC15XYOldNoteModule19VTBaseContainerView

%new
- (void)addSaveButton {
    if (!XHSREnabled(@"XHSR_Download")) return;
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:@"保存" forState:UIControlStateNormal];
    button.frame = CGRectMake(12, 12, 64, 32);
    button.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.35];
    button.layer.cornerRadius = 16.0;
    [button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [button addTarget:self action:@selector(handleSaveButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [(UIView *)self addSubview:button];
}

%new
- (void)handleSaveButtonTapped {
    UIImage *image = nil;
    for (UIView *sub in [(UIView *)self subviews]) {
        if ([sub isKindOfClass:[UIImageView class]] && ((UIImageView *)sub).image) {
            image = ((UIImageView *)sub).image;
            break;
        }
    }
    if (image) {
        [XBookEnhancerDownloader saveImage:image preferredName:nil completion:nil];
    }
}

%end

// LivePhoto 数据提取（原插件 class_addMethod 注入）
// 运行时真实类名：_TtC12XYNoteModule20CommentLivePhotoView
%hook _TtC12XYNoteModule20CommentLivePhotoView

%new
- (NSDictionary *)extractLivePhotoData {
    id large = XHSRSafeValue(self, @"largeImageURL");
    id json = XHSRSafeValue(self, @"livePhotoMediaJson");
    NSString *image = nil;
    if ([large isKindOfClass:[NSString class]]) image = large;
    else if (large) image = [large description];

    NSString *video = nil;
    if ([json isKindOfClass:[NSDictionary class]]) {
        for (id key in json) {
            NSString *k = [key description].lowercaseString;
            if ([k containsString:@"video"]) {
                id v = json[key];
                video = [v isKindOfClass:[NSString class]] ? v : [v description];
                break;
            }
        }
    }
    if (!image.length && !video.length) return nil;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    if (image.length) result[@"imageURL"] = image;
    if (video.length) result[@"videoURL"] = video;
    return result;
}

%end

// 聊天/消息页背景：key 为确证键 XHS_ChatBackgroundEnabled
// 图片路径由默认值提供（XHSR_ChatBackgroundPath / XHSR_ChatPageBackgroundPath）
static void XHSRApplyChatBackground(UIViewController *vc) {
    if (!vc || !vc.view) return;
    NSString *cls = NSStringFromClass(vc.class);
    if (!([cls containsString:@"Chat"] || [cls containsString:@"Message"])) return;

    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    BOOL chatOn = XHSREnabledDefaultNo(@"XHS_ChatBackgroundEnabled");
    BOOL pageOn = XHSREnabledDefaultNo(@"XHSR_ChatPageBackground");
    if (!chatOn && !pageOn) return;

    BOOL isChat = [cls containsString:@"Chat"];
    NSString *pathKey = isChat ? @"XHSR_ChatBackgroundPath" : @"XHSR_ChatPageBackgroundPath";
    NSString *path = [d stringForKey:pathKey];
    if (!path.length) return;
    UIImage *image = [UIImage imageWithContentsOfFile:path];
    if (!image) return;

    NSInteger tag = isChat ? 0x58424331 : 0x58424332;
    UIImageView *background = (UIImageView *)[vc.view viewWithTag:tag];
    if (!background) {
        background = [[UIImageView alloc] initWithFrame:vc.view.bounds];
        background.tag = tag;
        background.contentMode = UIViewContentModeScaleAspectFill;
        background.clipsToBounds = YES;
        background.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [vc.view insertSubview:background atIndex:0];
    }
    background.image = image;
}

%hook UIViewController

// 对应原插件 Hook 95：viewDidAppear 后按字体功能应用自定义字体
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    if ([XBookEnhancerFont isEnabled] && self.viewIfLoaded) {
        [XBookEnhancerFont applyToView:self.viewIfLoaded];
    }
    XHSRApplyChatBackground(self);
}

%end

// 笔记模型附加属性（原插件 class_addMethod 注入）
%hook XYNoteCellModel

%new
- (id)savedViewModel {
    return objc_getAssociatedObject(self, "XHSR_savedViewModel");
}

%new
- (void)setSavedViewModel:(id)value {
    objc_setAssociatedObject(self, "XHSR_savedViewModel", value, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

%end

#pragma mark - 模块二：去水印 / 保存限制绕过

%hook XYPHMediaSaveConfig

- (BOOL)disableSave {
    if (!XHSRSaveWithoutWatermark()) return %orig;
    return YES;
}

- (BOOL)disableWatermark {
    if (!XHSRSaveWithoutWatermark()) return %orig;
    return YES;
}

- (BOOL)disableWeiboCover {
    if (!XHSRSaveWithoutWatermark()) return %orig;
    return YES;
}

%end

%hook XYVFExpManager

- (BOOL)livePhotoWatermarkSwitch {
    if (!XHSRSaveWithoutWatermark()) return %orig;
    return YES;
}

// 原实现为延迟 0.3s 再调用原实现；Logos 的 %orig 不能跨 block 使用，这里保持同步调用。
- (void)livePhotoTapToPlayBack {
    %orig;
}

%end

%hook XYImageCommentManager

- (void)saveImageWithUrl:(id)url authorId:(id)authorId {
    if (!XHSREnabled(@"XHS_EnableCommentsImageDownload")) { %orig; return; }
    NSURL *u = XHSRURL(url);
    if (!u) { %orig; return; }
    [XBookEnhancerDownloader downloadURL:u preferredName:nil completion:nil];
}

%end

// 评论区视频下载：实现来自 Hook 43（0x2280xx），数据路径 currentComment.commentVideos[index].videoInfo
%hook _TtC12XYNoteModule23CommentEntityController

- (void)saveVideoWithIndex:(NSInteger)index {
    if (!XHSREnabled(@"XHS_EnableCommentsVideoDownload")) { %orig; return; }

    NSArray *videos = nil;
    @try {
        id comment = [(NSObject *)self valueForKey:@"currentComment"];
        videos = XHSRSafeValue(comment, @"commentVideos");
    } @catch (__unused NSException *e) {}
    if (index < 0 || index >= (NSInteger)videos.count) { %orig; return; }

    id item = videos[(NSUInteger)index];
    NSURL *url = nil;
    @try {
        url = XHSRURLFromObject([item valueForKey:@"videoInfo"], 0);
    } @catch (__unused NSException *e) {}
    if (!url) {
        for (NSString *key in @[@"videoUrl", @"videoURL", @"url", @"playUrl", @"masterUrl"]) {
            @try {
                url = XHSRURLFromObject([item valueForKey:key], 0);
            } @catch (__unused NSException *e) {}
            if (url) break;
        }
    }
    if (!url) { %orig; return; }
    [XBookEnhancerDownloader downloadURL:url preferredName:nil completion:nil];
}

%end

// 评论区语音下载：逆向自 Hook 2（gate XHS_EnableCommentsVoiceDownload，按钮 arrow.down.circle）
%hook _TtC13XYCommentBase18CommentVoiceBubble

- (void)layoutSubviews {
    %orig;
    if (!XHSREnabledDefaultNo(@"XHS_EnableCommentsVoiceDownload")) return;
    XHSRAttachInlineSaveButton((UIView *)self, self, @selector(xbe_downloadVoiceTapped:));
}

- (void)xbe_downloadVoiceTapped:(UIButton *)sender {
    NSURL *url = XHSRURLByProbingObject(self, @[@"comment", @"model", @"voiceModel", @"voiceInfo",
                                                 @"voice", @"voiceUrl", @"audioUrl", @"url"]);
    if (!url) return;
    [XBookEnhancerDownloader downloadURL:url preferredName:nil completion:nil];
}

%end

// 评论区表情下载：逆向自 Hook 46（gate XHS_EnableCommentsEmojiDownload，延迟 100ms 挂按钮）
%hook _TtCC12XYNoteModule25MemePreviewPageController13AddMemeButton

- (void)didMoveToSuperview {
    %orig;
    if (!XHSREnabledDefaultNo(@"XHS_EnableCommentsEmojiDownload")) return;
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        UIView *host = ((UIView *)strongSelf).superview;
        if (!host) return;
        XHSRAttachInlineSaveButton(host, strongSelf, @selector(xbe_saveEmojiTapped:));
    });
}

- (void)xbe_saveEmojiTapped:(UIButton *)sender {
    UIImage *image = XHSRImageInHierarchy(((UIView *)self).superview, 0);
    if (!image) return;
    [XBookEnhancerDownloader saveImage:image preferredName:nil completion:nil];
}

%end

// 评论区实况图保存：逆向自 Hook 41（创建 LivePhoto 时同时落盘成对资源）
%hook XYPKLivePhotoManager

- (void)createLivePhoto2WithInputImage:(id)image inputVideoPath:(id)videoPath source:(id)source completion:(id)completion {
    %orig;
    if (!XHSREnabledDefaultNo(@"XHS_EnableCommentsImageDownload")) return;
    if (!image || ![videoPath isKindOfClass:[NSString class]]) return;

    NSData *jpeg = UIImageJPEGRepresentation((UIImage *)image, 0.95);
    if (!jpeg.length) return;
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"xbe_comment_live.jpg"];
    if (![jpeg writeToFile:tmpPath atomically:YES]) return;

    NSString *path = (NSString *)videoPath;
    NSURL *videoURL = [path hasPrefix:@"file://"] ? [NSURL URLWithString:path] : [NSURL fileURLWithPath:path];
    [XBookEnhancerDownloader saveLivePhotoWithImageURL:[NSURL fileURLWithPath:tmpPath]
                                              videoURL:videoURL
                                         preferredName:nil
                                            completion:nil];
}

%end

#pragma mark - 越狱路径隐藏（实测 App 查询 /var/jb 下路径 174 次）

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    XBERecordPathProbe(path.UTF8String);
    if (XBEPathLooksSuspicious(path.UTF8String)) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    XBERecordPathProbe(path.UTF8String);
    if (XBEPathLooksSuspicious(path.UTF8String)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (XBEPathLooksSuspicious(path.UTF8String)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    return %orig;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (XBEPathLooksSuspicious(path.UTF8String)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    return %orig;
}

%end

#pragma mark - 模块三：越狱 / 调试检测绕过

%hook MOBFDevice
+ (BOOL)hasJailBroken { gXBEDetectCalls[0]++; return NO; }
%end

%hook XYFoundationTools
+ (BOOL)jailBreaked { gXBEDetectCalls[3]++; return NO; }
+ (BOOL)onceJailbroken { return NO; }
+ (BOOL)isRooted { gXBEDetectCalls[4]++; return NO; }
+ (BOOL)isBeingDebug { gXBEDetectCalls[5]++; return NO; }
+ (BOOL)canOpenWithPath:(id)path { return NO; }
%end

%hook XYDevice
+ (BOOL)onceJailbroken { gXBEDetectCalls[2]++; return NO; }
+ (BOOL)isJailbroken { gXBEDetectCalls[1]++; return NO; }
%end

%hook KeychainStore
- (id)readJailBreakFile { gXBEDetectCalls[6]++; return nil; }
- (BOOL)writejailBreakFile:(id)value { return YES; }
- (BOOL)setLock:(BOOL)lock { return YES; }
%end

%hook SVCMSecverifyLogModel
- (void)setIs_jail:(BOOL)value { gXBEDetectCalls[7]++; %orig(NO); }
%end

#pragma mark - 模块四：广告 / 开屏清理（全部受 XHS_RemoveAdsAndSponsors 控制）

%hook XYFFNoteAdsCellController
- (void)setAdsCell:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashTrackHelper_CPT
- (void)setAds:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAPMTracker
- (void)setAdsID:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAdsResourceTask
- (void)setAds:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAdsInfo
- (void)setAds:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAdsConfig
- (void)setAdsGroups:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAdsGroupInfo_CPT
- (void)setAds:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAdsConfig_CPT
- (void)setAdsGroups:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

%hook XYPHSplashAdsOpenAppView
- (void)createSubviews {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
}
%end

%hook XYPHVideoContentAdManager
- (void)setAdsModel:(id)value {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
- (id)initWithAdvertisementModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYVFAdvertisementViewModel
- (id)initWithContentModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYFeedAdsLandingPagelnfo
- (id)initWithNativeModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYFeedAdsLandingSinglePage
- (id)initWithNativeModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYFeedAdsCellViewModel
- (id)initWithNativeModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYFeedAdsCellButtonInfo
- (id)initWithNativeModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYFeedAdsCellVideolnfo
- (id)initWithNativeModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYFeedAdsCelllmagelnfo
- (id)initWithNativeModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return nil;
}
%end

%hook XYIndepHomeFeedDataSource
- (BOOL)handleCharacteristicSplashAd {
    if (!XHSRAdsRemovalEnabled()) return %orig;
    return NO;
}
- (void)setSplashModel:(id)model {
    if (!XHSRAdsRemovalEnabled()) { %orig; return; }
    %orig(nil);
}
%end

#pragma mark - 模块五：AppDelegate / XYTabBar

%hook AppDelegate

- (BOOL)openAppCanShowSplash {
    if (XHSREnabledDefaultNo(@"XHS_RemoveAdsAndSponsors")) return NO;
    return %orig;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    return %orig;
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
}

%end

// 底部 Tab 隐藏：逻辑来自 sub_22C7C8（XYTabBar layoutSubviews 实现）
// key 与匹配串均由运行时解密确证
@interface XYTabBar : UIView
- (void)xhsr_applyTabRemoval;
- (void)xhsr_clearBadgesIfNeeded;
- (void)xhsr_hideBadgeInView:(UIView *)view depth:(NSInteger)depth;
@end

%hook XYTabBar

%new
- (void)xhsr_applyTabRemoval {
    NSArray *tabs = XHSRSafeValue(self, @"tabs");
    if (![tabs isKindOfClass:[NSArray class]] || tabs.count == 0) return;

    NSMutableArray *visible = [NSMutableArray array];
    for (id item in tabs) {
        NSString *name = XHSRSafeValue(item, @"itemName");
        if (![name isKindOfClass:[NSString class]]) name = nil;

        BOOL remove = NO;
        if (name.length) {
            if (XHSREnabledDefaultNo(@"XHS_RemoveBottomTabHot") && [name containsString:@"video"]) remove = YES;
            else if (XHSREnabledDefaultNo(@"XHS_RemoveBottomTabPlus") && [name containsString:@"post"]) remove = YES;
            else if (XHSREnabledDefaultNo(@"XHS_RemoveBottomTabMessage") && [name containsString:@"message"]) remove = YES;
            else if (XHSREnabledDefaultNo(@"XHS_RemoveBottomTabShop") && [name containsString:@"shopping"]) remove = YES;
        }

        if (remove) {
            UIView *v = [item isKindOfClass:[UIView class]] ? (UIView *)item : nil;
            @try {
                [v removeFromSuperview];
                v.frame = CGRectZero;
                v.hidden = YES;
            } @catch (__unused NSException *e) {}
        } else {
            [visible addObject:item];
        }
    }

    CGFloat count = (CGFloat)visible.count;
    if (count <= 0) return;
    UIView *bar = [(NSObject *)self isKindOfClass:[UIView class]] ? (UIView *)self : nil;
    if (!bar) return;
    CGFloat w = bar.bounds.size.width / count;
    CGFloat h = bar.bounds.size.height;
    [visible enumerateObjectsUsingBlock:^(id item, NSUInteger idx, BOOL *stop) {
        if (![item isKindOfClass:[UIView class]]) return;
        @try {
            ((UIView *)item).frame = CGRectMake(w * (CGFloat)idx, 0, w, h);
        } @catch (__unused NSException *e) {}
    }];
}

- (void)layoutSubviews {
    %orig;
    [self xhsr_applyTabRemoval];
    [self xhsr_clearBadgesIfNeeded];
}

// 首页消息/关注红点：key 来自 sub_234C70 解密表
%new
- (void)xhsr_clearBadgesIfNeeded {
    BOOL msg = XHSREnabledDefaultNo(@"XHS_RemoveHomeMessageBadge");
    BOOL follow = XHSREnabledDefaultNo(@"XHS_RemoveHomeFollowBadge");
    if (!msg && !follow) return;
    NSArray *tabs = XHSRSafeValue(self, @"tabs");
    if (![tabs isKindOfClass:[NSArray class]]) return;
    for (id item in tabs) {
        if (![item isKindOfClass:[UIView class]]) continue;
        NSString *name = XHSRSafeValue(item, @"itemName");
        if (![name isKindOfClass:[NSString class]]) continue;
        BOOL hide = NO;
        if (msg && [name containsString:@"message"]) hide = YES;
        if (follow && ([name containsString:@"follow"] || [name containsString:@"home"])) hide = YES;
        if (hide) [self xhsr_hideBadgeInView:(UIView *)item depth:0];
    }
}

%new
- (void)xhsr_hideBadgeInView:(UIView *)view depth:(NSInteger)depth {
    if (!view || depth > 4) return;
    NSString *cls = NSStringFromClass(view.class);
    if ([cls containsString:@"Badge"] || [cls containsString:@"Dot"]) {
        view.hidden = YES;
    }
    if ([view isKindOfClass:[UILabel class]]) {
        UILabel *label = (UILabel *)view;
        NSString *text = label.text;
        NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
        if (text.length > 0 && text.length <= 3 &&
            [text rangeOfCharacterFromSet:nonDigits].location == NSNotFound) {
            label.hidden = YES;
        }
    }
    for (UIView *sub in view.subviews) {
        [self xhsr_hideBadgeInView:sub depth:depth + 1];
    }
}

- (void)didMoveToWindow { %orig; }
- (void)didMoveToSuperview { %orig; }
%end

#pragma mark - 初始化

extern void showCopyrightAnimation(void);

%ctor {
    @autoreleasepool {
        XBEInstallImageHider();
        NSLog(@"[XBookEnhancer] loaded. bundle=%@ version=%@",
              [[NSBundle mainBundle] bundleIdentifier],
              [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);
        [XBEFloatingEntry install];
        showCopyrightAnimation();
    }
}
