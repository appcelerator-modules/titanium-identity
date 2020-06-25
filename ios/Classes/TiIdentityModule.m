/**
 * Ti.Identity
 *
 * Created by Hans Knoechel
 * Copyright (c) 2017-present by Axway. All rights reserved.
 */

#import "TiIdentityModule.h"
#import "TiBase.h"
#import "TiHost.h"
#import "TiUtils.h"

@implementation TiIdentityModule

#pragma mark Internal

- (id)moduleGUID
{
  return @"c3d987a8-8bd4-42cd-a3e4-2a75952d1ea0";
}

// This is generated for your module, please do not change it
- (NSString *)moduleId
{
  return @"ti.identity";
}

- (NSString *)apiName
{
  return @"Ti.Identity";
}

#pragma mark Lifecycle

- (void)startup
{
  [super startup];
  NSLog(@"[DEBUG] %@ loaded", self);
}

- (id)_initWithPageContext:(id<TiEvaluator>)context
{
  if (self = [super _initWithPageContext:context]) {
    _authPolicy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
  }

  return self;
}

- (LAContext *)authContext
{
  if (!_authContext) {
    _authContext = [LAContext new];
  }

  return _authContext;
}

#pragma mark Public API

- (void)setAuthenticationPolicy:(id)value
{
  ENSURE_TYPE(value, NSNumber);
  _authPolicy = [TiUtils intValue:value def:LAPolicyDeviceOwnerAuthenticationWithBiometrics];
}

- (NSNumber *)biometryType
{
  if ([TiUtils isIOSVersionOrGreater:@"11.0"]) {
    return NUMINT([[self authContext] biometryType]);
  } else {
    NSLog(@"[ERROR] Ti.Identity.biometryType is only available on iOS 11 and later!");
    return NUMINT(-1);
  }
}

- (id)authenticationPolicy
{
  return NUMINTEGER(_authPolicy ?: LAPolicyDeviceOwnerAuthenticationWithBiometrics);
}

- (NSNumber *)isSupported:(id)unused
{
  if (![TiUtils isIOS8OrGreater]) {
    return NUMBOOL(NO);
  }

  __block BOOL isSupported = NO;

  TiThreadPerformOnMainThread(^{
    isSupported = [[self authContext] canEvaluatePolicy:_authPolicy error:nil];
  },
      YES);

  return NUMBOOL(isSupported);
}

- (void)authenticate:(id)args
{
  ENSURE_SINGLE_ARG(args, NSDictionary);

  NSError *authError = nil;
  NSString *reason = [TiUtils stringValue:[args valueForKey:@"reason"]];
  NSDictionary *isSupportedDict = [self deviceCanAuthenticate:nil];
  KrollCallback *callback = [args valueForKey:@"callback"];
  id allowableReuseDuration = [args valueForKey:@"allowableReuseDuration"];
  id fallbackTitle = [args valueForKey:@"fallbackTitle"];
  id cancelTitle = [args valueForKey:@"cancelTitle"];
  BOOL keepAlive = [TiUtils boolValue:@"keepAlive" properties:args def:YES];

  if (![callback isKindOfClass:[KrollCallback class]]) {
    NSLog(@"[WARN] Ti.Identity: The parameter `callback` in `authenticate` must be a function.");
    return;
  }

  [self replaceValue:callback forKey:@"callback" notification:NO];

  // Fail when Touch ID is not supported by the current device
  if ([isSupportedDict valueForKey:@"canAuthenticate"] == NUMBOOL(NO)) {
    TiThreadPerformOnMainThread(^{
      NSDictionary *event = @{
        @"error" : [isSupportedDict valueForKey:@"error"],
        @"code" : [isSupportedDict valueForKey:@"code"],
        @"success" : NUMBOOL(NO)
      };

      [self fireCallback:@"callback" withArg:event withSource:self];
    },
        NO);
    return;
  }

  // iOS 9: Expose failure behavior
  if ([TiUtils isIOS9OrGreater]) {
    if (allowableReuseDuration) {
      [[self authContext] setTouchIDAuthenticationAllowableReuseDuration:[TiUtils doubleValue:allowableReuseDuration]];
    }
  }

  // iOS 10: Expose support for localized titles
  if ([TiUtils isIOS10OrGreater]) {
    if (fallbackTitle) {
      [[self authContext] setLocalizedFallbackTitle:[TiUtils stringValue:fallbackTitle]];
    }

    if (cancelTitle) {
      [[self authContext] setLocalizedCancelTitle:[TiUtils stringValue:cancelTitle]];
    }
  }

  // Display the dialog if the security policy allows it (= device has Touch ID enabled)
  if ([[self authContext] canEvaluatePolicy:_authPolicy error:&authError]) {
    TiThreadPerformOnMainThread(^{
      [[self authContext] evaluatePolicy:_authPolicy
                         localizedReason:reason
                                   reply:^(BOOL success, NSError *error) {
                                     NSMutableDictionary *event = [NSMutableDictionary dictionary];

                                     if (error != nil) {
                                       [event setValue:[error localizedDescription] forKey:@"error"];
                                       [event setValue:NUMINTEGER([error code]) forKey:@"code"];
                                     }

                                     [event setValue:NUMBOOL(success) forKey:@"success"];

                                     // TIMOB-24489: Use this callback invocation to prevent issues with Kroll-Thread
                                     // and proxies that open another thread (e.g. Ti.Network)
                                     [self fireCallback:@"callback" withArg:event withSource:self];

                                     if (!keepAlive) {
                                       _authContext = nil;
                                     }
                                   }];
    },
        NO);

    return;
  }

  // Again, make sure the callback function runs on the main thread
  TiThreadPerformOnMainThread(^{
    NSMutableDictionary *event = [NSMutableDictionary dictionary];
    if (authError != nil) {
      [event setValue:[authError localizedDescription] forKey:@"error"];
      [event setValue:NUMINTEGER([authError code]) forKey:@"code"];
    } else {
      [event setValue:@"Can not evaluate Touch ID" forKey:@"error"];
      [event setValue:NUMINTEGER(1) forKey:@"code"];
    }

    [event setValue:NUMBOOL(NO) forKey:@"success"];
    [self fireCallback:@"callback" withArg:event withSource:self];
  },
      NO);
}

- (void)invalidate:(id)unused
{
  if (!_authContext) {
    NSLog(@"[ERROR] Ti.Identity: Cannot invalidate a Touch ID instance that does not exist. Use 'authenticate' before calling this.");
    return;
  }

  if ([TiUtils isIOS9OrGreater]) {
    [_authContext invalidate];
  }

  _authContext = nil;
}

- (NSDictionary *)deviceCanAuthenticate:(id)unused
{
  if (![TiUtils isIOS8OrGreater]) {
    return @{
      @"error" : @"The method `deviceCanAuthenticate` is only available in iOS 8 and later.",
      @"code" : [self ERROR_TOUCH_ID_NOT_AVAILABLE],
      @"canAuthenticate" : NUMBOOL(NO)
    };
  }

  NSError *authError = nil;
  BOOL canAuthenticate = [[self authContext] canEvaluatePolicy:_authPolicy error:&authError];
  NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:@{
    @"canAuthenticate" : NUMBOOL(canAuthenticate)
  }];

  if (authError != nil) {
    [result setValue:[TiUtils messageFromError:authError] forKey:@"error"];
    [result setValue:NUMINTEGER([authError code]) forKey:@"code"];
  }

  return result;
}

#pragma mark Constants

MAKE_SYSTEM_PROP(ERROR_TOUCH_ID_LOCKOUT, LAErrorTouchIDLockout);
MAKE_SYSTEM_PROP(ERROR_INVALID_CONTEXT, LAErrorInvalidContext);
MAKE_SYSTEM_PROP(ERROR_APP_CANCELLED, LAErrorAppCancel);
MAKE_SYSTEM_PROP(ERROR_TOUCH_ID_NOT_ENROLLED, LAErrorTouchIDNotEnrolled);
MAKE_SYSTEM_PROP(ERROR_TOUCH_ID_NOT_AVAILABLE, LAErrorTouchIDNotAvailable);
MAKE_SYSTEM_PROP(ERROR_PASSCODE_NOT_SET, LAErrorPasscodeNotSet);
MAKE_SYSTEM_PROP(ERROR_SYSTEM_CANCEL, LAErrorSystemCancel);
MAKE_SYSTEM_PROP(ERROR_USER_FALLBACK, LAErrorUserFallback);
MAKE_SYSTEM_PROP(ERROR_USER_CANCEL, LAErrorUserCancel);
MAKE_SYSTEM_PROP(ERROR_AUTHENTICATION_FAILED, LAErrorAuthenticationFailed);

#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 110000
MAKE_SYSTEM_PROP(ERROR_BIOMETRY_NOT_AVAILABLE, LAErrorBiometryNotAvailable);
MAKE_SYSTEM_PROP(ERROR_BIOMETRY_NOT_ENROLLED, LAErrorBiometryNotEnrolled);
MAKE_SYSTEM_PROP(ERROR_BIOMETRY_LOCKOUT, LAErrorBiometryLockout);

MAKE_SYSTEM_PROP(BIOMETRY_TYPE_NONE, LABiometryNone);
MAKE_SYSTEM_PROP(BIOMETRY_TYPE_TOUCH_ID, LABiometryTypeTouchID);
MAKE_SYSTEM_PROP(BIOMETRY_TYPE_FACE_ID, LABiometryTypeFaceID);
#endif

MAKE_SYSTEM_STR(ACCESSIBLE_WHEN_UNLOCKED, kSecAttrAccessibleWhenUnlocked);
MAKE_SYSTEM_STR(ACCESSIBLE_AFTER_FIRST_UNLOCK, kSecAttrAccessibleAfterFirstUnlock);
MAKE_SYSTEM_STR(ACCESSIBLE_ALWAYS, kSecAttrAccessibleAlways);
MAKE_SYSTEM_STR(ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly);
MAKE_SYSTEM_STR(ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
MAKE_SYSTEM_STR(ACCESSIBLE_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
MAKE_SYSTEM_STR(ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY, kSecAttrAccessibleAlwaysThisDeviceOnly);

MAKE_SYSTEM_PROP(ACCESS_CONTROL_USER_PRESENCE, 1); // kSecAccessControlUserPresence
MAKE_SYSTEM_PROP(ACCESS_CONTROL_TOUCH_ID_ANY, 2); // kSecAccessControlTouchIDAny
MAKE_SYSTEM_PROP(ACCESS_CONTROL_TOUCH_ID_CURRENT_SET, 8); // kSecAccessControlTouchIDCurrentSet
MAKE_SYSTEM_PROP(ACCESS_CONTROL_DEVICE_PASSCODE, 16); // kSecAccessControlDevicePasscode
MAKE_SYSTEM_PROP(ACCESS_CONTROL_OR, 16384); // kSecAccessControlOr
MAKE_SYSTEM_PROP(ACCESS_CONTROL_AND, 32768); // kSecAccessControlAnd
MAKE_SYSTEM_PROP(ACCESS_CONTROL_PRIVATE_KEY_USAGE, 1073741824); // kSecAccessControlPrivateKeyUsage
MAKE_SYSTEM_PROP(ACCESS_CONTROL_APPLICATION_PASSWORD, 2147483648); // kSecAccessControlApplicationPassword

MAKE_SYSTEM_PROP(AUTHENTICATION_POLICY_BIOMETRICS, LAPolicyDeviceOwnerAuthenticationWithBiometrics);
MAKE_SYSTEM_PROP(AUTHENTICATION_POLICY_PASSCODE, LAPolicyDeviceOwnerAuthentication);
#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 130000
MAKE_SYSTEM_PROP(AUTHENTICATION_POLICY_BIOMETRICS_OR_WATCH, kLAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch);
MAKE_SYSTEM_PROP(AUTHENTICATION_POLICY_WATCH, kLAPolicyDeviceOwnerAuthenticationWithWatch);
#endif

@end
