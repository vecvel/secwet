// macOS LocalAuthentication bridge for src/biometric/macos.rs.
//
// Kind codes: 0 none, 1 Touch ID, 2 Face ID, 3 Optic ID.
// Verify codes: 0 success, 1 unavailable, 2 failed, 3 cancelled, 4 other.

#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

static int secwet_kind_code(LABiometryType type) {
    switch (type) {
        case LABiometryTypeTouchID:
            return 1;
        case LABiometryTypeFaceID:
            return 2;
        default:
            break;
    }
    if (@available(macOS 14.0, *)) {
        if (type == LABiometryTypeOpticID) {
            return 3;
        }
    }
    return 0;
}

int secwet_biometric_kind(void) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
            return secwet_kind_code(context.biometryType);
        }
        // Locked out after failed attempts: the sensor is still enrolled, and
        // the system prompt offers the account password. Reporting it as
        // missing would let repeated failures skip the check.
        if (error && error.code == LAErrorBiometryLockout) {
            return secwet_kind_code(context.biometryType);
        }
        return 0;
    }
}

int secwet_biometric_verify(const char *reason_utf8) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        // Biometrics first, with the account password as the system fallback,
        // so a failing sensor never locks the user out.
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            return 1;
        }

        NSString *reason = reason_utf8 ? [NSString stringWithUTF8String:reason_utf8] : nil;
        if (reason.length == 0) {
            reason = @"unlock Secwet";
        }

        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block int status = 4;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:reason
                          reply:^(BOOL success, NSError *_Nullable authError) {
            if (success) {
                status = 0;
            } else {
                switch (authError.code) {
                    case LAErrorUserCancel:
                    case LAErrorSystemCancel:
                    case LAErrorAppCancel:
                        status = 3;
                        break;
                    case LAErrorAuthenticationFailed:
                        status = 2;
                        break;
                    case LAErrorBiometryNotAvailable:
                    case LAErrorBiometryNotEnrolled:
                    case LAErrorPasscodeNotSet:
                        status = 1;
                        break;
                    default:
                        status = 4;
                        break;
                }
            }
            dispatch_semaphore_signal(done);
        }];
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
        return status;
    }
}
