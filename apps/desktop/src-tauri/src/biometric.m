#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

int secwet_biometric_available(void) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
            return 1; // Biometrics (Touch ID) available
        }
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            return 2; // Passcode / system authentication available
        }
        return 0; // Not available
    }
}

int secwet_authenticate_biometrics(const char *reason_utf8) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            return 1; // Not supported / not enrolled
        }
        
        NSString *reason = reason_utf8 ? [NSString stringWithUTF8String:reason_utf8] : @"Unlock Secwet";
        if (!reason || [reason length] == 0) {
            reason = @"Unlock Secwet";
        }
        
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block int status = 2; // Default to error
        
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication localizedReason:reason reply:^(BOOL success, NSError * _Nullable authError) {
            if (success) {
                status = 0; // Success
            } else if (authError && authError.code == LAErrorUserCancel) {
                status = 3; // Cancelled by user
            } else {
                status = 2; // Auth failed
            }
            dispatch_semaphore_signal(sema);
        }];
        
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        return status;
    }
}
