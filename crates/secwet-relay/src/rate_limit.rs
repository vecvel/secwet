//! Rate limiting middleware and state tracking.
//!
//! Section 8.5:
//! - Per device: 20 requests per second burst 50.
//! - Per IP for unauthenticated endpoints: 10 per minute.

use governor::{
    clock::DefaultClock,
    state::keyed::DashMapStateStore,
    Quota, RateLimiter,
};
use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

pub type DeviceLimiter =
    RateLimiter<String, DashMapStateStore<String>, DefaultClock>;
pub type IpLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

#[derive(Clone)]
pub struct RateLimitManager {
    device_limiter: Arc<DeviceLimiter>,
    ip_limiter: Arc<IpLimiter>,
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitManager {
    pub fn new() -> Self {
        let quota = Quota::per_second(NonZeroU32::new(20).unwrap())
            .allow_burst(NonZeroU32::new(50).unwrap());
        let device_limiter = Arc::new(RateLimiter::dashmap(quota));

        let ip_quota = Quota::per_minute(NonZeroU32::new(10).unwrap());
        let ip_limiter = Arc::new(RateLimiter::dashmap(ip_quota));

        Self {
            device_limiter,
            ip_limiter,
        }
    }

    /// Checks if a device request is allowed.
    pub fn check_device(&self, device_id: &str) -> bool {
        self.device_limiter.check_key(&device_id.to_string()).is_ok()
    }

    /// Checks if an unauthenticated request from `ip` is allowed (10 per minute).
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        self.ip_limiter.check_key(&ip).is_ok()
    }
}
