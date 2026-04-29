//! Native macOS TouchID authentication via LAContext.
//!
//! Real implementation using `objc2-local-authentication 0.2` and `block2::RcBlock`.
//! The reply callback is a heap-allocated block that LAContext retains; the worker
//! thread initiates the call and exits immediately, while the main thread blocks
//! on a sync_channel until the system fires the callback (or 60s timeout).

#[cfg(target_os = "macos")]
pub use real::prompt_biometric;

#[cfg(not(target_os = "macos"))]
pub use stub::prompt_biometric;

#[cfg(target_os = "macos")]
mod real {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;
    use std::time::Duration;

    /// Prompt TouchID with the given reason. Blocks until user resolves
    /// (or 60s timeout). Returns Ok(true) on biometric success, Ok(false) on
    /// cancel/denied, Err for capability/internal errors.
    pub fn prompt_biometric(reason: &str) -> Result<bool, String> {
        let (tx, rx) = mpsc::sync_channel::<Result<bool, String>>(1);
        let reason_owned = reason.to_string();

        // Run the LAContext call on a dedicated thread so we don't block the
        // tokio runtime. The thread exits as soon as evaluatePolicy returns
        // (immediately, since it's async). The block keeps the channel sender
        // alive via move-capture; the system retains the block until it fires.
        std::thread::spawn(move || {
            let ctx: Retained<LAContext> = unsafe { LAContext::new() };

            // canEvaluatePolicy_error returns Result<(), Retained<NSError>>
            // — Ok(()) means biometrics are available, Err(NSError) means not.
            let can_eval = unsafe {
                ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            };
            if let Err(err) = can_eval {
                let msg = err.localizedDescription().to_string();
                let _ = tx.send(Err(format!("TouchID unavailable: {msg}")));
                return;
            }

            let reason_ns = NSString::from_str(&reason_owned);
            let tx_inner = tx.clone();

            // RcBlock::new → Retained<Block<dyn Fn(Bool, *mut NSError)>>
            // The block is heap-allocated and ref-counted; LAContext retains it
            // when we pass `&*block`, so it survives our local going out of scope.
            let block = RcBlock::new(move |success: Bool, err: *mut NSError| {
                let result = if success.as_bool() {
                    Ok(true)
                } else {
                    let msg = if err.is_null() {
                        String::from("user cancelled")
                    } else {
                        unsafe { (&*err).localizedDescription() }.to_string()
                    };
                    tracing::debug!(msg, "TouchID denied/cancelled");
                    Ok(false)
                };
                let _ = tx_inner.send(result);
            });

            unsafe {
                ctx.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                    &reason_ns,
                    &block,
                );
            }
            // `block` (Retained<Block>) goes out of scope here. Refcount drops
            // by 1, but LAContext has retained it, so it stays alive until
            // it fires. The thread also exits.
        });

        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(authorized)) => Ok(authorized),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("TouchID prompt timed out (60s)".into()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod stub {
    pub fn prompt_biometric(_reason: &str) -> Result<bool, String> {
        Ok(true)
    }
}
