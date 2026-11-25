/// Exit code: verification passed, achieved claim meets or exceeds requirement.
pub const VERIFY_PASS: u8 = 0;

/// Exit code: verification completed but achieved claim is below the required level.
pub const VERIFY_PARTIAL: u8 = 1;

/// Exit code: `doctor` reported an unhealthy state (an `error` finding).
///
/// Shares the value `1` with [`VERIFY_PARTIAL`] by family contract
/// (`cmdrvl.doctor.v1`): doctor-unhealthy is never exit `2`.
pub const UNHEALTHY: u8 = 1;

/// Exit code: structured refusal — bad input, missing file, or internal error.
pub const REFUSAL: u8 = 2;
