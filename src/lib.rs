pub mod adapter;
pub mod assembler;
pub mod cli;
pub mod commands;
pub mod hash;
pub mod manifest;
pub mod output;
pub mod policy;
pub mod refusal;
pub mod scanner;
pub mod types;
pub mod witness;

/// Entry point for the airlock CLI.
///
/// Returns an exit code: 0 = VERIFY_PASS, 1 = VERIFY_PARTIAL, 2 = REFUSAL.
/// Real dispatch is wired by al-jwl (CLI shell bead).
pub fn run() -> u8 {
    0
}
