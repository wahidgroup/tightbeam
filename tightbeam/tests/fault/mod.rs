//! Fault injection testing
//!
//! This module demonstrates tightbeam's CSP-driven fault injection capabilities
//! using the FaultModel with HashMap-based O(1) lookups and integer-based
//! probability (basis points).
//!
//! ## Fault Injection Strategy
//!
//! Faults are injected based on CSP process state and event labels:
//! - **State-Driven**: Faults trigger when specific (state, event) pairs occur
//! - **O(1 Lookup**: HashMap provides constant-time fault checking
//! - **Integer Probability**: Basis points (0-10000) for deterministic, no_std math
//! - **Type-Erased Errors**: Any type implementing InjectedError can be injected
//!
//! ## Test Structure
//!
//! - `comprehensive.rs`: Complete fault injection workflow with tb_scenario! and FDR

mod basic;
