//! Zero-copy URN (Uniform Resource Name) builder
//!
//! Provides a thin wrapper for building URN strings with minimal allocations
//! using `Cow` (Clone-on-Write) for efficient string handling.
//!
//! # Format
//!
//! ```text
//! urn:partition:service:region:account-id:resource
//! ```
//!
//! # Examples
//!
//! ```
//! use tightbeam::utils::urn::Urn;
//!
//! // Build a URN with owned strings
//! let urn = Urn::builder()
//!     .partition("aws")
//!     .service("iam")
//!     .account_id("123456789012")
//!     .resource("user/Bob")
//!     .build();
//!
//! assert_eq!(urn.to_string(), "urn:aws:iam::123456789012:user/Bob");
//!
//! // Build a URN with borrowed strings (zero-copy)
//! let partition = "aws";
//! let service = "s3";
//! let resource = "my-bucket";
//!
//! let urn = Urn::builder()
//!     .partition(partition)
//!     .service(service)
//!     .resource(resource)
//!     .build();
//!
//! assert_eq!(urn.to_string(), "urn:aws:s3:::my-bucket");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "std")]
use std::borrow::Cow;

use core::fmt;

/// A zero-copy URN (Uniform Resource Name) structure
///
/// Uses `Cow<'a, str>` for each component to minimize allocations.
/// Components can be borrowed or owned depending on usage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urn<'a> {
	/// The partition (e.g., "aws", "gcp", "azure")
	pub partition: Cow<'a, str>,
	/// The service namespace (e.g., "s3", "ec2", "iam")
	pub service: Cow<'a, str>,
	/// The region (optional, e.g., "us-east-1")
	pub region: Cow<'a, str>,
	/// The account ID (optional, e.g., "123456789012")
	pub account_id: Cow<'a, str>,
	/// The resource identifier
	pub resource: Cow<'a, str>,
}

impl<'a> Urn<'a> {
	/// Create a new URN builder
	#[inline]
	pub fn builder() -> UrnBuilder<'a> {
		UrnBuilder::new()
	}

	/// Convert the URN to an owned version with 'static lifetime
	#[inline]
	pub fn into_owned(self) -> Urn<'static> {
		Urn {
			partition: Cow::Owned(self.partition.into_owned()),
			service: Cow::Owned(self.service.into_owned()),
			region: Cow::Owned(self.region.into_owned()),
			account_id: Cow::Owned(self.account_id.into_owned()),
			resource: Cow::Owned(self.resource.into_owned()),
		}
	}

	/// Check if this URN has a region specified
	#[inline]
	pub fn has_region(&self) -> bool {
		!self.region.is_empty()
	}

	/// Check if this URN has an account ID specified
	#[inline]
	pub fn has_account_id(&self) -> bool {
		!self.account_id.is_empty()
	}
}

impl<'a> fmt::Display for Urn<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"urn:{}:{}:{}:{}:{}",
			self.partition, self.service, self.region, self.account_id, self.resource
		)
	}
}

/// Builder for constructing URNs with a fluent API
#[derive(Debug, Default)]
pub struct UrnBuilder<'a> {
	partition: Option<Cow<'a, str>>,
	service: Option<Cow<'a, str>>,
	region: Option<Cow<'a, str>>,
	account_id: Option<Cow<'a, str>>,
	resource: Option<Cow<'a, str>>,
}

impl<'a> UrnBuilder<'a> {
	/// Create a new URN builder
	#[inline]
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the partition (e.g., "aws", "gcp", "azure")
	#[inline]
	pub fn partition(mut self, partition: impl Into<Cow<'a, str>>) -> Self {
		self.partition = Some(partition.into());
		self
	}

	/// Set the service namespace (e.g., "s3", "ec2", "iam")
	#[inline]
	pub fn service(mut self, service: impl Into<Cow<'a, str>>) -> Self {
		self.service = Some(service.into());
		self
	}

	/// Set the region (optional, e.g., "us-east-1")
	#[inline]
	pub fn region(mut self, region: impl Into<Cow<'a, str>>) -> Self {
		self.region = Some(region.into());
		self
	}

	/// Set the account ID (optional, e.g., "123456789012")
	#[inline]
	pub fn account_id(mut self, account_id: impl Into<Cow<'a, str>>) -> Self {
		self.account_id = Some(account_id.into());
		self
	}

	/// Set the resource identifier
	#[inline]
	pub fn resource(mut self, resource: impl Into<Cow<'a, str>>) -> Self {
		self.resource = Some(resource.into());
		self
	}

	/// Build the URN
	///
	/// Missing optional fields (region, account_id) will be empty strings.
	/// Required fields (partition, service, resource) must be set.
	#[inline]
	pub fn build(self) -> Urn<'a> {
		Urn {
			partition: self.partition.unwrap_or(Cow::Borrowed("")),
			service: self.service.unwrap_or(Cow::Borrowed("")),
			region: self.region.unwrap_or(Cow::Borrowed("")),
			account_id: self.account_id.unwrap_or(Cow::Borrowed("")),
			resource: self.resource.unwrap_or(Cow::Borrowed("")),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_urn_builder_full() {
		let urn = Urn::builder()
			.partition("aws")
			.service("iam")
			.region("")
			.account_id("123456789012")
			.resource("user/division_abc/subdivision_xyz/Bob")
			.build();

		assert_eq!(
			urn.to_string(),
			"urn:aws:iam::123456789012:user/division_abc/subdivision_xyz/Bob"
		);
		assert!(!urn.has_region());
		assert!(urn.has_account_id());
	}

	#[test]
	fn test_urn_builder_s3_bucket() {
		let urn = Urn::builder().partition("aws").service("s3").resource("my-bucket").build();

		assert_eq!(urn.to_string(), "urn:aws:s3:::my-bucket");
		assert!(!urn.has_region());
		assert!(!urn.has_account_id());
	}

	#[test]
	fn test_urn_builder_lambda() {
		let urn = Urn::builder()
			.partition("aws")
			.service("lambda")
			.region("us-east-1")
			.account_id("123456789012")
			.resource("function:my-function")
			.build();

		assert_eq!(urn.to_string(), "urn:aws:lambda:us-east-1:123456789012:function:my-function");
		assert!(urn.has_region());
		assert!(urn.has_account_id());
	}

	#[test]
	fn test_urn_builder_ec2_instance() {
		let urn = Urn::builder()
			.partition("aws")
			.service("ec2")
			.region("us-east-1")
			.account_id("123456789012")
			.resource("instance/i-012abcd34efghi56")
			.build();

		assert_eq!(
			urn.to_string(),
			"urn:aws:ec2:us-east-1:123456789012:instance/i-012abcd34efghi56"
		);
	}

	#[test]
	fn test_urn_zero_copy_borrowed() {
		let partition = "aws";
		let service = "s3";
		let resource = "my-bucket";

		let urn = Urn::builder().partition(partition).service(service).resource(resource).build();

		// Verify zero-copy: borrowed strings should not allocate
		assert!(matches!(urn.partition, Cow::Borrowed(_)));
		assert!(matches!(urn.service, Cow::Borrowed(_)));
		assert!(matches!(urn.resource, Cow::Borrowed(_)));

		assert_eq!(urn.to_string(), "urn:aws:s3:::my-bucket");
	}

	#[test]
	fn test_urn_into_owned() {
		let urn = Urn::builder().partition("aws").service("s3").resource("my-bucket").build();

		let owned_urn = urn.into_owned();

		// Verify owned strings
		assert!(matches!(owned_urn.partition, Cow::Owned(_)));
		assert!(matches!(owned_urn.service, Cow::Owned(_)));
		assert!(matches!(owned_urn.resource, Cow::Owned(_)));

		assert_eq!(owned_urn.to_string(), "urn:aws:s3:::my-bucket");
	}

	#[test]
	fn test_urn_clone() {
		let urn1 = Urn::builder().partition("aws").service("s3").resource("my-bucket").build();

		let urn2 = urn1.clone();

		assert_eq!(urn1, urn2);
		assert_eq!(urn1.to_string(), urn2.to_string());
	}
}
