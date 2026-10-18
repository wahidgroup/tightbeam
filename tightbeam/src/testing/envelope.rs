//! Test helpers that read and replace the recipient of an
//! [`AuthEnvelopedData`].

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::enveloped_data::{KekRecipientInfo, OtherRecipientInfo, RecipientInfo, RecipientInfos};
use crate::crypto::cms::{AuthEnvelopedData, KemRecipientInfo};
use crate::der::asn1::SetOfVec;
use crate::der::Any;
use crate::oids::ORI_KEM;

/// The recipient of an envelope, as a test reads or replaces it.
pub trait EnvelopeRecipient: Sized {
	/// The one `KEKRecipientInfo` this envelope carries.
	fn kek_recipient(&self) -> KekRecipientInfo;

	/// The `KEMRecipientInfo` of the one `ori` this envelope carries.
	fn kem_recipient(&self) -> KemRecipientInfo;

	/// This envelope with `recipients` in place of its own.
	fn with_recipients(self, recipients: impl IntoIterator<Item = RecipientInfo>) -> Self;

	/// This envelope with `kek` alone in place of its recipients.
	fn with_kek_recipient(self, kek: &KekRecipientInfo) -> Self {
		self.with_recipients([RecipientInfo::Kekri(kek.clone())])
	}

	/// This envelope with `kem` alone, in an `ori` of type `id-ori-kem`, in
	/// place of its recipients.
	fn with_kem_recipient(self, kem: &KemRecipientInfo) -> Self {
		let ori_value = Any::encode_from(kem).expect("a KEMRecipientInfo encodes");
		let other = OtherRecipientInfo { ori_type: ORI_KEM, ori_value };
		self.with_recipients([RecipientInfo::Ori(other)])
	}
}

impl EnvelopeRecipient for AuthEnvelopedData {
	fn kek_recipient(&self) -> KekRecipientInfo {
		let kek = match self.recipient_infos.0.as_slice() {
			[RecipientInfo::Kekri(kek)] => Some(kek.clone()),
			_ => None,
		};
		kek.expect("the envelope carries one KEK recipient")
	}

	fn kem_recipient(&self) -> KemRecipientInfo {
		let other = match self.recipient_infos.0.as_slice() {
			[RecipientInfo::Ori(other)] => Some(other),
			_ => None,
		};

		let other = other.expect("the envelope carries one other recipient");
		let kem = other.ori_value.decode_as::<KemRecipientInfo>();
		kem.expect("the other recipient is a KEMRecipientInfo")
	}

	fn with_recipients(mut self, recipients: impl IntoIterator<Item = RecipientInfo>) -> Self {
		let recipients: Vec<RecipientInfo> = recipients.into_iter().collect();
		let recipients = SetOfVec::try_from(recipients).expect("distinct recipients are a SET");
		self.recipient_infos = RecipientInfos(recipients);
		self
	}
}
