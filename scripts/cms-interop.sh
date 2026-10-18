#!/bin/bash
# CMS interop check: parse each DER sample the crate emits with OpenSSL.
#
# The samples come from the test
# `the_emitted_structures_write_their_interop_samples`, which writes one
# `ContentInfo` per structure to target/cms-samples/, and the server and
# client certificates as server-certificate.crt and client-certificate.crt,
# when the environment holds TIGHTBEAM_CMS_SAMPLES. `make interop` runs both
# steps:
#
#   TIGHTBEAM_CMS_SAMPLES=1 cargo test -p tightbeam-rs --all-features --lib \
#     the_emitted_structures_write_their_interop_samples
#   scripts/cms-interop.sh
#
# For each sample, the script runs `openssl asn1parse` and
# `openssl cms -cmsout -print`. For each SignedData sample it also runs
# `openssl cms -verify -noverify -binary`, with the server and client
# certificates as a -certfile for a signer that embeds no certificate. The
# receipt both ends signed needs both. -noverify skips the chain to a trust
# anchor, so the check covers the signature, the signed attributes, and the
# content digest. It prints one result line per sample.
#
# For each AuthEnvelopedData sample under a KEKRecipientInfo, the test also
# writes the KEK, the kekid, and the expected plaintext, from fixed test keys,
# as <name>.kek, <name>.kekid, and <name>.plain. The script runs
# `openssl cms -decrypt -secretkey -secretkeyid` on the copy under OpenSSL's
# tags, and compares the output with the expected plaintext. OpenSSL has no
# DHKEM over secp256k1 under the crate's KEM identifier, so it parses the
# KEMRecipientInfo sample and cannot open it.
#
# The HPKE flow writes three samples. OpenSSL parses hpke-hello, the
# `ContentInfo` of type id-data whose content is the ClientHello. It verifies
# hpke-reply, the reply SignedData, under the certificate the reply carries.
# It decrypts hpke-closing, the anonymous closing under a KEKRecipientInfo,
# under its fixed test KEK.
#
# OpenSSL feeds no authAttrs to the cipher as associated data
# (crypto/cms/cms_env.c and cms_enc.c set none), where RFC 5083 section 2.2
# makes their DER the AAD. It writes the content before it checks the tag, so
# it recovers the plaintext of a sample that carries authAttrs and then
# refuses its tag. A content equal to the expected plaintext still shows the
# kekid, the key wrap, the GCM parameters, and the keystream, and the line
# names the refused tag apart from a failure.
#
# OpenSSL's template of AuthEnvelopedData (crypto/cms/cms_asn1.c) reads
# authAttrs under [2] and unauthAttrs under [3], the tags of AuthenticatedData
# (RFC 5652 section 9.1). RFC 5083 section 2.1 writes [1] and [2], and the crate
# follows RFC 5083. When OpenSSL refuses an AuthEnvelopedData sample, the script
# retags a copy to OpenSSL's tags and parses it again, so the line tells that
# deviation apart from a structure OpenSSL cannot read at all.
#
# The script exits non-zero when a sample fails `asn1parse`, fails the CMS
# parse under either tagging, fails to verify, fails to decrypt to its
# expected plaintext, or when a sample of `required` is absent.
# It has no dependency on the crate.
#
# References:
#   RFC 5652, Cryptographic Message Syntax:
#     https://datatracker.ietf.org/doc/html/rfc5652
#   RFC 5083, Authenticated-Enveloped-Data:
#     https://datatracker.ietf.org/doc/html/rfc5083#section-2.1
#   RFC 9629, KEM Algorithms in CMS:
#     https://datatracker.ietf.org/doc/html/rfc9629

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAMPLE_DIR="${1:-$PROJECT_ROOT/target/cms-samples}"
OPENSSL="${OPENSSL:-openssl}"

shopt -s nullglob
samples=("$SAMPLE_DIR"/*.der)
if [ "${#samples[@]}" -eq 0 ]; then
	echo "cms-interop: no samples in $SAMPLE_DIR" >&2
	exit 1
fi

# Each structure the handshake emits, so a writer that stops emitting one
# fails the run.
required=(
	cms-opening server-finished session-receipt sealed-finished kek-seal frame-signature joined-receipt
	hpke-hello hpke-reply hpke-closing
)
absent=0
for name in "${required[@]}"; do
	if [ ! -f "$SAMPLE_DIR/$name.der" ]; then
		echo "cms-interop: no $name sample in $SAMPLE_DIR" >&2
		absent=$((absent + 1))
	fi
done
if [ "$absent" -ne 0 ]; then
	exit 1
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

signers_pem=""
for certificate in "$SAMPLE_DIR/server-certificate.crt" "$SAMPLE_DIR/client-certificate.crt"; do
	if [ -f "$certificate" ]; then
		signers_pem="$scratch/signers.pem"
		"$OPENSSL" x509 -inform DER -in "$certificate" >> "$signers_pem"
	fi
done

# Print the content type and the first recipient kind of a parsed sample.
summary() {
	local printed="$1" content_type recipient
	content_type="$(printf '%s\n' "$printed" | awk '/contentType:/ { print $2; exit }')"
	recipient="$(printf '%s\n' "$printed" | grep -oE 'd\.(ori|kekri|kari|ktri|pwri)' | head -n 1 || true)"
	printf 'contentType %s%s' "${content_type:-unknown}" "${recipient:+, $recipient}"
}

# Verify a SignedData sample, with the server and client certificates as
# extra signer certificates when the samples carry them.
verify() {
	local sample="$1"
	local certfile=()
	if [ -n "$signers_pem" ]; then
		certfile=(-certfile "$signers_pem")
	fi
	if "$OPENSSL" cms -verify -inform DER -in "$sample" -noverify -binary ${certfile[@]+"${certfile[@]}"} \
		-out /dev/null > /dev/null 2>&1; then
		echo "cms -verify ok"
	else
		echo "cms -verify FAILED"
	fi
}

# Decrypt a retagged AuthEnvelopedData sample under the KEK its test wrote,
# and compare the content with the expected plaintext.
decrypt() {
	local copy="$1" name="$2" status=0
	local opened="$scratch/$name.opened" log="$scratch/$name.decrypt.log"
	"$OPENSSL" cms -decrypt -inform DER -in "$copy" -binary \
		-secretkey "$(cat "$SAMPLE_DIR/$name.kek")" -secretkeyid "$(cat "$SAMPLE_DIR/$name.kekid")" \
		-out "$opened" > "$log" 2>&1 || status=$?
	if ! cmp -s "$opened" "$SAMPLE_DIR/$name.plain"; then
		echo "cms -decrypt FAILED: $(grep -m 1 -i 'error' "$log" || echo 'the content differs from the expected plaintext')"
	elif [ "$status" -eq 0 ]; then
		echo "cms -decrypt ok"
	else
		echo "cms -decrypt recovers the expected plaintext, refuses the tag it checks without the authAttrs AAD"
	fi
}

# Write a copy of an AuthEnvelopedData sample with authAttrs moved from [1]
# to [2] and unauthAttrs from [2] to [3], the tags OpenSSL's template reads.
# The fields sit at depth 3 of the ContentInfo, and each retag rewrites one
# identifier octet in place.
retag() {
	local sample="$1" copy="$2" offset tag
	cp "$sample" "$copy"
	while read -r offset tag; do
		printf "\\x$tag" | dd of="$copy" bs=1 seek="$offset" conv=notrunc status=none
	done < <("$OPENSSL" asn1parse -inform DER -in "$sample" | awk '
		/:d=3 / && /cont \[ 1 \]/ { split($1, field, ":"); print field[1], "a2" }
		/:d=3 / && /cont \[ 2 \]/ { split($1, field, ":"); print field[1], "a3" }')
}

echo "cms-interop: $("$OPENSSL" version)"

failures=0
deviations=0
unauthenticated=0
for sample in "${samples[@]}"; do
	name="$(basename "$sample" .der)"

	if "$OPENSSL" asn1parse -inform DER -in "$sample" > /dev/null 2>&1; then
		asn1="asn1parse ok"
	else
		asn1="asn1parse FAILED"
		failures=$((failures + 1))
	fi

	verified=""
	if printed="$("$OPENSSL" cms -cmsout -print -inform DER -in "$sample" 2>&1)"; then
		cms="cms -cmsout -print ok ($(summary "$printed"))"
		if printf '%s\n' "$printed" | grep -q 'contentType: pkcs7-signedData'; then
			verified="$(verify "$sample")"
			case "$verified" in
				*FAILED) failures=$((failures + 1)) ;;
			esac
		fi
	elif printf '%s\n' "$printed" | grep -q 'Type=CMS_AuthEnvelopedData'; then
		retagged="$scratch/$name.der"
		retag "$sample" "$retagged"
		if printed="$("$OPENSSL" cms -cmsout -print -inform DER -in "$retagged" 2>&1)"; then
			cms="cms -cmsout -print refuses the RFC 5083 tags [1]/[2], parses under OpenSSL's [2]/[3] ($(summary "$printed"))"
			deviations=$((deviations + 1))
			if [ -f "$SAMPLE_DIR/$name.kek" ]; then
				verified="$(decrypt "$retagged" "$name")"
				case "$verified" in
					*FAILED*) failures=$((failures + 1)) ;;
					*"refuses the tag"*) unauthenticated=$((unauthenticated + 1)) ;;
				esac
			fi
		else
			cms="cms -cmsout -print FAILED under both taggings: $(printf '%s\n' "$printed" | head -n 1)"
			failures=$((failures + 1))
		fi
	else
		cms="cms -cmsout -print FAILED: $(printf '%s\n' "$printed" | head -n 1)"
		failures=$((failures + 1))
	fi

	printf '%-16s %s, %s%s\n' "$name" "$asn1" "$cms" "${verified:+, $verified}"
done

echo "cms-interop: ${#samples[@]} samples, $failures failed, $deviations parse only under OpenSSL's AuthEnvelopedData tags, $unauthenticated decrypt with no AAD check"
if [ "$failures" -ne 0 ]; then
	exit 1
fi
