#!/bin/bash
# CMS interop check: parse each DER sample the crate emits with OpenSSL.
#
# The samples come from the tests named
# `the_emitted_structures_write_their_interop_samples`, which write one
# `ContentInfo` per structure to target/cms-samples/, and the DER of three
# certificates, when the environment holds TIGHTBEAM_CMS_SAMPLES. `make
# interop` runs both steps:
#
#   TIGHTBEAM_CMS_SAMPLES=1 cargo test -p tightbeam-rs --all-features --lib \
#     the_emitted_structures_write_their_interop_samples
#   scripts/cms-interop.sh
#
# Each certificate carries the keyUsage bit of its one use:
#
#   server-certificate.crt                 digitalSignature, signs the reply
#   server-key-agreement-certificate.crt   keyAgreement, receives the opening
#   client-certificate.crt                 digitalSignature, signs the closing
#
# The script parses each with `openssl x509` and reads its keyUsage. It reads
# the subjectKeyIdentifier of both server certificates. It parses the
# KEMRecipientInfo of the cms-opening sample with `openssl asn1parse
# -strparse`, reads its rid, and checks that the rid is the [0]
# subjectKeyIdentifier of the key-agreement certificate and not that of the
# signing certificate.
#
# For each sample, the script runs `openssl asn1parse` and
# `openssl cms -cmsout -print`. For each SignedData sample it also runs
# `openssl cms -verify -noverify -binary`, with the server signing certificate
# and the client certificate as a -certfile for a signer that embeds no
# certificate. The receipt both ends signed needs both. -noverify skips the
# chain to a trust anchor, so the check covers the signature, the signed
# attributes, and the content digest. It prints one result line per sample.
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
# Frames and records write three samples. OpenSSL decrypts record, one
# session record under a KEKRecipientInfo, under its fixed test KEK. It
# parses frame-kem, the envelope of a frame sealed to a bare KEM recipient,
# and cannot open it, as with cms-opening. It parses compressed-data, the
# CompressedData of a compressed frame body, and the script checks that its
# encapContentInfo declares id-data (RFC 3274 section 1.1).
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
# expected plaintext, when a CompressedData sample declares another content
# type than id-data, when a certificate lacks the bit of its use, when the
# opening's rid names another certificate, or when a sample of `required` is
# absent.
# It has no dependency on the crate.
#
# References:
#   RFC 5652, Cryptographic Message Syntax:
#     https://datatracker.ietf.org/doc/html/rfc5652
#   RFC 5083, Authenticated-Enveloped-Data:
#     https://datatracker.ietf.org/doc/html/rfc5083#section-2.1
#   RFC 9629, KEM Algorithms in CMS:
#     https://datatracker.ietf.org/doc/html/rfc9629
#   RFC 3274, Compressed Data Content Type for CMS:
#     https://datatracker.ietf.org/doc/html/rfc3274#section-1.1

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

# Each structure the handshake, the session, and a frame emit, so a writer
# that stops emitting one fails the run.
required=(
	cms-opening server-finished session-receipt sealed-finished kek-seal frame-signature joined-receipt
	hpke-hello hpke-reply hpke-closing
	record frame-kem compressed-data
)

# Each certificate the samples name, beside the keyUsage bit of its use as
# OpenSSL prints it.
certificates=(
	"server-certificate:Digital Signature"
	"server-key-agreement-certificate:Key Agreement"
	"client-certificate:Digital Signature"
)

absent=0
for name in "${required[@]}"; do
	if [ ! -f "$SAMPLE_DIR/$name.der" ]; then
		echo "cms-interop: no $name sample in $SAMPLE_DIR" >&2
		absent=$((absent + 1))
	fi
done
for entry in "${certificates[@]}"; do
	if [ ! -f "$SAMPLE_DIR/${entry%%:*}.crt" ]; then
		echo "cms-interop: no ${entry%%:*} certificate in $SAMPLE_DIR" >&2
		absent=$((absent + 1))
	fi
done
if [ "$absent" -ne 0 ]; then
	exit 1
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

signers_pem="$scratch/signers.pem"
for certificate in "$SAMPLE_DIR/server-certificate.crt" "$SAMPLE_DIR/client-certificate.crt"; do
	"$OPENSSL" x509 -inform DER -in "$certificate" >> "$signers_pem"
done

# Print the keyUsage names a certificate sample asserts, comma-separated.
key_usage() {
	"$OPENSSL" x509 -inform DER -in "$1" -noout -ext keyUsage 2> /dev/null | tail -n +2 | sed 's/^ *//'
}

# Print the subjectKeyIdentifier of a certificate sample as lowercase hex.
key_identifier() {
	"$OPENSSL" x509 -inform DER -in "$1" -noout -ext subjectKeyIdentifier 2> /dev/null |
		tail -n +2 | tr -d ' :\n' | tr 'A-F' 'a-f'
}

# Print the rid of the KEMRecipientInfo in the opening sample `$1`, as
# lowercase hex, when it is the [0] subjectKeyIdentifier form (RFC 9629
# section 3, RFC 5652 section 6.2.1). The KEMRecipientInfo is the value that
# follows the id-ori-kem OID. The parse is re-rooted there, and the rid is
# its second field.
opening_rid() {
	local sample="$1" recipient="$scratch/kem-recipient-info.der" offset field header length
	offset="$("$OPENSSL" asn1parse -inform DER -in "$sample" | awk '
		/:(1\.2\.840\.113549\.1\.9\.16\.13\.3|id-ori-kem|id-smime-ori-kem)[[:space:]]*$/ { found = 1; next }
		found { split($1, at, ":"); print at[1]; exit }')"
	[ -n "$offset" ] || return 1
	"$OPENSSL" asn1parse -inform DER -in "$sample" -strparse "$offset" -noout -out "$recipient" > /dev/null || return 1

	field="$("$OPENSSL" asn1parse -inform DER -in "$recipient" | awk '/:d=1 / { count++ } count == 2 { print; exit }')"
	printf '%s\n' "$field" | grep -q 'prim: cont \[ 0 \]' || return 1
	read -r offset header length < <(printf '%s\n' "$field" |
		sed -E 's/^ *([0-9]+):d=[0-9]+ +hl= *([0-9]+) +l= *([0-9]+) .*$/\1 \2 \3/')
	od -An -tx1 -v -j "$((offset + header))" -N "$length" "$recipient" | tr -d ' \n'
}

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

# Check that a parsed CompressedData sample declares id-data as the type of
# the content it compresses (RFC 3274 section 1.1).
declared() {
	if printf '%s\n' "$1" | grep -qE 'eContentType:[[:space:]]*(pkcs7-data|1\.2\.840\.113549\.1\.7\.1)'; then
		echo "eContentType id-data"
	else
		echo "eContentType is not id-data FAILED"
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
for entry in "${certificates[@]}"; do
	name="${entry%%:*}"
	bit="${entry#*:}"
	if ! usage="$(key_usage "$SAMPLE_DIR/$name.crt")" || [ -z "$usage" ]; then
		printf '%-34s x509 parse FAILED, or no keyUsage\n' "$name"
		failures=$((failures + 1))
	elif printf '%s\n' "$usage" | grep -q "$bit"; then
		printf '%-34s x509 parses, keyUsage %s, the bit of its use\n' "$name" "$usage"
	else
		printf '%-34s x509 parses, keyUsage %s, lacks %s FAILED\n' "$name" "$usage" "$bit"
		failures=$((failures + 1))
	fi
done

agreement_id="$(key_identifier "$SAMPLE_DIR/server-key-agreement-certificate.crt")"
signing_id="$(key_identifier "$SAMPLE_DIR/server-certificate.crt")"
if ! rid="$(opening_rid "$SAMPLE_DIR/cms-opening.der")" || [ -z "$rid" ]; then
	echo "cms-opening rid: asn1parse parses no [0] subjectKeyIdentifier from the KEMRecipientInfo FAILED"
	failures=$((failures + 1))
elif [ -z "$agreement_id" ] || [ -z "$signing_id" ]; then
	echo "cms-opening rid: a server certificate carries no subjectKeyIdentifier FAILED"
	failures=$((failures + 1))
elif [ "$rid" = "$agreement_id" ] && [ "$rid" != "$signing_id" ]; then
	echo "cms-opening rid: asn1parse parses the KEMRecipientInfo rid as the subjectKeyIdentifier of server-key-agreement-certificate, not of server-certificate"
else
	echo "cms-opening rid: asn1parse parses the KEMRecipientInfo rid as another certificate's subjectKeyIdentifier FAILED"
	failures=$((failures + 1))
fi
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
		elif printf '%s\n' "$printed" | grep -q 'contentType: id-smime-ct-compressedData'; then
			verified="$(declared "$printed")"
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
