#!/bin/bash
# CMS interop check: OpenSSL parses, verifies, or decrypts every CMS sample
# the crate emits, with no tightbeam code in the loop.
#
# `make interop` runs both steps:
#
#   TIGHTBEAM_CMS_SAMPLES=1 cargo test -p tightbeam-rs --all-features --lib \
#     the_emitted_structures_write_their_interop_samples
#   scripts/cms-interop.sh [sample-dir]
#
# The test writes one ContentInfo per structure to target/cms-samples/, the
# four certificates the samples name, and the KEK, kekid, and plaintext of
# each sample sealed under a KEK. OPENSSL names the binary to run.
#
# Each check prints one line:
#
# - Certificate: it parses, and its keyUsage carries the bit of its one use.
# - Opening: its KEMRecipientInfo rid is the key-agreement certificate's subjectKeyIdentifier.
# - SignedData: `cms -verify` with no -certfile. The Finished and both receipts also chain to test-root.
# - AuthEnvelopedData under a KEK: `cms -decrypt` recovers the expected plaintext.
# - KEMRecipientInfo: parse only, because OpenSSL has no DHKEM over secp256k1.
# - CompressedData: its encapContentInfo declares id-data (RFC 3274 section 1.1).
#
# OpenSSL deviates from the RFCs in three ways, and the script counts each
# apart from a failure:
#
# - It reads authAttrs under [2] and unauthAttrs under [3] (cms_asn1.c), where RFC 5083 section 2.1
#   writes [1] and [2]. The script parses a retagged copy.
# - It feeds no authAttrs to the cipher as AAD (cms_env.c, cms_enc.c), against RFC 5083 section 2.2,
#   so it recovers the plaintext and then refuses the tag.
# - OpenSSL 3.0 cannot verify an ecdsa-with-SHA3-256 certificate signature. A self-signed probe
#   decides: when it fails, the chained samples verify without the chain, and their lines say so.
#
# The script exits non-zero on any FAILED line, a missing sample, or a probe
# certificate that fails to generate.
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
	"test-root:Certificate Sign"
)

# Each SignedData sample whose signers' certificates the test root issued,
# which the sample carries in its certificates.
anchored=(server-finished session-receipt joined-receipt)

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

root_pem="$scratch/test-root.pem"
"$OPENSSL" x509 -inform DER -in "$SAMPLE_DIR/test-root.crt" -out "$root_pem"

# The probe: a self-signed secp256k1 authority this OpenSSL generates under
# ecdsa-with-SHA3-256, verified against itself. It reads no sample, so a
# defect of the test root fails the run whenever the probe passes.
probe_key="$scratch/probe.key"
probe_pem="$scratch/probe.pem"
probe="OpenSSL refuses a self-signed secp256k1 probe certificate under ecdsa-with-SHA3-256"
if ! "$OPENSSL" ecparam -name secp256k1 -genkey -noout -out "$probe_key" > /dev/null 2>&1 ||
	! "$OPENSSL" req -x509 -new -key "$probe_key" -sha3-256 -subj "/CN=cms-interop probe" -days 1 \
		-out "$probe_pem" > /dev/null 2>&1; then
	echo "cms-interop: the secp256k1 probe certificate under ecdsa-with-SHA3-256 fails to generate" >&2
	exit 1
fi
chains=0
if "$OPENSSL" verify -CAfile "$probe_pem" "$probe_pem" > /dev/null 2>&1; then
	chains=1
fi

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

# Verify a SignedData sample under the certificates it carries alone. A
# sample of `anchored` also verifies each signer's chain to the test root,
# and any other skips the chain.
verify() {
	local sample="$1" name
	name="$(basename "$sample" .der)"
	if printf '%s\n' "${anchored[@]}" | grep -qx "$name" && [ "$chains" -eq 1 ]; then
		if "$OPENSSL" cms -verify -inform DER -in "$sample" -CAfile "$root_pem" -binary \
			-out /dev/null > /dev/null 2>&1; then
			echo "cms -verify ok under the certificates it carries, chained to test-root"
		else
			echo "cms -verify under the certificates it carries, chained to test-root FAILED"
		fi
	elif printf '%s\n' "${anchored[@]}" | grep -qx "$name"; then
		if "$OPENSSL" cms -verify -inform DER -in "$sample" -noverify -binary -out /dev/null > /dev/null 2>&1; then
			echo "cms -verify ok under the certificates it carries, chain unchecked: $probe"
		else
			echo "cms -verify under the certificates it carries FAILED"
		fi
	elif "$OPENSSL" cms -verify -inform DER -in "$sample" -noverify -binary -out /dev/null > /dev/null 2>&1; then
		echo "cms -verify ok under the certificate it carries"
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
unchained=0
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

if [ "$chains" -eq 0 ]; then
	echo "test-root chain: unchecked, $probe"
elif root_check="$("$OPENSSL" verify -CAfile "$root_pem" "$root_pem" 2>&1)"; then
	echo "test-root chain: the ecdsa-with-SHA3-256 probe verifies, and verify accepts test-root against itself"
else
	echo "test-root chain: verify refuses test-root against itself FAILED: $(printf '%s\n' "$root_check" | grep -m 1 -i 'error' || true)"
	failures=$((failures + 1))
fi

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
				*"chain unchecked"*) unchained=$((unchained + 1)) ;;
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

echo "cms-interop: ${#samples[@]} samples, $failures failed, $deviations parse only under OpenSSL's AuthEnvelopedData tags, $unauthenticated decrypt with no AAD check, $unchained verify with the chain unchecked"
if [ "$failures" -ne 0 ]; then
	exit 1
fi
