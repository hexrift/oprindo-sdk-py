"""The claim structure the C2PA Conformance Program assessed Oprindo against.

These assertions read the SIGNED CLAIM BYTES out of the produced asset, because
the SDK's own JSON view merges created and gathered assertions and so cannot see
either of the first two properties at all:

  1. every assertion in ``created_assertions``, none left in ``gathered``
  2. the actions assertion FIRST in ``created_assertions``
  3. the inception action reflects origin (created de novo vs opened)

Signing is done locally with a development key rather than by calling the
service, so the suite is offline but the signature is REAL — which matters,
because the claim is permuted inside the bytes being signed and the whole
design rests on the signature still validating afterwards.

Skipped entirely unless the ``c2pa`` extra and ``cryptography`` are installed;
both are heavy native wheels and the SDK's core is stdlib-only.
"""

from __future__ import annotations

import base64
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import c2pa  # type: ignore
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    _DEPS = True
except ImportError:  # pragma: no cover - exercised by the stdlib-only CI job
    _DEPS = False

from oprindo._cbor import array_element_spans, map_value_spans, read_text_string  # noqa: E402
from oprindo._manifest_store import (  # noqa: E402
    manifest_store_fragments,
    read_manifest_store,
)
from oprindo.client import Oprindo, OprindoError  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"

TINY_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a"
    "HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAA"
    "AAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q=="
)


def _tiny_png() -> bytes:
    """A 1x1 PNG, built rather than embedded so the CRCs are provably right."""
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
        + chunk(b"IEND", b"")
    )


def _active_claim(asset: bytes, mime: str) -> bytes:
    """The claim: the last CBOR box in the store carrying created_assertions."""
    store = read_manifest_store(asset, manifest_store_fragments(asset, mime))
    for i in range(len(store) - 8, 3, -1):
        if store[i : i + 4] != b"cbor":
            continue
        n = int.from_bytes(store[i - 4 : i], "big")
        if n < 8 or i - 4 + n > len(store):
            continue
        candidate = store[i + 4 : i - 4 + n]
        try:
            if "created_assertions" in map_value_spans(candidate, 0):
                return candidate
        except ValueError:
            pass
    raise AssertionError("no claim with created_assertions found in the store")


def _labels(claim: bytes, field: str) -> list[str]:
    """Assertion labels referenced by a named claim field, in claim order."""
    span = map_value_spans(claim, 0).get(field)
    if span is None:
        return []
    out = []
    for element in array_element_spans(claim, span.start).elements:
        url = map_value_spans(claim, element.start).get("url")
        text = read_text_string(claim, url.start) if url else None
        _, _, tail = (text or "").partition("c2pa.assertions/")
        out.append(tail)
    return out


def _ephemeral_chain():
    """A throwaway root + leaf chain c2pa-rs accepts, minted per run with openssl.

    No key material is committed to this repository. The recipe mirrors the
    Oprindo development chain exactly, because c2pa-rs enforces a certificate
    profile and reproducing it by hand is a source of false test failures
    rather than a thing under test: the leaf carries digitalSignature key usage
    and emailProtection extended key usage, and nothing else.
    """
    import subprocess
    import tempfile

    d = Path(tempfile.mkdtemp(prefix="oprindo-test-certs-"))

    def run(*args: str, **kwargs) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True, **kwargs)

    run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(d / "root.key.pem"))
    run(
        "req", "-new", "-x509", "-key", str(d / "root.key.pem"), "-sha256", "-days", "365",
        "-subj", "/O=Oprindo Test/CN=Oprindo Test Root", "-out", str(d / "root.cert.pem"),
    )
    run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(d / "leaf.sec1.pem"))
    # PKCS#8: the c2pa bindings reject SEC1 "EC PRIVATE KEY" PEMs.
    run("pkcs8", "-topk8", "-nocrypt", "-in", str(d / "leaf.sec1.pem"), "-out", str(d / "leaf.key.pem"))
    run(
        "req", "-new", "-key", str(d / "leaf.key.pem"), "-sha256",
        "-subj", "/O=Oprindo Test/CN=Oprindo Test Signer", "-out", str(d / "leaf.csr.pem"),
    )
    (d / "ext.cnf").write_text("keyUsage=digitalSignature\nextendedKeyUsage=emailProtection\n")
    run(
        "x509", "-req", "-in", str(d / "leaf.csr.pem"), "-CA", str(d / "root.cert.pem"),
        "-CAkey", str(d / "root.key.pem"), "-CAcreateserial", "-sha256", "-days", "180",
        "-extfile", str(d / "ext.cnf"), "-out", str(d / "leaf.cert.pem"),
    )

    pem = (d / "leaf.cert.pem").read_text() + (d / "root.cert.pem").read_text()
    key = serialization.load_pem_private_key((d / "leaf.key.pem").read_bytes(), password=None)
    return pem, key


class _LocallySigning(Oprindo):
    """Signs with a development key instead of calling the service.

    Emulates broker-owned COSE with a real signature over the supplied claim.
    The SDK must embed the complete response and validate the resulting asset.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._chain, self._key = _ephemeral_chain()

    def _json(self, method, path, payload=None, auth=True):
        if path == "/v1/signing-info":
            return 200, {"cert_chain": [self._chain], "trust_state": "pre_conformance"}
        if path == "/v1/sign-claim":
            # Emulate the broker's complete COSE response, signing the actual
            # supplied claim with a real ephemeral key. No raw-digest fallback.
            claim = base64.b64decode(payload["claim_bytes_b64"], validate=True)
            chain = [cert.public_bytes(serialization.Encoding.DER)
                     for cert in x509.load_pem_x509_certificates(self._chain.encode())]
            protected = _cbor({1: -7, 33: chain})
            der = self._key.sign(_cbor(["Signature1", protected, b"", claim]), ec.ECDSA(hashes.SHA256()))
            r, s = asym_utils.decode_dss_signature(der)
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            reserve = payload["reserve_size"]
            pad = reserve - len(protected) - 100
            for _ in range(8):
                cose = b"\xd2" + _cbor([protected, {"pad": bytes(pad)}, None, raw])
                if len(cose) == reserve:
                    break
                pad += reserve - len(cose)
            assert len(cose) == reserve
            self.last_payload = payload
            self.last_cose = cose
            return 200, {
                "cose_sign1": base64.b64encode(cose).decode(),
                "trust_state": "pre_conformance",
                "timestamp_included": False,
                "evidence_id": "00000000-0000-4000-8000-000000000000",
            }
        raise AssertionError(f"unexpected request to {path}")


def _cbor(value):
    """Small test-only COSE encoder; production takes broker bytes unchanged."""
    def head(major, number):
        if number < 24:
            return bytes([(major << 5) | number])
        width = 1 if number < 256 else 2 if number < 65536 else 4
        return bytes([(major << 5) | {1: 24, 2: 25, 4: 26}[width]]) + number.to_bytes(width, "big")
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(_cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(_cbor(key) + _cbor(item) for key, item in value.items())
    raise TypeError(value)


GENERATOR = {"name": "Test Generator", "version": "1.0.0"}


@unittest.skipUnless(_DEPS, "requires the c2pa extra and cryptography")
class ClaimConformance(unittest.TestCase):
    def setUp(self):
        self.sdk = _LocallySigning("opr_live_test", base_url="https://api.invalid")

    def _mark(self, data: bytes) -> bytes:
        return self.sdk.mark(data, "image/jpeg", GENERATOR).asset

    def test_embeds_the_complete_broker_cose_without_rewrapping(self):
        for asset, mime in [(TINY_JPEG, "image/jpeg"), (_tiny_png(), "image/png")]:
            with self.subTest(mime=mime):
                signed = self.sdk.mark(asset, mime, GENERATOR).asset
                store = read_manifest_store(signed, manifest_store_fragments(signed, mime))
                self.assertIn(self.sdk.last_cose, store)
                self.assertEqual(base64.b64decode(self.sdk.last_payload["claim_bytes_b64"]), _active_claim(signed, mime))
                self.assertGreater(self.sdk.last_payload["reserve_size"], 10000)

    def test_refuses_an_obsolete_raw_signature_response(self):
        original = self.sdk._json
        def obsolete(method, path, payload=None, auth=True):
            if path == "/v1/sign-claim":
                return 200, {"signature": "AA==", "trust_state": "trusted"}
            return original(method, path, payload, auth)
        self.sdk._json = obsolete
        with self.assertRaises(OprindoError) as caught:
            self._mark(TINY_JPEG)
        self.assertEqual(caught.exception.code, "signing_failed")

    def test_refuses_trusted_label_without_a_timestamp(self):
        original = self.sdk._json
        def mislabeled(method, path, payload=None, auth=True):
            status, result = original(method, path, payload, auth)
            if path == "/v1/sign-claim":
                result["trust_state"] = "trusted"
            return status, result
        self.sdk._json = mislabeled
        with self.assertRaises(OprindoError) as caught:
            self._mark(TINY_JPEG)
        self.assertEqual(caught.exception.code, "signing_failed")

    def test_every_assertion_is_created_and_gathered_is_empty(self):
        claim = _active_claim(self._mark(TINY_JPEG), "image/jpeg")
        self.assertEqual(_labels(claim, "gathered_assertions"), [])
        self.assertIn("c2pa.hash.data", _labels(claim, "created_assertions"))

    def test_actions_assertion_is_first(self):
        claim = _active_claim(self._mark(TINY_JPEG), "image/jpeg")
        self.assertRegex(_labels(claim, "created_assertions")[0], r"^c2pa\.actions(\.v\d+)?$")

    def test_png_survives_the_store_rewrite(self):
        """PNG takes a different path: the rewritten chunks need fresh CRCs.

        A wrong CRC would not show up as a claim problem, so this asserts the
        signature validates rather than merely that the labels look right.
        """
        signed = self.sdk.mark(_tiny_png(), "image/png", GENERATOR).asset
        claim = _active_claim(signed, "image/png")
        self.assertRegex(_labels(claim, "created_assertions")[0], r"^c2pa\.actions(\.v\d+)?$")
        with c2pa.Reader("image/png", io.BytesIO(signed)) as reader:
            report = json.loads(reader.json())
        results = report.get("validation_results", {}).get("activeManifest", {})
        self.assertIn(
            "claimSignature.validated", {e.get("code") for e in results.get("success", [])}
        )

    def test_signature_still_validates_over_the_permuted_claim(self):
        """The property the whole design rests on.

        The claim is permuted inside the bytes handed to the signer, so the
        signature covers the permuted claim; the store is then rewritten to
        match. If either half were wrong this would fail.
        """
        signed = self._mark(TINY_JPEG)
        with c2pa.Reader("image/jpeg", io.BytesIO(signed)) as reader:
            report = json.loads(reader.json())
        results = report.get("validation_results", {}).get("activeManifest", {})
        codes = {entry.get("code") for entry in results.get("success", [])}
        self.assertIn("claimSignature.validated", codes)
        self.assertIn("assertion.hashedURI.match", codes)
        self.assertIn("assertion.dataHash.match", codes)
        # The development chain is not trust-listed; nothing else may fail.
        self.assertEqual(
            [f.get("code") for f in results.get("failure", [])],
            ["signingCredential.untrusted"],
        )


@unittest.skipUnless(_DEPS, "requires the c2pa extra and cryptography")
class InceptionAction(unittest.TestCase):
    def setUp(self):
        self.sdk = _LocallySigning("opr_live_test", base_url="https://api.invalid")

    def test_created_de_novo_takes_no_ingredient(self):
        claim = _active_claim(self.sdk.mark(TINY_JPEG, "image/jpeg", GENERATOR).asset, "image/jpeg")
        created = _labels(claim, "created_assertions")
        self.assertFalse([label for label in created if label.startswith("c2pa.ingredient")])

    def test_opens_rather_than_creates_an_asset_with_provenance(self):
        """The case the conformance assessor challenged."""
        source = (FIXTURES / "signed-by-another-product.jpg").read_bytes()
        signed = self.sdk.mark(source, "image/jpeg", GENERATOR).asset
        claim = _active_claim(signed, "image/jpeg")
        created = _labels(claim, "created_assertions")

        # Actions still first, though an ingredient now precedes it in the
        # order c2pa-rs assembles.
        self.assertRegex(created[0], r"^c2pa\.actions(\.v\d+)?$")
        self.assertTrue([label for label in created if label.startswith("c2pa.ingredient")])
        self.assertEqual(_labels(claim, "gathered_assertions"), [])

        with c2pa.Reader("image/jpeg", io.BytesIO(signed)) as reader:
            report = json.loads(reader.json())
        active = report["manifests"][report["active_manifest"]]
        actions = next(
            a for a in active["assertions"] if a["label"].startswith("c2pa.actions")
        )["data"]["actions"]
        self.assertEqual(actions[0]["action"], "c2pa.opened")
        # The origin of ingested content is the parent's to state, not ours.
        self.assertNotIn("digitalSourceType", actions[0])
        # An unlinked c2pa.opened reads Invalid, so the link must be present.
        self.assertTrue(actions[0]["parameters"]["ingredients"])

    def test_refuses_created_over_an_asset_that_carries_provenance(self):
        source = (FIXTURES / "signed-by-another-product.jpg").read_bytes()
        with self.assertRaises(OprindoError) as caught:
            self.sdk.mark(
                source,
                "image/jpeg",
                GENERATOR,
                actions=[{"action": "c2pa.created", "digitalSourceType": "http://example/x"}],
            )
        self.assertEqual(caught.exception.code, "action_not_permitted")

    def test_refuses_opened_with_nothing_to_open(self):
        with self.assertRaises(OprindoError) as caught:
            self.sdk.mark(TINY_JPEG, "image/jpeg", GENERATOR, actions=[{"action": "c2pa.opened"}])
        self.assertEqual(caught.exception.code, "action_not_permitted")

    def test_refuses_a_source_type_on_opened(self):
        source = (FIXTURES / "signed-by-another-product.jpg").read_bytes()
        with self.assertRaises(OprindoError) as caught:
            self.sdk.mark(
                source,
                "image/jpeg",
                GENERATOR,
                actions=[{"action": "c2pa.opened", "digitalSourceType": "http://example/x"}],
            )
        self.assertEqual(caught.exception.code, "action_not_permitted")


class CborSpans(unittest.TestCase):
    """Pure unit tests — no native wheel needed."""

    def test_walks_a_nested_definite_length_map(self):
        # {"a": [1, 2], "b": "xy"}
        encoded = bytes.fromhex("a2616182010261626278790000")[:11]
        spans = map_value_spans(encoded, 0)
        self.assertEqual(set(spans), {"a", "b"})
        self.assertEqual(len(array_element_spans(encoded, spans["a"].start).elements), 2)

    def test_refuses_indefinite_length_items(self):
        from oprindo._cbor import CborError, read_head

        with self.assertRaises(CborError):
            read_head(bytes([0x5F]), 0)  # indefinite-length byte string


if __name__ == "__main__":
    unittest.main()
