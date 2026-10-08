"""c2pa-rs settings for the content-local signing path.

These are the settings the C2PA Conformance Program assessment turned on. Stock
c2pa-rs defaults produce a manifest that is structurally valid but nonconformant
in two ways this module fixes, plus a third (assertion ORDER) that no setting
can reach — see :mod:`oprindo._claim_order`.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

#: Every assertion label this SDK can emit. c2pa-rs puts only the hard binding
#: in the claim's ``created_assertions`` and everything else in
#: ``gathered_assertions``; the Conformance Program requires the whole set to
#: sit in ``created_assertions``, because all of it is payload the generator
#: signs.
#:
#: Labels are matched as written, so BOTH the family and the versioned form have
#: to be listed — a v2 claim references ``c2pa.actions.v2``, not
#: ``c2pa.actions``. Anything omitted falls back to ``gathered_assertions`` with
#: no error.
CREATED_ASSERTION_LABELS = [
    "c2pa.actions",
    "c2pa.actions.v2",
    "c2pa.hash.data",
    "c2pa.hash.boxes",
    "c2pa.thumbnail.claim",
    "c2pa.thumbnail.claim.jpeg",
    "c2pa.thumbnail.claim.png",
    "c2pa.ingredient",
    "c2pa.ingredient.v2",
    "c2pa.ingredient.v3",
    "c2pa.thumbnail.ingredient",
]

#: Vendored from the C2PA Conformance Program, retrieved 2026-07-28. The
#: SHA-256 of each file is pinned so a verdict can always be traced to an exact
#: revision — these are the bytes Oprindo's own conformance evidence was
#: produced against.
TRUST_LIST_FILES = {
    "C2PA-TRUST-LIST.pem": "b1f399a7235f188a22f3db97992f1cc1417517664600335f9d105a6a7cdb46c1",
    "C2PA-TSA-TRUST-LIST.pem": "76788c4c36644ee24674f6d63e9ee6f0186c3e25e39ea80da67d1b6f35dbea62",
}


@lru_cache(maxsize=1)
def trust_anchors() -> str:
    """Both published trust lists, concatenated.

    c2pa-rs keeps ONE trust-anchor pool, used for both claim-signing and
    time-stamping certificates — there is no separate TSA section, and unknown
    settings keys are ignored rather than rejected, so inventing one would look
    like it worked while doing nothing.
    """
    package = resources.files(__package__) / "trust"
    return "\n".join((package / name).read_text(encoding="utf-8") for name in TRUST_LIST_FILES)


def _trust_settings() -> dict:
    """Governs the verdict reported on assets being INGESTED, both when
    verifying directly and when recording an ingredient's validation results
    into a manifest being signed.

    Without trust anchors c2pa-rs cannot chain a signing certificate to
    anything, so every third-party asset reads back
    ``signingCredential.untrusted``, and a certificate that was valid when it
    signed reads ``signingCredential.expired`` — validity is judged at "now"
    rather than at the trusted timestamp.
    """
    return {
        "trust": {"verify_trust_list": True, "trust_anchors": trust_anchors()},
        "verify": {"verify_trust": True, "verify_timestamp_trust": True},
    }


def reader_settings() -> dict:
    """Verification path: trust configuration only."""
    return _trust_settings()


def builder_settings() -> dict:
    """Signing path.

    Carries the trust anchors too, because an ingredient's validation results
    are captured while the builder ingests it — without them, ingested
    provenance would be recorded as untrusted in assets we sign.

    ``verify_after_sign`` is off because the claim is permuted after c2pa-rs
    lays it out, so the manifest c2pa-rs would verify is not the one that ends
    up in the asset. The placeholder signature is replaced by broker COSE over the permuted claim;
    the completed asset is then validated separately.
    """
    settings = _trust_settings()
    settings["builder"] = {"created_assertion_labels": CREATED_ASSERTION_LABELS}
    settings["verify"] = {**settings["verify"], "verify_after_sign": False}
    return settings
