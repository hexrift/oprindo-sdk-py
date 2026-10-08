"""Oprindo Python SDK — three verbs: mark, verify, evidence.

CONTENT-LOCAL BY DEFAULT: with the ``c2pa`` extra installed
(``pip install oprindo[c2pa]``), ``mark`` assembles and embeds the C2PA
manifest on YOUR machine; only the claim (kilobytes of metadata and hashes)
is sent to Oprindo. Without the extra, ``mark`` refuses unless you
explicitly opt into the full-service path (``allow_full_service=True``),
which transmits the asset bytes.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Any, Optional


TRAINED_ALGORITHMIC_MEDIA = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
)

DEFAULT_ACTIONS = [
    {"action": "c2pa.created", "digitalSourceType": TRAINED_ALGORITHMIC_MEDIA}
]

_SANDBOX_MARKER = "oprindo-sandbox"

#: Instance id given to the parent ingredient, so the inception action can name
#: what it opened. Any stable value works; it only has to match on both sides.
PARENT_INGREDIENT_ID = "xmp:iid:oprindo-parent-ingredient"


def _default_actions(has_prior_manifest: bool) -> list[dict[str, Any]]:
    """The inception action for an asset, chosen by what the asset actually is.

    C2PA requires the inception action to reflect origin: ``c2pa.created`` only
    when the asset originates here, ``c2pa.opened`` when it arrived with prior
    provenance. Asserting creation over ingested content claims an origin the
    signer cannot vouch for — and ``c2pa.opened`` carries no digitalSourceType
    for the same reason.
    """
    if has_prior_manifest:
        return [{"action": "c2pa.opened"}]
    return [{"action": "c2pa.created", "digitalSourceType": TRAINED_ALGORITHMIC_MEDIA}]


def _resolve_actions(
    actions: list[dict[str, Any]], has_prior_manifest: bool
) -> list[dict[str, Any]]:
    """Validate actions against what the asset is, and link ``c2pa.opened`` to
    the ingredient it opened.

    The link is mandatory: "Any c2pa.opened or c2pa.placed action must have an
    associated ingredient identified by the ingredientIds parameter field."
    Without it c2pa-rs raises ``assertion.action.ingredientMismatch`` and the
    whole asset reads Invalid — an unlinked ``c2pa.opened`` is worse than the
    wrong-action problem it fixes.
    """
    resolved: list[dict[str, Any]] = []
    for action in actions:
        name = action.get("action")
        if name == "c2pa.created" and has_prior_manifest:
            raise OprindoError(
                "action_not_permitted",
                0,
                "this asset already carries a C2PA manifest, so it was not created "
                "here — use c2pa.opened, or omit `actions` and the SDK will choose "
                "correctly",
            )
        if name != "c2pa.opened":
            resolved.append(action)
            continue
        if action.get("digitalSourceType") is not None:
            raise OprindoError(
                "action_not_permitted",
                0,
                "c2pa.opened must not assert a digitalSourceType — the origin of "
                "content you opened is the parent manifest's to state",
            )
        if not has_prior_manifest:
            raise OprindoError(
                "action_not_permitted",
                0,
                "c2pa.opened requested but this asset carries no prior manifest to open",
            )
        resolved.append({**action, "parameters": {"ingredientIds": [PARENT_INGREDIENT_ID]}})
    return resolved


def _has_manifest(c2pa: Any, asset: bytes, mime_type: str, ctx: Any) -> bool:
    """Whether the asset already carries a readable C2PA manifest.

    "No manifest" and "unreadable manifest" are different answers and must stay
    different: the first is the ordinary case for content created here, the
    second means the asset's origin cannot be established. Only the first is
    reported as False — anything else propagates so the caller can refuse.
    """
    import io

    try:
        with c2pa.Reader(mime_type, io.BytesIO(asset), context=ctx) as reader:
            data = json.loads(reader.json())
    except c2pa.C2paError.ManifestNotFound:
        return False
    return bool(data.get("active_manifest"))


class OprindoError(Exception):
    def __init__(self, code: str, status: int, detail: str | None = None):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.status = status


@dataclass
class MarkResult:
    asset: bytes
    mime_type: str
    trust_state: str
    evidence_id: Optional[str]


class Oprindo:
    def __init__(self, api_key: str, base_url: str = "https://api.oprindo.com"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    # -- HTTP ---------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        auth: bool = True,
    ) -> tuple[int, bytes, dict[str, str]]:
        req = urllib.request.Request(self.base_url + path, data=body, method=method)
        if auth:
            req.add_header("authorization", f"Bearer {self.api_key}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as res:  # noqa: S310 (https URLs)
                return res.status, res.read(), dict(res.headers.items())
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers.items())

    def _json(self, method: str, path: str, payload: Any = None, auth: bool = True) -> tuple[int, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        status, raw, _ = self._request(
            method, path, body, {"content-type": "application/json"} if body else {}, auth
        )
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError:
            return status, {}

    # -- verbs --------------------------------------------------------------

    def mark(
        self,
        asset: bytes,
        mime_type: str,
        generator: dict[str, str],
        actions: list[dict[str, str]] | None = None,
        title: str | None = None,
        allow_full_service: bool = False,
    ) -> MarkResult:
        """Mark an asset with a signed C2PA manifest.

        Content-local when the ``c2pa`` extra is installed. Otherwise raises
        unless ``allow_full_service=True`` (asset bytes are then transmitted).
        """
        gen = dict(generator)
        if self.api_key.startswith("opr_test_") and _SANDBOX_MARKER not in gen.get("name", "").lower():
            gen["name"] = f"{gen['name']} ({_SANDBOX_MARKER})"

        try:
            import c2pa  # type: ignore  # optional extra
        except ImportError:
            c2pa = None

        if c2pa is not None:
            return self._mark_local(c2pa, asset, mime_type, gen, actions, title)
        if actions is not None:
            # Only the local path inspects the asset, so only it can tell
            # whether the requested action reflects the asset's origin.
            raise OprindoError(
                "content_local_unavailable",
                0,
                "explicit actions require content-local marking; install oprindo[c2pa]",
            )
        if not allow_full_service:
            raise OprindoError(
                "content_local_unavailable",
                0,
                "install oprindo[c2pa] for content-local marking, or pass "
                "allow_full_service=True to explicitly transmit the asset",
            )
        return self._mark_full_service(asset, mime_type)

    def _mark_local(
        self,
        c2pa: Any,
        asset: bytes,
        mime_type: str,
        generator: dict[str, str],
        actions: list[dict[str, Any]] | None,
        title: str | None,
    ) -> MarkResult:
        import io
        import secrets

        from ._claim_order import with_actions_assertion_first
        from ._cbor import cose_payload_span
        from ._manifest_store import (
            manifest_store_fragments,
            read_manifest_store,
            replace_in_store,
            signature_placeholder_span,
            write_manifest_store,
        )
        from ._settings import builder_settings, reader_settings

        status, info = self._json("GET", "/v1/signing-info", auth=False)
        if status != 200:
            raise OprindoError("signing_info_unavailable", status)
        cert_chain = "\n".join(info["cert_chain"])
        asset_sha256 = hashlib.sha256(asset).hexdigest()

        # Whether the input already carries provenance decides both that a
        # parentOf ingredient is added and that c2pa.opened can name it, so it
        # is settled once, up front, and both follow from the same answer.
        #
        # This read must not FAIL OPEN. An unreadable manifest is not the same
        # as no manifest, and treating it as one would assert c2pa.created over
        # content that arrived with provenance — the precise overreach the
        # inception-action rule exists to prevent, reintroduced through an error
        # path. Refuse instead.
        try:
            with c2pa.Context.from_dict(reader_settings()) as ctx:
                has_prior_manifest = _has_manifest(c2pa, asset, mime_type, ctx)
        except OprindoError:
            raise
        except Exception as exc:  # noqa: BLE001 — any read failure is a refusal
            raise OprindoError(
                "asset_unreadable",
                0,
                "this asset carries provenance that could not be read, so its origin "
                f"cannot be established and it will not be marked: {exc}",
            ) from exc

        resolved = _resolve_actions(
            actions if actions is not None else _default_actions(has_prior_manifest),
            has_prior_manifest,
        )

        captured: dict[str, bytes] = {}
        placeholder = secrets.token_bytes(64)

        def sign_callback(data: bytes) -> bytes:
            # The native binding accepts a raw ECDSA signature, not broker COSE.
            # Build a temporary manifest locally; replace its complete signature
            # box after asking the broker to inspect and sign the actual claim.
            payload = cose_payload_span(data)
            captured["claim"] = data[payload.start : payload.end]
            return placeholder

        manifest: dict[str, Any] = {
            "claim_generator_info": [
                {"name": generator["name"], "version": generator["version"]}
            ],
            "format": mime_type,
            "assertions": [{"label": "c2pa.actions", "data": {"actions": resolved}}],
        }
        if title:
            manifest["title"] = title

        out = io.BytesIO()
        with c2pa.Context.from_dict(builder_settings()) as ctx:
            with c2pa.Signer.from_callback(
                sign_callback, c2pa.C2paSigningAlg.ES256, cert_chain, None
            ) as signer:
                builder = c2pa.Builder.from_json(json.dumps(manifest), ctx)
                if has_prior_manifest:
                    # Reference the prior manifest as an ingredient rather than
                    # silently orphaning it — the builder's default drops it.
                    builder.add_ingredient(
                        json.dumps(
                            {
                                "title": "source asset",
                                "relationship": "parentOf",
                                "instance_id": PARENT_INGREDIENT_ID,
                            }
                        ),
                        mime_type,
                        io.BytesIO(asset),
                    )
                builder.sign(signer, mime_type, io.BytesIO(asset), out)

        signed = out.getvalue()
        original = captured.get("claim")
        if original is None:
            raise OprindoError("signing_failed", 502, "the builder did not produce a claim")
        claim = with_actions_assertion_first(original) or original
        fragments = manifest_store_fragments(signed, mime_type)
        if not fragments:
            raise OprindoError("signing_failed", 502, "no manifest store in the staged asset")
        store = read_manifest_store(signed, fragments)
        signature = signature_placeholder_span(store, placeholder)
        reserve_size = signature.end - signature.start
        request_claim: dict[str, Any] = {
            "claim_version": 1,
            "instance_id": f"xmp:iid:{uuid.uuid4()}",
            "format": mime_type,
            "claim_generator_info": generator,
            "assertions": [{"label": "c2pa.actions", "data": {"actions": resolved}}],
            "asset_sha256": asset_sha256,
            "claim_sha256": hashlib.sha256(claim).hexdigest(),
        }
        if title:
            request_claim["title"] = title
        status, response = self._json("POST", "/v1/sign-claim", {
            "claim": request_claim,
            "claim_bytes_b64": b64encode(claim).decode("ascii"),
            "reserve_size": reserve_size,
        })
        if status != 200:
            raise OprindoError(response.get("error", "signing_failed"), status)
        try:
            cose = b64decode(response["cose_sign1"], validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise OprindoError("signing_failed", 502, "no valid COSE signature in response") from exc
        if len(cose) != reserve_size:
            raise OprindoError("signing_failed", 502, "COSE signature does not fit the reserved box")
        store = replace_in_store(store, original, claim)
        store = store[:signature.start] + cose + store[signature.end:]
        signed = write_manifest_store(signed, fragments, store, mime_type)

        # Return only a completed, validated asset. A trusted response must
        # include a timestamp that actually validates against the TSA trust list.
        with c2pa.Context.from_dict(reader_settings()) as ctx:
            with c2pa.Reader(mime_type, io.BytesIO(signed), context=ctx) as reader:
                report = json.loads(reader.json())
        active = report.get("validation_results", {}).get("activeManifest", {})
        failures = {entry.get("code") for entry in active.get("failure", [])}
        codes = {entry.get("code") for entry in active.get("success", [])}
        if "claimSignature.validated" not in codes or failures - {"signingCredential.untrusted", "timeStamp.untrusted"}:
            raise OprindoError("signing_failed", 502, "the completed manifest did not validate")
        if response.get("trust_state") == "trusted":
            required = {"signingCredential.trusted", "claimSignature.validated", "timeStamp.trusted", "timeStamp.validated"}
            if failures or not required <= codes:
                raise OprindoError("signing_failed", 502, "trusted signing requires a validated timestamp and credential")
        return MarkResult(
            asset=signed,
            mime_type=mime_type,
            trust_state=response.get("trust_state", "unknown"),
            evidence_id=response.get("evidence_id"),
        )

    def _mark_full_service(self, asset: bytes, mime_type: str) -> MarkResult:
        status, raw, headers = self._request(
            "POST",
            "/v1/mark",
            asset,
            {"content-type": "application/octet-stream", "x-oprindo-mime": mime_type},
        )
        if status != 200:
            try:
                err = json.loads(raw).get("error", "mark_failed")
            except json.JSONDecodeError:
                err = "mark_failed"
            raise OprindoError(err, status)
        return MarkResult(
            asset=raw,
            mime_type=mime_type,
            trust_state=headers.get("x-oprindo-trust-state", "unknown"),
            evidence_id=headers.get("x-oprindo-evidence-id"),
        )

    def verify(self, asset: bytes, mime_type: str, allow_hosted: bool = True) -> dict[str, Any]:
        """Verify an asset's C2PA manifest.

        Local (no network) when the ``c2pa`` extra is installed; otherwise
        uses the hosted verify endpoint when ``allow_hosted`` is True.
        """
        try:
            import c2pa  # type: ignore
            import io

            reader = c2pa.Reader(mime_type, io.BytesIO(asset))
            data = json.loads(reader.json())
            active = data.get("manifests", {}).get(data.get("active_manifest") or "", {})
            return {
                "manifest_present": bool(active),
                "claim_generator": active.get("claim_generator"),
                "assertions": [a.get("label") for a in active.get("assertions", [])],
                "validation_status": data.get("validation_status") or [],
            }
        except ImportError:
            pass
        except Exception:
            return {"manifest_present": False, "claim_generator": None, "assertions": [], "validation_status": []}
        if not allow_hosted:
            raise OprindoError("local_verify_unavailable", 0, "install oprindo[c2pa]")
        status, raw, _ = self._request(
            "POST",
            "/v1/verify",
            asset,
            {"content-type": "application/octet-stream", "x-oprindo-mime": mime_type},
            auth=False,
        )
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise OprindoError("verify_failed", status)

    def evidence(
        self,
        from_ts: str | None = None,
        to_ts: str | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Fetch implementation-evidence records (paginated)."""
        params = {k: v for k, v in {"from": from_ts, "to": to_ts, "cursor": cursor}.items() if v}
        qs = ("?" + urllib.parse.urlencode(params)) if params else ""
        status, body = self._json("GET", f"/v1/evidence{qs}")
        if status != 200:
            raise OprindoError(body.get("error", "request_failed") if isinstance(body, dict) else "request_failed", status)
        return body
