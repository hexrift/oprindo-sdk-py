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
from base64 import b64decode
from dataclasses import dataclass
from typing import Any, Optional

from ._der import ecdsa_der_to_raw

DEFAULT_ACTIONS = [
    {
        "action": "c2pa.created",
        "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
    }
]

_SANDBOX_MARKER = "oprindo-sandbox"


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
        actions = actions or DEFAULT_ACTIONS
        gen = dict(generator)
        if self.api_key.startswith("opr_test_") and _SANDBOX_MARKER not in gen.get("name", "").lower():
            gen["name"] = f"{gen['name']} ({_SANDBOX_MARKER})"

        try:
            import c2pa  # type: ignore  # optional extra
        except ImportError:
            c2pa = None

        if c2pa is not None:
            return self._mark_local(c2pa, asset, mime_type, gen, actions, title)
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
        actions: list[dict[str, str]],
        title: str | None,
    ) -> MarkResult:
        status, info = self._json("GET", "/v1/signing-info", auth=False)
        if status != 200:
            raise OprindoError("signing_info_unavailable", status)
        cert_chain = "\n".join(info["cert_chain"]).encode()
        asset_sha256 = hashlib.sha256(asset).hexdigest()
        state: dict[str, Any] = {}

        def sign_callback(data: bytes) -> bytes:
            claim = {
                "claim_version": 1,
                "instance_id": f"xmp:iid:{uuid.uuid4()}",
                "format": mime_type,
                "claim_generator_info": generator,
                "assertions": [{"label": "c2pa.actions", "data": {"actions": actions}}],
                "asset_sha256": asset_sha256,
                "claim_sha256": hashlib.sha256(data).hexdigest(),
            }
            if title:
                claim["title"] = title
            s, resp = self._json("POST", "/v1/sign-claim", {"claim": claim})
            if s != 200:
                raise OprindoError(resp.get("error", "signing_failed"), s)
            state["trust_state"] = resp["trust_state"]
            state["evidence_id"] = resp.get("evidence_id")
            # Digest path returns a DER ECDSA signature; COSE needs raw r||s.
            return ecdsa_der_to_raw(b64decode(resp["signature"]))

        signer = c2pa.create_signer(sign_callback, c2pa.SigningAlg.ES256, cert_chain, None)
        manifest = {
            "claim_generator": f"{generator['name']}/{generator['version']}",
            "format": mime_type,
            "assertions": [{"label": "c2pa.actions", "data": {"actions": actions}}],
        }
        if title:
            manifest["title"] = title
        builder = c2pa.Builder(json.dumps(manifest))
        import io

        out = io.BytesIO()
        builder.sign(signer, mime_type, io.BytesIO(asset), out)
        return MarkResult(
            asset=out.getvalue(),
            mime_type=mime_type,
            trust_state=state.get("trust_state", "unknown"),
            evidence_id=state.get("evidence_id"),
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
