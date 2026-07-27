# oprindo

Python SDK for [Oprindo](https://oprindo.com) — C2PA signing identity and
implementation evidence for generative-AI providers.

## Your content stays local

With the `c2pa` extra installed, `mark()` assembles and embeds the C2PA manifest
**on your machine** — only the claim (kilobytes of metadata and hashes) is sent to
Oprindo. **Your media bytes never leave your process in this mode.**

Without the extra, `mark()` refuses to run unless you explicitly pass
`allow_full_service=True`, which transmits the asset to the hosted marking endpoint.
The choice is always yours and always explicit.

## Install

```sh
pip install oprindo[c2pa]     # content-local marking (recommended)
pip install oprindo           # stdlib-only: hosted verify + evidence
```

## Mark

```python
from oprindo import Oprindo

client = Oprindo(api_key=os.environ["OPRINDO_API_KEY"])

with open("generated.jpg", "rb") as f:
    result = client.mark(f.read(), "image/jpeg", generator={"name": "YourProduct", "version": "1.0.0"})

with open("generated.marked.jpg", "wb") as f:
    f.write(result.asset)

print(result.trust_state, result.evidence_id)
```

Every signature carries an explicit trust state (`sandbox`, `pre_conformance`, or
`trusted`) — never blurred. Test-key signatures carry a visible sandbox marker.

## Verify

```python
report = client.verify(asset_bytes, "image/jpeg")
```

Local when the `c2pa` extra is installed; hosted otherwise.

## Evidence

```python
records = client.evidence(from_ts="2026-08-01")
```

Append-only, hash-chained implementation-evidence records, mapped to EU
Transparency Code Section 1 measures.

## Scope

This SDK helps you implement and evidence Article 50 marking measures. Compliance
depends on your complete implementation and circumstances. Nothing here is legal
advice.

## License

Apache-2.0
