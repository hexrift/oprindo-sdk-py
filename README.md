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

### Provenance actions

Omit `actions` and the SDK inspects the asset and picks the correct inception
action:

| Input | Action asserted |
| --- | --- |
| No prior manifest | `c2pa.created` + `digitalSourceType: trainedAlgorithmicMedia` |
| Already carries provenance | `c2pa.opened`, with the prior manifest referenced as a `parentOf` ingredient |

This matters for conformance. C2PA requires the inception action to reflect
origin: asserting `c2pa.created` over content that arrived with a manifest
claims an origin you cannot vouch for. Accordingly:

- `c2pa.created` on an asset that already carries provenance is **refused**.
- `c2pa.opened` must not carry a `digitalSourceType` — the origin of content you
  opened is the parent manifest's to state — and is refused if there is nothing
  to open.
- An asset whose existing provenance cannot be read is **refused rather than
  marked**, because "unreadable" is not "absent".

## Verify

```python
report = client.verify(asset_bytes, "image/jpeg")
```

Local when the `c2pa` extra is installed; hosted otherwise. The C2PA
Conformance Program CA and TSA trust lists ship with the package and are loaded
on the local path, so a credential chaining to a listed root reads as trusted
and certificate validity is judged at the trusted timestamp rather than at
"now".

## Conformance

Output conforms to the requirements the C2PA Conformance Program assessed
Oprindo against (record `019fa058-c512-7f87-a214-4d8cfbda73ce`, Generator
Product, Assurance Level 1):

- every assertion in the claim's `created_assertions`, with `gathered_assertions`
  empty;
- the actions assertion **first** in `created_assertions`;
- CA and TSA trust lists loaded on the validation and ingredient-ingestion paths;
- an inception action that reflects origin.

The second is not reachable through c2pa-rs configuration — it assembles claims
in a fixed order that never puts actions first when a claim thumbnail or
ingredient is present. The SDK therefore permutes the claim *inside the bytes
handed to the signer*, so the signature covers the permuted claim, then rewrites
the manifest store to match. The permutation moves raw CBOR byte slices, so the
claim keeps its exact length and JUMBF box lengths stay valid. See
`oprindo/_claim_order.py`.

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
