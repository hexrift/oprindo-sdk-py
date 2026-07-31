"""Puts the actions assertion first in the claim's ``created_assertions``.

The C2PA Conformance Program requires the actions assertion to be the first
entry. c2pa-rs assembles a claim in a fixed order — claim thumbnail, ingredient
thumbnails, ingredients, manifest-definition assertions, hard binding — which
puts actions fourth whenever an ingredient is present and second whenever a
claim thumbnail is. Nothing in the settings or the Builder API changes that
order, so the claim is permuted after c2pa-rs builds it and before it is signed.

The permutation moves raw CBOR byte slices, so the claim keeps exactly its
original length and the JUMBF box holding it does not have to be resized.
"""

from __future__ import annotations

import re

from ._cbor import array_element_spans, map_value_spans, read_text_string

#: The assertion whose reference must come first.
ACTIONS_LABEL = "c2pa.actions"

_MULTI_INSTANCE = re.compile(r"__\d+$")
_ASSERTION_VERSION = re.compile(r"\.v\d+$")


def _referenced_label(url: str) -> str:
    """The label an assertion reference points at.

    ``self#jumbf=c2pa.assertions/c2pa.actions.v2`` becomes ``c2pa.actions``.
    Multi-instance (``__1``) and assertion-version (``.v2``) suffixes are
    stripped: they name the same assertion family.
    """
    _, _, tail = url.partition("c2pa.assertions/")
    if not tail:
        return ""
    return _ASSERTION_VERSION.sub("", _MULTI_INSTANCE.sub("", tail))


def _index_of_actions(claim: bytes, elements: list) -> int:
    """Index of the entry referencing the actions assertion, or -1."""
    for i, element in enumerate(elements):
        url = map_value_spans(claim, element.start).get("url")
        if url is None:
            continue
        text = read_text_string(claim, url.start)
        if text is not None and _referenced_label(text) == ACTIONS_LABEL:
            return i
    return -1


def with_actions_assertion_first(claim: bytes) -> bytes | None:
    """Rewrite ``claim`` with the actions assertion moved to the front of
    ``created_assertions``, preserving the relative order of everything else.

    Returns None when no rewrite is needed or possible — no
    ``created_assertions``, no actions reference, or it is already first — so
    the caller can skip the splice.

    Raises:
        ValueError: if the rewrite would change the claim's length, which must
            never happen and would corrupt the manifest store if it did.
    """
    fields = map_value_spans(claim, 0)
    created = fields.get("created_assertions")
    if created is None:
        return None
    array = array_element_spans(claim, created.start)
    if len(array.elements) < 2:
        return None

    actions_at = _index_of_actions(claim, array.elements)
    if actions_at <= 0:
        return None

    reordered = [array.elements[actions_at]] + [
        element for i, element in enumerate(array.elements) if i != actions_at
    ]
    rewritten = b"".join(
        [claim[: array.first]]  # everything up to the first entry
        + [claim[span.start : span.end] for span in reordered]  # entries, actions first
        + [claim[array.end :]]  # everything after the array
    )

    if len(rewritten) != len(claim):
        raise ValueError(
            f"claim-order: rewrite changed claim length {len(claim)} -> {len(rewritten)}"
        )
    return rewritten
