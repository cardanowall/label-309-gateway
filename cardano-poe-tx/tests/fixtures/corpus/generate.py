#!/usr/bin/env python3
"""Regenerate the deterministic corpus input fixtures.

The inputs here are shared by the Rust tests and an out-of-tree Node oracle, so
they must be byte-for-byte reproducible from these rules alone:

  * record bytes:  b[i] = (i * 7 + 13) mod 256
  * utxo tx_hash:  sha256("corpus:" + name + ":" + index) hex
  * change_address and network_id are fixed across the corpus (testnet)

The record bytes themselves are not stored in the fixtures (only `record_len`):
both the Rust harness and the Node oracle materialise them from the formula, so
the fixture stays small and the formula is the single source of truth. Run this
script and commit the resulting `inputs/*.json` whenever the case set changes.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

CHANGE_ADDRESS = "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4"
NETWORK_ID = 0
PROTOCOL = {
    "min_fee_a": 44,
    "min_fee_b": 155381,
    "coins_per_utxo_byte": 4310,
    "max_tx_size": 16384,
}

INPUTS_DIR = pathlib.Path(__file__).parent / "inputs"


def utxo_tx_hash(name: str, index: int) -> str:
    return hashlib.sha256(f"corpus:{name}:{index}".encode()).hexdigest()


def utxos(name: str, lovelaces: list[int]) -> list[dict]:
    return [
        {"tx_hash": utxo_tx_hash(name, i), "index": i, "lovelace": lovelace}
        for i, lovelace in enumerate(lovelaces)
    ]


def case(
    name: str,
    *,
    record_len: int,
    lovelaces: list[int],
    mode: str = "standard",
    validity=None,
    expect: str = "ok",
    utxo_name: str | None = None,
) -> dict:
    # `utxo_name` lets a derived case (competing_b) reuse another case's utxo
    # identities so the two share a common candidate pool.
    return {
        "name": name,
        "mode": mode,
        "protocol": PROTOCOL,
        "record_len": record_len,
        "utxos": utxos(utxo_name or name, lovelaces),
        "validity": validity,
        "expect": expect,
        "change_address": CHANGE_ADDRESS,
        "network_id": NETWORK_ID,
    }


def build_cases() -> list[dict]:
    cases: list[dict] = []

    # Single-output size sweep across the 64-byte metadata chunk boundary and
    # well past it. Each is funded by five identical 6 ADA utxos.
    for n in (1, 63, 64, 65, 127, 128, 129, 1024, 4096, 14000):
        cases.append(case(f"size_{n}", record_len=n, lovelaces=[6_000_000] * 5))

    # Forces selection of more than one input: each ~0.8 ADA utxo is too small
    # to fund the 1 KiB record on its own (the post-fee change would fall below
    # min-ADA), so the builder must combine at least two.
    cases.append(case("multi_input", record_len=1024, lovelaces=[800_000] * 4))

    # Change after fee falls below min-ADA and there is no further input to pull
    # in, so the leftover must fold entirely into the fee. A single ~0.85 ADA
    # input leaves sub-min-ADA change after the fee with nothing to add.
    cases.append(
        case("change_below_min_ada_fold", record_len=32, lovelaces=[850_000])
    )

    # Change after fee would fall below min-ADA, but a second input is available.
    # Selection is value-first, so the larger of the two inputs is tried alone:
    # it leaves sub-min-ADA change, so the builder pulls in the second input and
    # emits a valid change output instead of folding. Two ~1 ADA inputs make the
    # single-input change fall below the floor while the combined change clears
    # it.
    cases.append(
        case(
            "change_below_min_ada_add_input",
            record_len=32,
            lovelaces=[1_000_000, 1_000_000],
        )
    )

    # Exact-fit selection mode over five 6 ADA utxos.
    cases.append(
        case("exact_fit", record_len=256, lovelaces=[6_000_000] * 5, mode="exact_fit")
    )

    # TTL-only validity, on the size_1024 funding shape.
    cases.append(
        case(
            "ttl_set",
            record_len=1024,
            lovelaces=[6_000_000] * 5,
            validity={"invalid_hereafter": 100_000_000, "valid_from": None},
        )
    )

    # Both TTL and a lower validity bound.
    cases.append(
        case(
            "ttl_and_valid_from",
            record_len=1024,
            lovelaces=[6_000_000] * 5,
            validity={"invalid_hereafter": 100_000_000, "valid_from": 50_000_000},
        )
    )

    # A single tiny utxo cannot cover fee plus min-ADA change.
    cases.append(
        case("insufficient", record_len=1024, lovelaces=[200_000], expect="insufficient_funds")
    )

    # competing_a / competing_b share a candidate identity space; competing_b is
    # competing_a minus the lexicographically-first utxo (by tx_hash hex). The
    # pair pins that selection is a pure function of the candidate set (so the
    # two select different inputs), independent of the order the utxos are
    # listed in.
    competing_pool = utxos("competing", [6_000_000] * 6)
    competing_a = {
        "name": "competing_a",
        "mode": "standard",
        "protocol": PROTOCOL,
        "record_len": 1024,
        "utxos": competing_pool,
        "validity": None,
        "expect": "ok",
        "change_address": CHANGE_ADDRESS,
        "network_id": NETWORK_ID,
    }
    first_hash = min(u["tx_hash"] for u in competing_pool)
    competing_b = dict(competing_a)
    competing_b["name"] = "competing_b"
    competing_b["utxos"] = [u for u in competing_pool if u["tx_hash"] != first_hash]
    cases.append(competing_a)
    cases.append(competing_b)

    return cases


def main() -> None:
    INPUTS_DIR.mkdir(parents=True, exist_ok=True)
    for c in build_cases():
        path = INPUTS_DIR / f"{c['name']}.json"
        path.write_text(json.dumps(c, indent=2) + "\n")
    print(f"wrote {len(build_cases())} fixtures to {INPUTS_DIR}")


if __name__ == "__main__":
    main()
