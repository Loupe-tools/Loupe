#!/usr/bin/env python3
"""build_test_mmdb.py — emit minimal valid MMDB fixtures for unit tests.

Used by tests/unit/mmdb-reader.test.js. Outputs two committed fixtures:

  • `tests/fixtures/test-country.mmdb` — geo (country-only) DB with
    nested-schema records (`country.iso_code`, `country.names.en`).
  • `tests/fixtures/test-asn.mmdb`     — ASN DB with
    `autonomous_system_number` + `autonomous_system_organization` records.

CI runs the parser unit tests against both without needing the 8 MB
DB-IP fixture.

Format reference:
  https://maxmind.github.io/MaxMind-DB/

What this builder produces:
  • IPv4-only tree (`ip_version: 4`), 24-bit records (smallest legal
    record_size — 6 bytes per node).
  • Four leaf records mapped to four canonical IPv4 prefixes:
      8.8.8.0/24      → United States   / US
      1.1.1.0/24      → Australia       / AU
      193.0.0.0/24    → Netherlands     / NL
      210.130.0.0/16  → Japan           / JP
    All other addresses fall through to "no record" (record value
    equal to node_count, which the reader treats as a miss).
  • Decoded metadata map with all required fields:
      binary_format_major_version: 2
      binary_format_minor_version: 0
      build_epoch: 1761955200 (2025-11-01 UTC; pinned)
      database_type: 'Loupe-Test-Country'
      ip_version: 4
      languages: ['en']
      node_count: <computed>
      record_size: 24

The output file is byte-deterministic for a given source — the build
script uses `SOURCE_DATE_EPOCH` to pin `build_epoch` if the env var is
set (CI sets this; locally it falls back to a hard-coded value so the
fixture diff stays empty across rebuilds).

Encoding helpers below intentionally cover ONLY the types this fixture
needs: utf-8 strings, uint16, uint32, maps. The reader supports more,
but every additional encoder is more code to audit.

Re-run with:
  python scripts/misc/build_test_mmdb.py

The output is committed to `tests/fixtures/test-country.mmdb`. CI does
NOT regenerate it on every build — the fixture is treated as a static
asset, and a regression in this script would surface as a unit-test
failure (the reader's expected ISO codes wouldn't match).
"""

from __future__ import annotations

import os
import sys


# ── Type-byte constants (MMDB type field, stored in high 3 bits) ──────────
T_POINTER = 1
T_UTF8    = 2
T_UINT16  = 5
T_UINT32  = 6
T_MAP     = 7
T_ARRAY   = 11


def _control_byte(typ: int, payload_len: int) -> bytes:
    """Encode the control byte + (optional) length-extension bytes.

    Per spec, payload_len < 29 fits in the low 5 bits of the control
    byte; 29..284 uses one extension byte holding `payload_len - 29`;
    285..65820 uses two extension bytes; etc. We support the first two
    ranges because the ASN fixture's key
    `autonomous_system_organization` is 30 bytes — past the 5-bit
    immediate range, but well under one extension byte's worth.

    Types 0..7 fit the high-3-bits field directly. Types 8..15 use the
    "extended" form: high 3 bits = 0, and one extra byte after the
    control byte holds (real_type - 7). Both branches are needed
    because this fixture uses MMDB_TYPE_ARRAY (11) for the `languages`
    metadata field.
    """
    if payload_len < 0:
        raise ValueError(f'negative payload_len: {payload_len}')
    if payload_len < 29:
        len_field = payload_len
        ext_bytes = b''
    elif payload_len <= 28 + 0xFF:
        # One-byte extension: control len-field = 29, extra byte = (n - 29).
        len_field = 29
        ext_bytes = bytes([payload_len - 29])
    elif payload_len <= 285 + 0xFFFF:
        # Two-byte extension: control len-field = 30, two extra bytes BE.
        len_field = 30
        ext_bytes = (payload_len - 285).to_bytes(2, 'big')
    else:
        raise NotImplementedError(f'payload_len {payload_len} too large')
    if typ <= 7:
        return bytes([(typ << 5) | len_field]) + ext_bytes
    # Extended type: high 3 bits = 0 (MMDB_TYPE_EXTENDED), len_field
    # in the low 5 bits, then one byte = typ - 7, then ext bytes.
    return bytes([len_field, typ - 7]) + ext_bytes


def enc_utf8(s: str) -> bytes:
    """UTF-8 string with a (possibly extended) length control byte."""
    payload = s.encode('utf-8')
    return _control_byte(T_UTF8, len(payload)) + payload


def enc_uint(typ: int, n: int) -> bytes:
    """Big-endian uint with minimal-byte encoding (drop leading zeros)."""
    if n < 0:
        raise ValueError(f'unsigned only, got {n}')
    if n == 0:
        return _control_byte(typ, 0)
    payload = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return _control_byte(typ, len(payload)) + payload


def enc_uint16(n: int) -> bytes:
    return enc_uint(T_UINT16, n)


def enc_uint32(n: int) -> bytes:
    return enc_uint(T_UINT32, n)


def enc_map(items: list[tuple[str, bytes]]) -> bytes:
    """A map is `<control-byte: type=7, payload_len = entry-count>`
    followed by `entry-count` (key, value) pairs. Keys are utf-8."""
    out = bytearray(_control_byte(T_MAP, len(items)))
    for key, val_bytes in items:
        out += enc_utf8(key)
        out += val_bytes
    return bytes(out)


def enc_array(elements: list[bytes]) -> bytes:
    out = bytearray(_control_byte(T_ARRAY, len(elements)))
    for el in elements:
        out += el
    return bytes(out)


# ── Record builder for one leaf "country" entry ───────────────────────────
def country_record(country_name: str, iso2: str) -> bytes:
    """Produce the GeoLite2-shaped data record for a country-only entry.

    Shape:
      { country: { iso_code: <ISO2>, names: { en: <Name> } } }
    """
    names_map = enc_map([('en', enc_utf8(country_name))])
    country_map = enc_map([
        ('iso_code', enc_utf8(iso2)),
        ('names', names_map),
    ])
    return enc_map([('country', country_map)])


# ── Record builder for one leaf "ASN" entry ──────────────────────────────
def asn_record(asn: int, org: str) -> bytes:
    """Produce the GeoLite2-ASN shaped data record for an ASN entry.

    Shape:
      { autonomous_system_number: <uint>, autonomous_system_organization: <utf8> }
    """
    return enc_map([
        ('autonomous_system_number', enc_uint32(asn)),
        ('autonomous_system_organization', enc_utf8(org)),
    ])


# ── 24-bit search-tree node encoder ───────────────────────────────────────
def encode_node_24(left: int, right: int) -> bytes:
    """24-bit record: 6 bytes per node (3 bytes left, 3 bytes right)."""
    if left < 0 or left > 0xFFFFFF or right < 0 or right > 0xFFFFFF:
        raise ValueError('24-bit overflow')
    return left.to_bytes(3, 'big') + right.to_bytes(3, 'big')


# ── Tree construction ─────────────────────────────────────────────────────
# We build a minimal IPv4 prefix-trie. Each node has left (0-bit branch)
# and right (1-bit branch). For an internal node, the branches point at
# child node indices (< node_count). For a leaf, the branch points at
# `node_count + dataOffsetWithin DataSection + 16` per the MMDB spec
# convention: "values >= node_count refer to data records; subtract
# node_count + 16 to get the byte offset into the data section after
# the 16-byte zero separator". (The reader walks tree until value
# >= node_count, then computes data_offset = value - node_count - 16
# relative to data section start. See `_findIpv4` in mmdb-reader.js.)
#
# Special "no record" sentinel: any branch pointing at `node_count`
# itself is treated as a miss by the reader.


def build_tree(prefixes: list[tuple[int, int, int]]) -> tuple[bytes, dict[int, int], int]:
    """Build a 32-level binary trie covering the supplied prefixes.

    `prefixes` is a list of `(start_ip_uint32, prefix_len, data_record_index)`.
    `data_record_index` is the position of the leaf's data record within
    the DATA-RECORDS-CONCATENATED-IN-ORDER sequence; we resolve those
    to byte offsets later once we know the data section's layout.

    Returns:
      tree_bytes              — 6 * node_count bytes
      data_idx_to_node_value  — map from data_record_index to the leaf
                                value that should be stored at the
                                appropriate tree slot. Computed once
                                we know node_count + each record's
                                offset within the data section.
      node_count              — number of nodes in the tree
    """
    # Each internal node lives at an index. Index 0 is the root.
    # We allocate as we descend each prefix, splitting nodes that are
    # currently "no record" (left=right=0 placeholder, fixed up
    # later).
    NO_RECORD_PLACEHOLDER = -1  # resolved to node_count post-build
    LEAF_PLACEHOLDER = -2       # marks "this is a leaf for this prefix"

    nodes: list[list[int]] = [[NO_RECORD_PLACEHOLDER, NO_RECORD_PLACEHOLDER]]

    # Track which (node_idx, branch) is a leaf for which data record so
    # we can fix up after we know node_count.
    leaf_assignments: list[tuple[int, int, int]] = []  # (node_idx, branch, data_record_idx)

    for start_ip, prefix_len, data_idx in prefixes:
        if prefix_len < 1 or prefix_len > 32:
            raise ValueError(f'bad prefix_len: {prefix_len}')
        cur = 0
        for depth in range(prefix_len - 1):
            bit = (start_ip >> (31 - depth)) & 1
            child = nodes[cur][bit]
            if child < 0:
                # Allocate a fresh internal node here; the placeholder
                # gets replaced with the new node's index.
                new_idx = len(nodes)
                nodes.append([NO_RECORD_PLACEHOLDER, NO_RECORD_PLACEHOLDER])
                nodes[cur][bit] = new_idx
                cur = new_idx
            else:
                cur = child
        # Final bit: assign a leaf
        leaf_bit = (start_ip >> (31 - (prefix_len - 1))) & 1
        leaf_assignments.append((cur, leaf_bit, data_idx))
        nodes[cur][leaf_bit] = LEAF_PLACEHOLDER

    return nodes, leaf_assignments


def _emit_mmdb(out_path: str,
               prefixes: list[tuple[int, int]],
               record_blobs: list[bytes],
               database_type: str) -> int:
    """Shared writer: turn a list of `(start_ip, prefix_len)` prefixes
    plus a parallel list of pre-encoded data records into a complete
    MMDB byte stream.

    Returns the number of nodes (for diagnostics)."""
    if len(prefixes) != len(record_blobs):
        raise ValueError('prefix / record count mismatch')

    record_offsets: list[int] = []
    cursor = 0
    for blob in record_blobs:
        record_offsets.append(cursor)
        cursor += len(blob)

    prefix_input = [(s, p, i) for i, (s, p) in enumerate(prefixes)]
    nodes, leaf_assignments = build_tree(prefix_input)
    node_count = len(nodes)
    NO_RECORD_VALUE = node_count

    LEAF_PLACEHOLDER = -2
    NO_RECORD_PLACEHOLDER = -1

    leaf_table: dict[tuple[int, int], int] = {}
    for node_idx, branch, data_idx in leaf_assignments:
        leaf_table[(node_idx, branch)] = data_idx

    final_nodes: list[tuple[int, int]] = []
    for idx, (left, right) in enumerate(nodes):
        new_left = left
        new_right = right
        if new_left == LEAF_PLACEHOLDER:
            data_idx = leaf_table[(idx, 0)]
            new_left = node_count + 16 + record_offsets[data_idx]
        elif new_left == NO_RECORD_PLACEHOLDER:
            new_left = NO_RECORD_VALUE
        if new_right == LEAF_PLACEHOLDER:
            data_idx = leaf_table[(idx, 1)]
            new_right = node_count + 16 + record_offsets[data_idx]
        elif new_right == NO_RECORD_PLACEHOLDER:
            new_right = NO_RECORD_VALUE
        final_nodes.append((new_left, new_right))

    tree_bytes = bytearray()
    for left, right in final_nodes:
        tree_bytes += encode_node_24(left, right)

    data_section = bytearray()
    for blob in record_blobs:
        data_section += blob

    SOURCE_DATE_EPOCH = int(os.environ.get('SOURCE_DATE_EPOCH', '1761955200'))
    metadata_map = enc_map([
        ('binary_format_major_version', enc_uint16(2)),
        ('binary_format_minor_version', enc_uint16(0)),
        ('build_epoch', enc_uint32(SOURCE_DATE_EPOCH)),
        ('database_type', enc_utf8(database_type)),
        ('ip_version', enc_uint16(4)),
        ('languages', enc_array([enc_utf8('en')])),
        ('node_count', enc_uint32(node_count)),
        ('record_size', enc_uint16(24)),
    ])

    metadata_marker = bytes([
        0xAB, 0xCD, 0xEF,
        0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D,
    ])
    payload = bytes(tree_bytes) + b'\x00' * 16 + bytes(data_section) + metadata_marker + metadata_map

    with open(out_path, 'wb') as f:
        f.write(payload)

    print(f'OK  Wrote {out_path}  ({len(payload):,} bytes, '
          f'{node_count} nodes, {len(prefixes)} prefixes)')
    return node_count


def main() -> int:
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'tests', 'fixtures',
    )
    os.makedirs(out_dir, exist_ok=True)

    # ── Geo (country) fixture ─────────────────────────────────────────
    # Each tuple: (start_ip_uint32, prefix_len, country_name, iso2)
    #   8.8.8.0/24    = 0x08080800 / 24
    #   1.1.1.0/24    = 0x01010100 / 24
    #   193.0.0.0/24  = 0xC1000000 / 24
    #   210.130.0.0/16 = 0xD2820000 / 16
    geo_mappings = [
        (0x08080800, 24, 'United States', 'US'),
        (0x01010100, 24, 'Australia', 'AU'),
        (0xC1000000, 24, 'Netherlands', 'NL'),
        (0xD2820000, 16, 'Japan', 'JP'),
    ]
    _emit_mmdb(
        os.path.join(out_dir, 'test-country.mmdb'),
        prefixes=[(s, p) for (s, p, _c, _iso) in geo_mappings],
        record_blobs=[country_record(c, iso) for (_s, _p, c, iso) in geo_mappings],
        database_type='Loupe-Test-Country',
    )

    # ── ASN fixture ───────────────────────────────────────────────────
    # Each tuple: (start_ip_uint32, prefix_len, asn, org)
    # Real-world AS numbers for the same addresses the country fixture
    # covers, so unit tests can exercise both readers off the same IPs:
    #   8.8.8.0/24     → AS15169  Google LLC
    #   1.1.1.0/24     → AS13335  Cloudflare, Inc.
    #   193.0.0.0/24   → AS3333   RIPE NCC
    #   210.130.0.0/16 → AS2516   KDDI CORPORATION
    asn_mappings = [
        (0x08080800, 24, 15169, 'Google LLC'),
        (0x01010100, 24, 13335, 'Cloudflare, Inc.'),
        (0xC1000000, 24,  3333, 'RIPE NCC'),
        (0xD2820000, 16,  2516, 'KDDI CORP'),
    ]
    _emit_mmdb(
        os.path.join(out_dir, 'test-asn.mmdb'),
        prefixes=[(s, p) for (s, p, _a, _o) in asn_mappings],
        record_blobs=[asn_record(a, o) for (_s, _p, a, o) in asn_mappings],
        database_type='Loupe-Test-ASN',
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
