# Original implementation

`cipher1_original.py` and `cipher2_original.py` are the two scripts this
package replaces, kept verbatim for provenance and for comparison against the
rewrite.

They are **not** importable as part of `cipherx` and should not be used. Both
contain a silent data-corruption bug in the block-padding stage
(`rstrip('X')`), which destroys any message whose pre-padding form ends in a
literal `'X'`:

| Structural key | Custom-layer round-trip failures |
|---|---|
| `akanksh-super-unique-key` (their shipped default) | 0 % |
| `my-secret-m-key` | 6.5 % |
| `demo-key-2025` | 10 % |
| `MMMM` | 69 % |

The default key masks the bug by coincidence. See `docs/PAPER_MAPPING.md`
(difference D3) for the full explanation, and
`tests/test_structural.py::TestBlockPermutation::test_payload_ending_in_x_survives`
for the regression that pins the fix.
