# Fingerprint reference artifacts

The bundled detector is a local copy of [Ikaleio/lm-detector](https://github.com/Ikaleio/lm-detector), distributed under the original MIT license (copyright xqy2006). No online scoring service is used.

## Pinned upstream version

- Repository: https://github.com/Ikaleio/lm-detector
- Commit: [`7663b6580cb6c9123da72e9218e700537544f1db`](https://github.com/Ikaleio/lm-detector/commit/7663b6580cb6c9123da72e9218e700537544f1db)
- Bank built at: `2026-11-17T19:37:59.839365+00:00`
- Schema: `shared-detector-v2`
- Models: **72** (previously 64), adding `openpangu-2.0-flash`, `openpangu-2.0-pro`, `muse-ember`, `claude-fable-5.2`, `gemini-4-carbon`, `gemini-4-hydrogen`, `gpt-6.2-sol`, and `gpt-6.2-astra`. No prior model IDs were removed.
- Scorer: synchronized with the upstream 2026-10-24 `sequenceShape` fix ([`ef6badb71016`](https://github.com/Ikaleio/lm-detector/commit/ef6badb71016)): reject non-model sequences only if **both** sequence signals fail.

## Content SHA-256

| Artifact | SHA-256 |
| --- | --- |
| Bundled `data/shared_detector.bin` | `f6cf5bb49f621690da7eba3173b34ea978af19b51987a65e0b37c424d5904343` |
| Upstream `data/unified_bank.json` (metadata source, not bundled) | `8e7a0083dc66d941229c49e195c503a4362d1b33edd2aa6318877849eef7b691` |
| Generated `data/model_metadata.json` | `417c29228d77016790731e03e5ceacc94a2ba67d44212968821cf8c4d4e75158` |

## Reproducibility

Run from repository root:

```sh
python3 scripts/sync-fingerprint-bank.py --check
python3 scripts/sync-fingerprint-bank.py --write
```

The script pins the upstream commit and expected checksums, and checks the build timestamp, source reference hash, model ID order and model counts before replacing the data files.

`internal/fingerprint/testdata/official_results.json` was regenerated using the original upstream JavaScript `analyzeSharedOutputs` and binary decoder from the pinned commit against 16 frozen sample groups. Their top-1 predictions remain unchanged; 15 of 16 golden result records changed because rankings or calibrated probabilities changed. The source scorer files (`shared-detector.ts`, `fingerprint-core.js`, `positional.ts`, and `detector-codec.ts`) are byte-identical to the previous pinned revision. Only the local `.ts` import extension in `shared-detector.ts` was adjusted for Node 24 module resolution. The Go port is compared against these independent upstream scores by `TestOriginalJavaScriptParity` (1e-6 tolerance for scores and probabilities).

**Important:** Updated reference data can change rankings for pre-existing models. Since unavailable automatic checks also trigger isolation, validate reference mappings and detection behavior in observation mode before enabling production routing.
