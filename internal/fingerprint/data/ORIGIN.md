# Fingerprint reference artifacts

The bundled detector is a local copy of [Ikaleio/lm-detector](https://github.com/Ikaleio/lm-detector), distributed under the original MIT license (copyright xqy2006). No online scoring service is used.

## Pinned upstream version

- Repository: https://github.com/Ikaleio/lm-detector
- Commit: [`a4ef212df06817e8071acd05f00219f4c9eb2f9a`](https://github.com/Ikaleio/lm-detector/commit/a4ef212df06817e8071acd05f00219f4c9eb2f9a)
- Bank built at: `2026-10-27T05:02:50.758637+00:00`
- Schema: `shared-detector-v2`
- Models: **64** (previously 60), adding `kimi-k3.1-pro`, `gemini-3.5-flash-lite`, `minimax-m3.1-flash` and `gpt-6.1-terra`.
- Scorer: synchronized with the upstream 2026-10-24 `sequenceShape` fix ([`ef6badb71016`](https://github.com/Ikaleio/lm-detector/commit/ef6badb71016)): reject non-model sequences only if **both** sequence signals fail.

## Content SHA-256

| Artifact | SHA-256 |
| --- | --- |
| Bundled `data/shared_detector.bin` | `9ac93e5e580f5bac887f97a20bfae15d0a3ad08c6372e4b3552fce6708078a80` |
| Upstream `data/unified_bank.json` (metadata source, not bundled) | `7117831989ca8e1793cd954899ec5f614541a37ea65a4174b711f80e6036fb1b` |
| Generated `data/model_metadata.json` | `42a2856119bb663917afd9ac7c56c22b0db831cd06b873a17418df615b675dc5` |

## Reproducibility

Run from repository root:

```sh
python3 scripts/sync-fingerprint-bank.py --check
python3 scripts/sync-fingerprint-bank.py --write
```

The script pins the upstream commit and expected checksums, and checks the build timestamp, source reference hash, model ID order and model counts before replacing the data files.

`internal/fingerprint/testdata/official_results.json` was regenerated using the original upstream JavaScript `analyzeSharedOutputs` and binary decoder from the pinned commit against the existing 16 sample groups. Only the local `.ts` import extension in `shared-detector.ts` was adjusted for Node 24 module resolution. The Go port is compared against these independent upstream scores by `TestOriginalJavaScriptParity` (1e-6 tolerance for scores and probabilities).

**Important:** Updated reference data can change rankings for pre-existing models. Since unavailable automatic checks also trigger isolation, validate reference mappings and detection behavior in observation mode before enabling production routing.
