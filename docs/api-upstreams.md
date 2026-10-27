# API upstream monitoring

The guard monitors explicitly enrolled Magpie API keys alongside Codex
logins. Upstream credentials remain in Magpie's private `providers.json`; the
guard console and SQLite state contain stable identities only.

## Enrollment

1. Add the provider through Magpie's provider editor, with its Responses endpoint,
   API key and model list.
2. Create `api-upstreams.json` beside `providers.json`, owned by the Magpie user
   with mode `0600`:

   ```json
   [{"provider":"example","key_id":"0123456789","name":"Example API"}]
   ```

   `key_id` is the first ten hexadecimal characters of SHA-256 of the saved API
   key. Never put the key itself in this file. Enrollment is explicit to avoid
   spending probe quota on every configured provider.
3. In the guard console, add the enrolled API account with its qualified model,
   such as `example/gpt-6.1-sol`. If the model maps to the local fingerprint
   library, automatic fingerprint scoring works without a separate saved
   expected-model setting. Unknown aliases remain neutral until explicitly
   mapped via the advanced reference override.

The stable monitoring ID incorporates the provider and key fingerprint. Probes
resolve Magpie's native routing trace ID: `provider` for one active key, or
`provider#key_id` for multiple active keys. The saved key must still be active;
discovery fails rather than silently testing a replacement. A rotated key needs
explicit enrollment and a new monitoring target.

## Isolation and recovery

- Healthy targets default to one check every 30 minutes; intervals and
  request timeouts can be customized globally or per API monitoring target.
- One completed fingerprint question contains three samples. A reliable
  mismatch immediately isolates the API provider; no additional fingerprint
  review or high/low risk classification runs.
- Other objective questions require three wrong answers to the same question
  before isolation. Inconclusive results and transport failures, including
  HTTP 429, do not count as quality failures.
- Recovery uses the same question twice, with a customizable confirmation
  interval. The first and subsequent quarantine retests have independently
  configurable intervals (default 6 hours, then 24 hours).
- API isolation removes the provider from production Gateway Key `models`
  scopes. This currently isolates the **whole provider**, including its other
  keys and models. Use separate provider entries for independent isolation.
- The dedicated probe key retains access for recovery. Successful recovery
  restores each production key's original model scope.
- Empty model scopes mean unrestricted access in Magpie. If isolation would
  leave no permitted model, the key is disabled instead.
- Explicit provider scopes are required while API isolation is active. Group
  aliases or wildcard provider prefixes cause a conflict instead of being
  silently rewritten. External permission edits are detected and preserved.
- Magpie requires access to every member of an unnamed routing group. Therefore
  an automatic group containing an isolated API provider is unavailable while
  that hold is active. Call a healthy qualified model, such as
  `codex/gpt-6.1-sol` or `example/gpt-6.1-sol`, during isolation. The guard
  does not alter Magpie's group authorization semantics.
- Codex quarantine continues to use native account allowlists. API identities
  do not change the expected Codex login count.

Fingerprint scores are statistical comparisons with the selected reference;
they do not prove the upstream model's identity. For example, the reference
category displayed as `gpt-6-astra/6.1-sol` has the internal ID `gpt-6-astra`.

## Validation

`go test ./... -count=1` covers fixed routing, provider/model binding, automatic
question-specific failure thresholds, production isolation, custom
timing policies, dedicated probe access, persistence,
recovery, HTTP 429 handling and external scope conflicts. The routing identity
tests cover single, multiple, disabled and duplicate saved keys.

## Packaging

Build and install a package containing the updated helper with
`npm run build:release`. A source-only `github:` installation at alpha.21 pins the immutable,
verified alpha.20 backend including unified quarantine and custom timings.
The alpha.21 complete Release package includes the freshly built Go helper.
Both installation paths retain SHA-256 integrity checks.
