# API upstream compatibility

Starting with alpha.33, automatic detection, quarantine, recovery and production
route synchronization manage **Codex accounts only**. Other providers remain
under the administrator's control.

Existing explicitly enrolled API upstreams can still be selected for manual
objective or fingerprint diagnostics. These requests use the same dedicated
probe Key selected in the Guard console. Results are historical diagnostics;
they do not change production permissions or create automatic provider holds.
Legacy API targets are skipped by the automatic scheduler. Legacy API hold
records are not used to restrict any provider's models.

## Existing enrollment

Manual diagnostics can use the existing private `api-upstreams.json` file in
Magpie's data directory:

```json
[{"provider":"example","key_id":"0123456789","name":"Example API"}]
```

The key identifier is the first ten hexadecimal characters of the SHA-256 of
the API key already stored in Magpie's provider configuration. Do not duplicate
raw upstream credentials in this file. Qualified models such as
`example/gpt-model` stay pinned to the enrolled upstream identity; they are not
fallback candidates for a Codex detection request.

## Full Codex quarantine

Independent providers do not require enrollment to remain production fallback
candidates. Guard reads actual providers and mixed routing groups dynamically.
It removes only Codex account selections and, when necessary, temporarily
restricts Codex model access or Codex group members using the existing safe
fallback mechanism. Provider names, model names and group names are not fixed.

Other-provider account selections, administrator model permissions, disabled
keys, group members, ordering, priorities and routing strategies are preserved.
An administrator editing those fields does not require whitelist approval.
On recovery, Guard removes only its own temporary restrictions. Where a key's
ambiguous/unlimited model scope cannot safely retain independent traffic, the
existing conservative key-disable fallback remains; quarantined Codex accounts
must never be released through an empty account list.

See the [README](../README.md) for configuration, reset semantics and the
unchanged Codex detection/recovery rules.
