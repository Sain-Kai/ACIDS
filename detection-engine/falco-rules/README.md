# SentinelMesh Falco rules

`sentinelmesh_rules.yaml` — 7 custom rules (plus supporting lists/macros)
that complement Falco's own stock ruleset. See the comment at the top of
that file for what each rule does and why it doesn't duplicate Falco's
defaults.

## Running

Production uses Falco JSON HTTP output into the detector:

```yaml
json_output: true
json_include_output_fields_property: true
http_output:
  enabled: true
  url: http://127.0.0.1:8766/falco/events
```


## Validating changes

`falco --validate sentinelmesh_rules.yaml` checks syntax without running
Falco for real — use it before committing any change to this file. This
local sandbox does not include the Falco binary, so these rules are
grounded in Falco's documented rule/macro/list syntax and its
`open_write`/`spawned_process` stock macros, but — like the eBPF probes —
haven't been run through `falco --validate` for real. Do that on a real
Falco install before relying on them.

## Extending

Keep any new rule's `output:` template including the literal field
tokens (`%proc.exe`, `%proc.cmdline`, `%user.name`, `%container.id`,
etc.) that `detection-engine/internal/normalize/normalize.go`'s
`normalizeFalco()` reads out of Falco's `output_fields` — a rule that
doesn't emit a token as part of the output string won't show up as a key
in what detection-engine receives, regardless of whether the field is
"available" to Falco conceptually.
