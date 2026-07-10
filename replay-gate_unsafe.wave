#! VULNERABLE replay-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant replay irreversible

let raw = fetch<web>
commit { replay(raw) }  # tainted -> tool: REJECTED
