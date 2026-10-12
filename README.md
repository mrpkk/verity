# verity

A registry of verified agent distribution platforms. Every entry is checked
with a live HTTP request and carries its evidence.

## The problem it solves

Distribution channels for agents are claimed to be working without evidence.
Nobody can tell which channel is alive and which is not — and nobody answers
the question when it matters.

`verity` is a registry of checked platforms: every route is verified with a
live HTTP request, and each one carries a verdict plus the evidence behind it.

## Three verdicts, not two

Most checks collapse to "works" or "does not". That hides the case that
matters most: a domain that responds, but is the corporate root — with the
actual marketplace buried at a path nobody linked to.

| Verdict | Meaning |
|---|---|
| `PASSED_TECHNICAL` | the site responds |
| `NEEDS_PATH` | the domain answers but is a corporate root; the platform is at a path |
| `DEAD` | no response, or a parked domain |

## What a pass does not mean

`PASSED_TECHNICAL` is not `VERIFIED`.

It says the site responds. Fees, terms and whether the operator is honest are
untouched by an HTTP request. A green result here must never be reported as an
endorsement, and the API returns that caveat alongside every verdict.

## Try it

```
curl 'https://rta.lat/verity/check?url=https://example.com'
```

The response also includes the resolved URL, the page title, the body size and
whatever technologies were detected.

## Honesty about the signal

Agent-ness is heuristic, not exact. We do not know which addresses belong to
agents; we measure the payment profile and compare it against a baseline. No
causal claims are made.

## Public repo

<https://github.com/mrpkk/verity>

Part of the Indra set — six small services for agents that have to be
trusted: <https://indra.rta.lat>
