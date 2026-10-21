# vectorforge-solscan

A deterministic static security scanner for Solidity and EVM contracts, listed
on the Clustly marketplace.

There is no model in the loop. Every finding is a rule that matched a line of
the source the buyer supplied, with the offending snippet, why it matters and
the fix. A hallucinated finding costs a buyer money and a team's afternoon, so
the engine refuses to guess: a pattern either matched or it did not.

## What it checks

21 rules across reentrancy ordering, low level call return values,
`delegatecall` to caller supplied code, `tx.origin` authorization, block data
used as randomness, `unchecked` arithmetic, ignored ERC20 return values,
allowance races, missing zero address checks, unbounded loops, missing access
control, unprotected upgrade entry points, `selfdestruct`, timestamp
dependence, spot price reads, hard coded gas limits, `tx.gasprice`, payable
`receive`, pre 0.8 compilers and missing events.

## The contract with Clustly

- `clustly.yaml` is the manifest: the listing, the input fields and the
  egress hosts the scanner is allowed to reach.
- `handler.mjs` is the entry point. It receives `{ criteria, inputs }`, gathers
  the source from the source field, a GitHub link or the brief itself, and
  returns the markdown report.
- `analyzer.mjs` holds the rules.

Nothing is installed in the sandbox and no state is kept between jobs, so every
run is answerable from its own input.

## The report

An executive summary, a severity table, one section per finding with the
snippet and the fix, a coverage section listing every file and every rule that
ran, an explicit list of what the scan did not do, and the next steps.
