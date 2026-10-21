// Deterministic Solidity / EVM static security scanner.
//
// Contract contract (Clustly hosting): export a default async handler, receive
// { criteria, inputs }, return the deliverable as a string. Throw when the job
// cannot be done, so the buyer is refunded instead of receiving a useless file.
//
// No dependencies, no model credential, no state: every job runs in a fresh
// sandbox and must be answerable from its own input.

import { analyze, RULE_COUNT, SEVERITIES } from "./analyzer.mjs";

const MAX_FILES = 12;
const MAX_SOURCE_BYTES = 400_000;

function pickInput(inputs, names) {
  for (const n of names) {
    const v = inputs?.[n];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

/** Pull source out of the brief when the buyer pasted it in the criteria. */
function sourceFromCriteria(criteria) {
  if (!criteria) return "";
  const fenced = [...criteria.matchAll(/```(?:solidity|vyper|rust)\s*\n([\s\S]*?)```/gi)].map((m) => m[1]);
  if (fenced.length) return fenced.join("\n\n");
  const lines = criteria.split(/\r?\n/);
  const solidityish = lines.filter((l) =>
    /\b(contract|function|pragma solidity|import |interface |modifier |mapping\(|require\(|revert )/.test(l),
  );
  if (solidityish.length >= 5) return solidityish.join("\n");
  return "";
}

function splitFiles(text, name) {
  // A paste may hold several contracts. Split on top level contract keywords
  // only when the paste clearly holds more than one.
  const parts = text.split(/\n(?=\s*(?:abstract\s+)?contract\s+[A-Za-z0-9_$]+\s*(?:is\b[^\{]*)?\{)/g);
  if (parts.length <= 1) return [{ name, content: text }];
  return parts.map((p, i) => {
    const m = p.match(/contract\s+([A-Za-z0-9_$]+)/);
    return { name: `${name}${parts.length > 1 ? `#${i + 1} ${m ? m[1] : ""}` : ""}`, content: p };
  });
}

async function fetchRepo(url) {
  const raw = /^https?:\/\/raw\.githubusercontent\.com\//i.test(url);
  const api = /^https?:\/\/api\.github\.com\//i.test(url);
  const github = /^https?:\/\/github\.com\//i.test(url);
  if (!raw && !api && !github) throw new Error("Unsupported source URL. Give a raw.githubusercontent.com link, a github.com repository link, or paste the source into the source field.");

  const headers = { "user-agent": "clustly-solidity-scanner" };
  if (api) {
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error(`GitHub API returned ${res.status} for the repository. Paste the contract source into the source field instead.`);
    const data = await res.json();
    const tree = Array.isArray(data) ? data : data.tree || [];
    const files = tree.filter((f) => /\.sol$/i.test(f.path || "")).slice(0, MAX_FILES);
    if (!files.length) throw new Error("No Solidity files found in that repository. Paste the contract source into the source field.");
    const out = [];
    for (const f of files) {
      const r = await fetch(`https://raw.githubusercontent.com${f.path.startsWith("/") ? "" : "/"}${f.path}`, { headers });
      if (!r.ok) continue;
      out.push({ name: f.path, content: (await r.text()).slice(0, MAX_SOURCE_BYTES) });
    }
    if (!out.length) throw new Error("The repository files could not be fetched. Paste the contract source into the source field.");
    return out;
  }

  if (github) {
    const m = url.match(/^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\/blob\/([^\s?#]+))?/i);
    if (!m) throw new Error("That GitHub link could not be parsed. Use a repository link or a raw file link.");
    const [, owner, repo, blobPath] = m;
    if (blobPath) {
      const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${blobPath}`, { headers });
      if (!res.ok) throw new Error(`The file could not be fetched (${res.status}). Paste the source into the source field.`);
      return [{ name: `${owner}/${repo}/${blobPath}`, content: (await res.text()).slice(0, MAX_SOURCE_BYTES) }];
    }
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`, { headers });
    if (!res.ok) throw new Error(`The repository tree could not be read (${res.status}). Paste the source into the source field.`);
    const data = await res.json();
    const tree = (data.tree || []).filter((f) => /\.sol$/i.test(f.path || "")).slice(0, MAX_FILES);
    if (!tree.length) throw new Error("No Solidity files found in that repository. Paste the source into the source field.");
    const out = [];
    for (const f of tree) {
      const r = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${f.path}`, { headers });
      if (!r.ok) continue;
      out.push({ name: `${owner}/${repo}/${f.path}`, content: (await r.text()).slice(0, MAX_SOURCE_BYTES) });
    }
    if (!out.length) throw new Error("The repository files could not be fetched. Paste the source into the source field.");
    return out;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`The source URL returned ${res.status}. Paste the source into the source field.`);
  return [{ name: url.split("/").pop() || "source.sol", content: (await res.text()).slice(0, MAX_SOURCE_BYTES) }];
}

function severityCounts(findings) {
  const c = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

function render(files, findings, source) {
  const counts = severityCounts(findings);
  const totalLines = files.reduce((n, f) => n + f.content.split(/\r?\n/).length, 0);
  const contractNames = files
    .map((f) => (f.content.match(/contract\s+([A-Za-z0-9_$]+)/) || [])[1])
    .filter(Boolean);

  const out = [];
  out.push(`# Solidity security scan${contractNames.length ? ` — ${contractNames.join(", ")}` : ""}`);
  out.push("");
  out.push(
    `**Scope:** ${files.length} file${files.length === 1 ? "" : "s"}, ${totalLines} lines scanned · ` +
      `**Rules:** ${RULE_COUNT} · **Findings:** ${findings.length} ` +
      `(high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
  );
  out.push("");
  out.push("## Executive summary");
  out.push("");
  if (!findings.length) {
    out.push(
      "No pattern from the rule set matched this source. That is not a clean bill of health: the scan is " +
        "pattern based and does not reason about the contract's business logic, cross contract invariants, or " +
        "anything that only shows up at runtime. Read the coverage section below before you treat this as good news.",
    );
  } else {
    const highs = findings.filter((f) => f.severity === "high");
    const meds = findings.filter((f) => f.severity === "medium");
    const lead = highs.length
      ? `${highs.length} high severity issue${highs.length === 1 ? "" : "s"} need attention before this contract handles value: ${highs.map((f) => f.ruleId).join(", ")}.`
      : meds.length
        ? `No high severity pattern matched. ${meds.length} medium severity issue${meds.length === 1 ? "" : "s"} deserve a look: ${meds.map((f) => f.ruleId).join(", ")}.`
        : `Only low severity and informational patterns matched (${findings.length} in total).`;
    out.push(lead);
    out.push("");
    out.push(
      `The most common pattern here is **${findings[0].ruleId}** (${findings.filter((f) => f.ruleId === findings[0].ruleId).length} occurrence${findings.filter((f) => f.ruleId === findings[0].ruleId).length === 1 ? "" : "s"}).`,
    );
  }
  out.push("");

  out.push("## Findings");
  out.push("");
  if (!findings.length) {
    out.push("None.");
  } else {
    out.push("| Rule | Severity | Finding | Location | Confidence |");
    out.push("|---|---|---|---|---|");
    for (const f of findings) {
      out.push(`| ${f.ruleId} | ${f.severity} | ${f.title} | ${f.file}:${f.line} | ${f.confidence} |`);
    }
  }
  out.push("");

  for (const f of findings) {
    out.push(`### [${f.severity.toUpperCase()}] ${f.ruleId} — ${f.title}`);
    out.push("");
    out.push(`**Location:** ${f.file}:${f.line}  |  **Confidence:** ${f.confidence}`);
    out.push("");
    if (f.snippet) {
      out.push("```solidity");
      out.push(f.snippet);
      out.push("```");
      out.push("");
    }
    if (f.detail) {
      out.push(f.detail);
      out.push("");
    }
    out.push(`**Why it matters:** ${f.why}`);
    out.push("");
    out.push(`**Fix:** ${f.fix}`);
    out.push("");
  }

  out.push("## Coverage");
  out.push("");
  out.push(`- Source used: ${source}`);
  for (const f of files) out.push(`- \`${f.name}\` — ${f.content.split(/\r?\n/).length} lines`);
  out.push(`- Rules executed: ${RULE_COUNT} (${Object.keys(SEVERITIES).length} severity levels)`);
  out.push("");
  out.push("## What this scan did not do");
  out.push("");
  out.push("- It is pattern based. It does not model your contract's business logic, invariants, or cross contract trust assumptions.");
  out.push("- It found no runtime bugs: no fuzzing, no symbolic execution, no test execution, no gas benchmarking, no economic analysis.");
  out.push("- It did not read the dependencies your contract imports. An imported library carries its own risk and is not covered here.");
  out.push("- It did not check the deployment, the proxy setup, the admin keys, the oracle setup, or the off chain services around the contract.");
  out.push("");
  out.push("## Next steps");
  out.push("");
  if (counts.high) {
    out.push(`1. Fix the ${counts.high} high severity finding${counts.high === 1 ? "" : "s"} first, then rerun the scan.`);
  } else {
    out.push("1. Review the medium severity findings and decide, in the code, whether each one is reachable in your deployment.");
  }
  out.push("2. Add a test that proves the fixed path behaves as intended. A finding without a regression test comes back.");
  out.push("3. Get a human auditor for anything holding value. This scan narrows where to look, it does not replace a review.");
  out.push("4. Send this report and the source to a second pair of eyes before you ship.");
  out.push("");
  out.push(`_Generated by a deterministic rule engine (${RULE_COUNT} rules, no model in the loop). Every finding above points at a line in the source you supplied._`);
  return out.join("\n");
}

export default async function handler(job) {
  const input = job?.input ?? job ?? {};
  const criteria = typeof input.criteria === "string" ? input.criteria : "";
  const inputs = input.inputs && typeof input.inputs === "object" ? input.inputs : {};

  const pasted = pickInput(inputs, ["source", "code", "contract_source", "solidity_code"]);
  const url = pickInput(inputs, ["repo_url", "url", "repository", "source_url"]);

  let files = [];
  let sourceNote;
  if (pasted) {
    files = splitFiles(pasted, "pasted.sol");
    sourceNote = "the source field";
  } else if (url) {
    files = await fetchRepo(url);
    sourceNote = url;
  } else {
    const fromCriteria = sourceFromCriteria(criteria);
    if (!fromCriteria) {
      throw new Error(
        "No Solidity source was found. Paste the contract into the source field, or give a GitHub link in the repository field, " +
          "or include the code in the brief. Nothing was charged for this run.",
      );
    }
    files = splitFiles(fromCriteria, "brief.sol");
    sourceNote = "the brief";
  }

  if (!files.length) throw new Error("The source was empty, so there was nothing to scan.");
  const findings = analyze(files);
  return render(files, findings, sourceNote);
}
