// Solidity / EVM static security rules.
//
// Every rule returns findings with a file, a line, the offending snippet, a
// severity, a confidence and a fix. The rules are deliberately conservative:
// a scanner that cries wolf is worse than no scanner, so a rule that cannot
// prove its claim reports a lower severity or a lower confidence.

const SEV = { HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info" };

function lines(content) {
  return content.split(/\r?\n/);
}

function findAll(content, regex, limit = 40) {
  const out = [];
  const src = lines(content);
  for (let i = 0; i < src.length && out.length < limit; i++) {
    const m = src[i].match(regex);
    if (m) out.push({ line: i + 1, text: src[i].trim().slice(0, 220), match: m[0] });
  }
  return out;
}

/** Split a file into function bodies by matching braces from each `function`. */
function functionBlocks(content) {
  const src = lines(content);
  const blocks = [];
  for (let i = 0; i < src.length; i++) {
    const head = src[i];
    if (!/\bfunction\b/.test(head)) continue;
    const nameM = head.match(/function\s+([A-Za-z0-9_$]+)/);
    let depth = 0;
    let started = false;
    let body = "";
    let end = i;
    for (let j = i; j < src.length && j < i + 400; j++) {
      for (const ch of src[j]) {
        if (ch === "{") {
          depth++;
          started = true;
        } else if (ch === "}") {
          depth--;
        }
        body += src[j] + "\n";
      }
      if (started && depth <= 0) {
        end = j;
        break;
      }
    }
    blocks.push({
      name: nameM ? nameM[1] : "(unnamed)",
      signature: head.trim().slice(0, 200),
      startLine: i + 1,
      endLine: end + 1,
      body,
      modifiers: (head.match(/function\s+[A-Za-z0-9_$]+\s*\([^)]*\)\s*([^{]*)/) || [, ""])[1].trim(),
    });
    i = end;
  }
  return blocks;
}

const EXTERNAL_CALL =
  /\b(?:call|delegatecall|staticcall)\s*[({]|\.transfer\s*\(|\.send\s*\(|safeTransfer(?:From)?\s*\(|\.approve\s*\(|\.mint\s*\(|\.burnFrom\s*\(/;
const STORAGE_WRITE = /(?:[\w$]+\s*\.\s*[\w$]+|[\w$]+\s*\[[^\]]*\])\s*(?:\+\+|--|=(?!=))/;
const CHECKED = /\brequire\s*\(|\bif\s*\(|\bassert\s*\(|=\s*(?:bool|success|ok|result)\b|\breturn\b/;

const RULES = [
  {
    id: "REENTRANCY-CEI",
    severity: SEV.HIGH,
    title: "External call after a state change (checks-effects-interactions)",
    why: "A state change that happens before an external call lets the callee re-enter the contract while the state is half updated. On a withdraw or a claim path that is the classic drain.",
    fix: "Move every state write before the external call, or guard the function with a reentrancy lock (OpenZeppelin ReentrancyGuard) and read the updated state after the call.",
    confidence: "medium",
    detect(content) {
      const out = [];
      for (const b of functionBlocks(content)) {
        if (/\b(view|pure)\b/.test(b.signature)) continue;
        if (/nonReentrant/.test(b.signature)) continue;
        const bl = b.body.split(/\r?\n/);
        let writeAt = -1;
        let callAt = -1;
        for (let i = 0; i < bl.length; i++) {
          if (writeAt < 0 && STORAGE_WRITE.test(bl[i]) && !/^\s*(uint|int|bool|address|bytes|mapping|string)\b/.test(bl[i].trim())) writeAt = i;
          if (callAt < 0 && EXTERNAL_CALL.test(bl[i]) && !/\.approve\s*\(/.test(bl[i])) callAt = i;
        }
        if (writeAt > -1 && callAt > -1 && writeAt < callAt) {
          out.push({
            line: b.startLine + writeAt,
            text: bl[writeAt].trim().slice(0, 220),
            detail: `In \`${b.name}\` the state write on line ${b.startLine + writeAt} happens before the external call on line ${b.startLine + callAt}.`,
          });
        }
      }
      return out;
    },
  },
  {
    id: "UNCHECKED-LOW-LEVEL-CALL",
    severity: SEV.HIGH,
    title: "Low level call result not checked",
    why: "`call` returns a success flag. Ignoring it means a transfer that silently failed still counts as paid, and the contract believes it moved value.",
    fix: "Capture the result and require it: `require(success, \"call failed\");`.",
    confidence: "high",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /\.call\s*[({]|\bcall\s*\{\s*value\s*:/)) {
        if (CHECKED.test(hit.text)) continue;
        if (/^\s*(bool|success|ok|result)\s+\w+\s*=/.test(hit.text)) continue;
        out.push({ line: hit.line, text: hit.text, detail: "The success flag of this call is discarded." });
      }
      return out;
    },
  },
  {
    id: "DELEGATECALL-UNTRUSTED",
    severity: SEV.HIGH,
    title: "delegatecall to a caller supplied address",
    why: "delegatecall runs foreign code in this contract's storage context. If the target address comes from a parameter, a user controls this contract's state.",
    fix: "Never delegatecall to user input. Use a fixed, audited implementation address, or replace the pattern with a normal call.",
    confidence: "medium",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /delegatecall\s*[({]/)) {
        if (/\bimmutable\b|\bconstant\b/.test(hit.text)) continue;
        out.push({ line: hit.line, text: hit.text, detail: "A delegatecall target that is not a constant can be pointed at arbitrary code." });
      }
      return out;
    },
  },
  {
    id: "TX-ORIGIN-AUTH",
    severity: SEV.HIGH,
    title: "tx.origin used for authorization",
    why: "tx.origin is the externally owned account that started the transaction. Any contract in the middle can make that account call in, so it is not an authorization signal.",
    fix: "Use msg.sender for authorization, and require the call to come directly from the intended caller.",
    confidence: "high",
    detect(content) {
      return findAll(content, /tx\.origin\s*(==|!=|<|>)/).map((h) => ({ line: h.line, text: h.text, detail: "tx.origin appears in a comparison used as an identity check." }));
    },
  },
  {
    id: "WEAK-RANDOMNESS",
    severity: SEV.HIGH,
    title: "Block data used as a random source",
    why: "Validators influence block timestamps, block numbers and the coinbase. Anything derived from them can be predicted or manipulated.",
    fix: "Use a verifiable randomness source (Chainlink VRF, commit reveal) for anything that must be unpredictable.",
    confidence: "high",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /block\.(timestamp|number|coinbase|prevrandao)|blockhash\s*\(/)) {
        const weak = /%|random|rand\b/i.test(hit.text);
        out.push({
          line: hit.line,
          text: hit.text,
          detail: weak
            ? "Block data feeds a random looking value, so the outcome can be influenced."
            : "Block data drives a decision and can be manipulated by a validator.",
          severity: weak ? SEV.HIGH : SEV.MEDIUM,
        });
      }
      return out;
    },
  },
  {
    id: "UNCHECKED-ARITHMETIC",
    severity: SEV.MEDIUM,
    title: "unchecked arithmetic block",
    why: "An unchecked block turns overflow and underflow back into silent wrap around, which is the default behaviour of Solidity before 0.8.",
    fix: "Remove the unchecked block, or prove every operation in it cannot overflow and say so in a comment next to it.",
    confidence: "high",
    detect(content) {
      return findAll(content, /\bunchecked\s*\{/).map((h) => ({ line: h.line, text: h.text, detail: "Arithmetic here is not checked for overflow or underflow." }));
    },
  },
  {
    id: "UNCHECKED-ERC20-RETURN",
    severity: SEV.MEDIUM,
    title: "ERC20 return value ignored",
    why: "Some ERC20 tokens return false instead of reverting. Ignoring the return value means a transfer that failed still looks successful.",
    fix: "Use SafeERC20, or check the boolean: `require(token.transfer(to, amount), \"transfer failed\");`.",
    confidence: "medium",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /\.(transfer|transferFrom|approve)\s*\(/)) {
        if (/\.address\s*\(this\)\s*\./.test(hit.text)) continue;
        if (CHECKED.test(hit.text)) continue;
        if (/^\s*(bool|success|ok)\s+\w+\s*=/.test(hit.text)) continue;
        out.push({ line: hit.line, text: hit.text, detail: "The boolean return value of this token call is not checked." });
      }
      return out;
    },
  },
  {
    id: "APPROVE-RACE",
    severity: SEV.MEDIUM,
    title: "approve without resetting the allowance first",
    why: "Changing a non zero allowance directly leaves the old allowance in place until the new one is mined, and a spender can front run the change to take both allowances.",
    fix: "Set the allowance to zero first, then to the new value, or use increaseAllowance / safeApprove.",
    confidence: "medium",
    detect(content) {
      const out = [];
      const src = lines(content);
      for (let i = 0; i < src.length; i++) {
        const m = src[i].match(/\.approve\s*\(\s*([A-Za-z0-9_$.]+)\s*,\s*([^)]+)\)/);
        if (!m) continue;
        const before = src.slice(Math.max(0, i - 12), i).join("\n");
        if (!new RegExp("\\.approve\\s*\\(\\s*" + m[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*,\\s*0\\s*\\)").test(before)) {
          out.push({ line: i + 1, text: src[i].trim().slice(0, 220), detail: "The allowance is not reset to zero before it is changed." });
        }
      }
      return out;
    },
  },
  {
    id: "MISSING-ZERO-ADDRESS-CHECK",
    severity: SEV.MEDIUM,
    title: "Transfer to an address parameter without a zero address check",
    why: "Sending to address(0) burns the value in many token implementations and is almost never intended.",
    fix: "Require the recipient to be non zero: `require(to != address(0), \"zero address\");`.",
    confidence: "medium",
    detect(content) {
      const out = [];
      for (const b of functionBlocks(content)) {
        const params = (b.signature.match(/\(([^)]*)\)/) || [, ""])[1];
        const addrParam = (params.match(/address\s+([A-Za-z0-9_$]+)/) || [])[1];
        if (!addrParam) continue;
        if (!new RegExp("\\b" + addrParam + "\\b").test(b.body)) continue;
        if (!/\.transfer\s*\(|\.send\s*\(|call\s*\{\s*value|safeTransfer/.test(b.body)) continue;
        if (/address\(0\)/.test(b.body)) continue;
        out.push({ line: b.startLine, text: b.signature, detail: `\`${addrParam}\` is used as a transfer target with no zero address check in the body.` });
      }
      return out;
    },
  },
  {
    id: "UNBOUNDED-LOOP",
    severity: SEV.MEDIUM,
    title: "Loop with no upper bound",
    why: "A loop that cannot be bounded by a caller supplied limit can be used to freeze the contract, and each iteration costs gas the caller must pay.",
    fix: "Bound the loop with a limit parameter, or use a paginated pull pattern instead of a push loop.",
    confidence: "high",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;/)) {
        out.push({ line: hit.line, text: hit.text, detail: "This loop has no terminating condition in the source." });
      }
      return out;
    },
  },
  {
    id: "ACCESS-CONTROL-MISSING",
    severity: SEV.MEDIUM,
    title: "State changing function without an access control modifier",
    why: "A privileged function without a guard can be called by anyone, which usually means the owner actions are open to the public.",
    fix: "Add the same modifier the other privileged functions use, or an explicit `require(msg.sender == owner)` check in the body.",
    confidence: "low",
    detect(content) {
      if (!/onlyOwner|onlyRole|requiresAuth|_checkOwner/.test(content)) return [];
      const out = [];
      for (const b of functionBlocks(content)) {
        if (/\b(view|pure)\b/.test(b.signature)) continue;
        if (/constructor/.test(b.signature)) continue;
        if (/onlyOwner|onlyRole|requiresAuth|_checkOwner/.test(b.modifiers + b.signature)) continue;
        if (!STORAGE_WRITE.test(b.body)) continue;
        if (!/^\s*(function|external|public)/.test(b.signature.trim())) continue;
        out.push({ line: b.startLine, text: b.signature, detail: "This function writes state but carries no access control modifier." });
      }
      return out;
    },
  },
  {
    id: "UPGRADE-UNPROTECTED",
    severity: SEV.MEDIUM,
    title: "Upgrade entry point without an access control modifier",
    why: "An unprotected upgrade lets anyone replace the implementation and take the whole contract.",
    fix: "Put onlyOwner or a timelocked governance check on the upgrade function.",
    confidence: "high",
    detect(content) {
      const out = [];
      for (const b of functionBlocks(content)) {
        if (!/upgradeTo(AndCall)?\s*\(/.test(b.body + b.signature)) continue;
        if (/onlyOwner|onlyRole|requiresAuth|governance|timelock/i.test(b.modifiers + b.signature)) continue;
        out.push({ line: b.startLine, text: b.signature, detail: "The upgrade function has no owner or governance guard." });
      }
      return out;
    },
  },
  {
    id: "SELFDESTRUCT",
    severity: SEV.MEDIUM,
    title: "selfdestruct present",
    why: "selfdestruct is deprecated in modern Solidity and it destroys the contract. In an upgradeable proxy it can brick the implementation.",
    fix: "Remove the call, or gate it behind a governance timelock and prefer disabling the implementation over destroying it.",
    confidence: "high",
    detect(content) {
      return findAll(content, /selfdestruct\s*\(/).map((h) => ({ line: h.line, text: h.text, detail: "selfdestruct destroys the contract permanently." }));
    },
  },
  {
    id: "BLOCK-TIMESTAMP-DEPENDENCE",
    severity: SEV.MEDIUM,
    title: "Logic depends on block.timestamp",
    why: "A validator can move a block timestamp by a few seconds. Deadlines, lotteries and reward timing that depend on it can be nudged.",
    fix: "Accept a small tolerance, or use a commit reveal scheme for anything that must be unpredictable.",
    confidence: "medium",
    detect(content) {
      return findAll(content, /block\.timestamp\s*(==|!=|<=|>=|<|>)/).map((h) => ({ line: h.line, text: h.text, detail: "A decision depends on the block timestamp." }));
    },
  },
  {
    id: "SPOT-PRICE-USAGE",
    severity: SEV.LOW,
    title: "Spot price read instead of a time weighted average",
    why: "A spot price can be moved within a single block, so a protocol that prices collateral or collateral ratios from it can be manipulated.",
    fix: "Use a TWAP over a meaningful window, and check the manipulation threshold explicitly.",
    confidence: "low",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /getPrice\s*\(|latestAnswer\s*\(|latestRoundData\s*\(/)) {
        if (/twap|TWAP|timeWeighted/i.test(hit.text)) continue;
        out.push({ line: hit.line, text: hit.text, detail: "This reads a spot price." });
      }
      return out;
    },
  },
  {
    id: "HARDCODED-GAS",
    severity: SEV.LOW,
    title: "Hard coded gas limit on a call",
    why: "A fixed gas stipend breaks when the callee gets more expensive, and the call fails in a way that is hard to diagnose.",
    fix: "Leave the gas unstipended, or compute the limit from the callee's current cost.",
    confidence: "high",
    detect(content) {
      return findAll(content, /gas\s*:\s*\d+/).map((h) => ({ line: h.line, text: h.text, detail: "The call carries a fixed gas limit." }));
    },
  },
  {
    id: "TX-GASPRICE",
    severity: SEV.LOW,
    title: "tx.gasprice used in logic",
    why: "The gas price is set by the sender, so a user can make a contract behave differently for free.",
    fix: "Do not branch on tx.gasprice. If a gas price matters, read an oracle.",
    confidence: "high",
    detect(content) {
      return findAll(content, /tx\.gasprice/).map((h) => ({ line: h.line, text: h.text, detail: "The gas price is read from the transaction." }));
    },
  },
  {
    id: "PAYABLE-RECEIVE",
    severity: SEV.LOW,
    title: "Contract accepts plain ETH with no accounting",
    why: "ETH sent through receive() or a payable fallback without a ledger entry is stuck in the contract with no way to recover it.",
    fix: "Emit an event and credit the sender, or make the function reject unexpected value.",
    confidence: "low",
    detect(content) {
      return findAll(content, /receive\s*\(\s*\)\s*external\s+payable/).map((h) => ({ line: h.line, text: h.text, detail: "The receive function accepts ETH without recording who sent it." }));
    },
  },
  {
    id: "SOLC-PRE-0.8",
    severity: SEV.LOW,
    title: "Compiler before 0.8 without an unchecked block",
    why: "Before 0.8 arithmetic overflow wrapped silently instead of reverting, and many audited patterns assume 0.8 semantics.",
    fix: "Compile with 0.8 or later, or keep every arithmetic operation inside a checked context that is proven safe.",
    confidence: "high",
    detect(content) {
      const out = [];
      for (const hit of findAll(content, /pragma\s+solidity\s*[^;]*;\s*\/\/\s*.*|pragma\s+solidity\s*(\^|>=|~)?\s*0\.[0-7]\./)) {
        const m = hit.match.match(/0\.[0-7]\./);
        if (!m) continue;
        out.push({ line: hit.line, text: hit.text, detail: "This file compiles with a pre 0.8 compiler, where arithmetic wraps silently." });
      }
      return out;
    },
  },
  {
    id: "MISSING-EVENT",
    severity: SEV.INFO,
    title: "State change without an event",
    why: "Off chain indexers and block explorers can only follow a contract through its events. A write with no event is invisible to them.",
    fix: "Emit an event for every state change a user cares about.",
    confidence: "low",
    detect(content) {
      const out = [];
      for (const b of functionBlocks(content)) {
        if (/\b(view|pure)\b/.test(b.signature)) continue;
        if (!STORAGE_WRITE.test(b.body)) continue;
        if (/\bemit\b/.test(b.body)) continue;
        out.push({ line: b.startLine, text: b.signature, detail: "This function changes state and emits no event." });
      }
      return out;
    },
  },
];

/** Run every rule over every file. */
export function analyze(files) {
  const findings = [];
  for (const file of files) {
    for (const rule of RULES) {
      let hits = [];
      try {
        hits = rule.detect(file.content) || [];
      } catch {
        hits = [];
      }
      for (const hit of hits) {
        findings.push({
          ruleId: rule.id,
          severity: hit.severity || rule.severity,
          title: rule.title,
          why: rule.why,
          fix: rule.fix,
          confidence: rule.confidence,
          file: file.name,
          line: hit.line || 1,
          snippet: hit.text || "",
          detail: hit.detail || "",
        });
      }
    }
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return findings;
}

export const RULE_COUNT = RULES.length;
export const SEVERITIES = SEV;
