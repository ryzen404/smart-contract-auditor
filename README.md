# SmartContract AI Auditor

Multi-agent AI system that analyzes Solidity smart contracts for security vulnerabilities, gas optimization, and best practices.

## Features

- **Security Agent** — Detects reentrancy, access control issues, integer overflow, unsafe transfers, missing events, and zero-amount checks
- **Gas Agent** — Identifies storage packing opportunities, calldata optimization, unchecked arithmetic, and deployment cost reductions
- **Best Practices Agent** — Checks NatSpec documentation, event emissions, Pausable implementation, and input validation
- **Risk Score** — 0-100 score with Critical/High/Medium/Low risk classification
- **Fix Suggestions** — Actionable remediation for every finding
- **Code Highlighting** — Pinpoints exact vulnerable lines with fix context

## How It Works

### Pipeline

1. **Input** — Paste Solidity contract code into the editor
2. **Parse** — Extract functions, state variables, imports, modifiers, events
3. **Analyze** — Three specialist agents run in parallel:
   - **Security Agent** — vulnerability detection
   - **Gas Agent** — optimization opportunities
   - **Best Practices Agent** — code quality checks
4. **Score** — Aggregate findings into 0-100 risk score
5. **Report** — Display findings with severity, vulnerable lines, and fix suggestions

### Scoring

| Severity | Deduction |
|----------|-----------|
| Critical | -25 |
| High     | -15 |
| Medium   | -8 |
| Low      | -3 |

| Score   | Risk Level |
|---------|------------|
| 80-100  | Low        |
| 60-79   | Medium     |
| 40-59   | High       |
| 0-39    | Critical   |

### Security Agent

- Reentrancy (external calls before state updates)
- Missing access control (public functions without modifiers)
- Unsafe ETH transfers (.transfer/.send vs .call)
- Integer overflow in user-controlled arithmetic
- Missing event emissions for state changes
- Zero-amount validation gaps

### Gas Agent

- Storage variable packing (slot optimization)
- Memory vs calldata for read-only params
- Unchecked arithmetic for safe operations
- Public vs external function visibility
- Deployment cost optimization

### Best Practices Agent

- NatSpec documentation coverage
- Event definitions for all state changes
- Pausable emergency mechanism
- Zero-address input validation
- Withdrawal pattern vs push pattern
- ReentrancyGuard usage

## Stack

- Next.js 15 (App Router)
- TypeScript
- Client-side analysis (no backend required)

## Run Locally

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

## Built for Xiaomi MiMo 100T Creator Program

Multi-agent architecture showcasing long-chain reasoning and specialized AI agent collaboration for smart contract security analysis.

## License

MIT
