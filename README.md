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

### Architecture

```
User pastes Solidity code
        │
        ▼
┌─────────────────────────────┐
│      Contract Parser        │
│   Extract: functions,       │
│   state vars, imports,      │
│   modifiers, events         │
└─────────────┬───────────────┘
              │
     ┌────────┼────────┐
     ▼        ▼        ▼
┌─────────┐ ┌───────┐ ┌──────────┐
│Security │ │  Gas  │ │  Best    │
│ Agent   │ │ Agent │ │Practices │
│         │ │       │ │  Agent   │
│• Reentrancy │ │• Storage  │ │• NatSpec  │
│• Access ctrl│ │  packing  │ │• Events   │
│• Overflow   │ │• Calldata │ │• Pausable │
│• Unsafe xfer│ │• Unchecked│ │• Validation│
│• Missing evt│ │• Deploy   │ │• Modifiers│
└────┬────┘ └───┬───┘ └────┬─────┘
     │          │          │
     └────────┬─┴──────────┘
              ▼
┌─────────────────────────────┐
│       Score Engine          │
│  Critical: -25 per finding  │
│  High:     -15 per finding  │
│  Medium:   -8 per finding   │
│  Low:      -3 per finding   │
│                             │
│  Score → Risk Level:        │
│  80-100: Low                │
│  60-79:  Medium             │
│  40-59:  High               │
│  0-39:   Critical           │
└─────────────┬───────────────┘
              ▼
┌─────────────────────────────┐
│       Audit Report          │
│  • Overall score + risk     │
│  • Findings by severity     │
│  • Vulnerable code lines    │
│  • Fix suggestions          │
│  • Gas optimization tips    │
│  • Best practice recs       │
└─────────────────────────────┘
```

### Detection Rules

**Security Agent** checks:
- Reentrancy (external calls before state updates)
- Missing access control (public functions without modifiers)
- Unsafe ETH transfers (.transfer/.send vs .call)
- Integer overflow in user-controlled arithmetic
- Missing event emissions for state changes
- Zero-amount validation gaps

**Gas Agent** analyzes:
- Storage variable packing (slot optimization)
- Memory vs calldata for read-only params
- Unchecked arithmetic for safe operations
- Public vs external function visibility
- Deployment cost optimization

**Best Practices Agent** verifies:
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
