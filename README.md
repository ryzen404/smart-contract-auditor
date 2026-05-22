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

1. Paste your Solidity contract into the editor
2. Click **Run Audit**
3. Three specialized agents analyze the contract in parallel
4. Review findings by category: Security, Gas Optimization, Best Practices

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
