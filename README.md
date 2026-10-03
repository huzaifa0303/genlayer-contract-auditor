# SmartContractAuditor — GenLayer Intelligent Contract

An Intelligent Contract deployed on **GenLayer Testnet Bradbury** that audits
smart contracts via GitHub URL or pasted code using on-chain LLM inference.

## What it does

1. Fetches contract code from GitHub raw URL OR accepts pasted code directly
2. Asks an LLM to find security vulnerabilities
3. Reaches consensus via Optimistic Democracy
4. Returns SAFE / VULNERABLE / CRITICAL verdict on-chain

## Contract Methods

| Method | Type | Description |
|---|---|---|
| `audit_from_url(github_raw_url)` | write | Fetches contract from URL and audits it |
| `audit_from_code(contract_code)` | write | Audits pasted contract code directly |
| `get_latest()` | view | Returns last audit result |
| `get_total()` | view | Total audits done |

## Deployment

- **Network:** GenLayer Testnet Bradbury
- **Contract address:** `0xf77404F709180eFa8e9e40326d2227dda376B9f5`
- **Deploy tx:** `0x5c77...`

## License
MIT
