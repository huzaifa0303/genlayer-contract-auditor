# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *


class SmartContractAuditor(gl.Contract):

    last_target:   str
    last_verdict:  str
    last_issues:   str
    last_severity: str
    total:         u256

    def __init__(self):
        self.last_target   = ""
        self.last_verdict  = ""
        self.last_issues   = ""
        self.last_severity = ""
        self.total         = u256(0)

    @gl.public.write
    def audit_from_url(self, github_raw_url: str) -> str:
        assert github_raw_url.startswith("http"), "URL must start with http"

        _url = github_raw_url

        def leader_fn():
            page = gl.nondet.web.get(_url)
            code = page.body.decode("utf-8", errors="ignore")[:5000]

            prompt = f"""You are a professional smart contract security auditor.

Analyze the following smart contract code and identify security issues.

CONTRACT CODE:
{code}

Audit this contract and respond in this EXACT format only:
VERDICT: <SAFE|VULNERABLE|CRITICAL>
SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>
ISSUES: <comma separated list of issues found, or NONE if safe>
SUMMARY: <one sentence overall assessment, max 150 chars>

Rules:
- SAFE      -> no major issues found
- VULNERABLE -> has issues but not immediately exploitable
- CRITICAL  -> has severe issues like reentrancy, unauthorized access, fund loss risk"""

            raw   = gl.nondet.exec_prompt(prompt)
            lines = raw.strip().splitlines()

            verdict  = "VULNERABLE"
            severity = "MEDIUM"
            issues   = "Could not parse issues."
            summary  = "Manual review recommended."

            for line in lines:
                u = line.upper()
                if u.startswith("VERDICT:"):
                    val = line.split(":", 1)[1].strip().upper()
                    if val in ("SAFE", "VULNERABLE", "CRITICAL"):
                        verdict = val
                elif u.startswith("SEVERITY:"):
                    val = line.split(":", 1)[1].strip().upper()
                    if val in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                        severity = val
                elif u.startswith("ISSUES:"):
                    issues = line.split(":", 1)[1].strip()[:200]
                elif u.startswith("SUMMARY:"):
                    summary = line.split(":", 1)[1].strip()[:150]

            return verdict + "||" + severity + "||" + issues + "||" + summary

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                v = leader_fn()
                return v.split("||")[0] == leader_result.calldata.split("||")[0]
            except Exception:
                return False

        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
        return self._save(github_raw_url, result)

    @gl.public.write
    def audit_from_code(self, contract_code: str) -> str:
        assert len(contract_code) >= 10, "Contract code too short"

        _code = contract_code[:5000]

        def leader_fn():
            prompt = f"""You are a professional smart contract security auditor.

Analyze the following smart contract code and identify security issues.

CONTRACT CODE:
{_code}

Audit this contract and respond in this EXACT format only:
VERDICT: <SAFE|VULNERABLE|CRITICAL>
SEVERITY: <LOW|MEDIUM|HIGH|CRITICAL>
ISSUES: <comma separated list of issues found, or NONE if safe>
SUMMARY: <one sentence overall assessment, max 150 chars>

Rules:
- SAFE      -> no major issues found
- VULNERABLE -> has issues but not immediately exploitable
- CRITICAL  -> has severe issues like reentrancy, unauthorized access, fund loss risk"""

            raw   = gl.nondet.exec_prompt(prompt)
            lines = raw.strip().splitlines()

            verdict  = "VULNERABLE"
            severity = "MEDIUM"
            issues   = "Could not parse issues."
            summary  = "Manual review recommended."

            for line in lines:
                u = line.upper()
                if u.startswith("VERDICT:"):
                    val = line.split(":", 1)[1].strip().upper()
                    if val in ("SAFE", "VULNERABLE", "CRITICAL"):
                        verdict = val
                elif u.startswith("SEVERITY:"):
                    val = line.split(":", 1)[1].strip().upper()
                    if val in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                        severity = val
                elif u.startswith("ISSUES:"):
                    issues = line.split(":", 1)[1].strip()[:200]
                elif u.startswith("SUMMARY:"):
                    summary = line.split(":", 1)[1].strip()[:150]

            return verdict + "||" + severity + "||" + issues + "||" + summary

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                v = leader_fn()
                return v.split("||")[0] == leader_result.calldata.split("||")[0]
            except Exception:
                return False

        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
        return self._save("pasted_code", result)

    def _save(self, target: str, result: str) -> str:
        parts = result.split("||")
        self.last_target   = target
        self.last_verdict  = parts[0] if len(parts) > 0 else "VULNERABLE"
        self.last_severity = parts[1] if len(parts) > 1 else "MEDIUM"
        self.last_issues   = parts[2] if len(parts) > 2 else ""
        self.total         = u256(int(self.total) + 1)
        return self.last_verdict

    @gl.public.view
    def get_latest(self) -> dict:
        return {
            "target":   self.last_target,
            "verdict":  self.last_verdict,
            "severity": self.last_severity,
            "issues":   self.last_issues,
            "total":    int(self.total),
        }

    @gl.public.view
    def get_total(self) -> int:
        return int(self.total)
