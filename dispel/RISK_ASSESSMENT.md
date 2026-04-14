# dispel

- **Tool to be used:** dispel
- **Actions:** Scan the running system for indicators of malware and suspicious activity, and report findings.
- **Rationale:** Provides rapid detection of adversary presence and malicious software without requiring any changes to the system.
- **Risk:** Very low - entirely read-only; dispel does not terminate processes, modify files, or change any system state. It only flags findings for the operator to act on.
- **Recovery:** Kill the dispel process.
