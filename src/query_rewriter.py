"""
query_rewriter.py — turn a raw log line into a plain-language behaviour description.

This is Phase B step 1 from CLAUDE.md. Why it's needed:

Raw logs and ATT&CK speak different languages. A log says "Logon Type: 10";
ATT&CK says "Remote Desktop Protocol". A log says "CreateRemoteThread ...
WriteProcessMemory"; ATT&CK says "Process Injection". Search can't match words
that simply aren't there — the eval showed this was the #1 cause of misses.

So before searching we ask the LLM to translate the log into what an analyst would
SAY happened ("a remote interactive (RDP) logon by the administrator account from
10.10.14.7"). That description shares vocabulary with ATT&CK, so search finds it.

How this stays GROUNDED (it must not become "the LLM guesses the answer"):
  - The rewriter is told NOT to output any ATT&CK technique IDs. It only describes
    behaviour. It can't smuggle an answer into search.
  - The description is only a SEARCH QUERY. The technique IDs in the final answer
    still come exclusively from the real ATT&CK records that search retrieves,
    and the final LLM step still must quote evidence from the ORIGINAL log.
  - We search with the description AND the original log together (see
    retrieval.py), so exact tokens like "lsass.exe" or "vssadmin" still count.
"""

import re

from src.llm import LLMClient

REWRITE_SYSTEM_PROMPT = """You translate raw security log lines into a short, plain-language description of the behaviour they show, as a security analyst would describe it.

Cover all three of these in ONE short plain-prose paragraph (at most 80 words, no headings, no bold, no bullet points):
1. ACTION - what the command or event actually DOES, in plain terms (e.g. "lists all computers in the domain", "reads secrets from the Kubernetes cluster", "hides a file", "creates a new service", "modifies a registry value", "creates a local user account", "downloads a file from an external server", "writes into another process's memory").
2. TOOL - the specific program or utility doing it (e.g. attrib.exe, sc.exe, kubectl, net.exe, reg.exe, vssadmin). The shell that launched it (cmd.exe, PowerShell, bash, sh) is usually just the vehicle: mention the shell only if HOW it was used is itself suspicious (an encoded or obfuscated script, a hidden window, launched by an Office document).
3. PURPOSE - what the actor likely achieves (e.g. "to steal credentials", "to persist across reboots", "to weaken a security protection").
If the log shows several distinct actions, describe each one.

Also:
- Explain what event IDs, logon types, and command-line flags MEAN rather than repeating them.
- Do NOT write any MITRE ATT&CK technique IDs (like T1003) or tactic IDs. Describe behaviour only.
- If the activity looks like ordinary, benign use, say so plainly instead of inventing something malicious."""

# Belt and braces: even though the prompt forbids IDs, strip any that slip through,
# so the rewrite can never inject a technique ID into the search query.
_TECHNIQUE_ID = re.compile(r"\bT[AS]?\d{4}(?:\.\d{3})?\b")


class QueryRewriter:
    """Uses the (swappable) LLM to describe a log's behaviour in plain language."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def rewrite(self, log_line: str) -> str:
        description = self.llm.chat(REWRITE_SYSTEM_PROMPT, f"Log line:\n{log_line}")
        return _TECHNIQUE_ID.sub("", description).strip()
