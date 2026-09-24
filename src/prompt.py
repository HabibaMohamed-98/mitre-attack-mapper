"""
prompt.py — build the grounded prompt from a log + the retrieved techniques.

This is where RAG's "open-book exam" happens. We don't ask the LLM "what ATT&CK
technique is this?" from memory. Instead we hand it a SHORTLIST of real techniques
(from our retrieval core) plus their real mitigations, and ask it to answer USING
ONLY that shortlist.

*** THE GROUNDING RULE (this is what stops invented technique codes) ***
The prompt instructs the model, in strong terms, to:
  1. Label the log using ONLY the technique IDs we provide — never invent a T-code.
  2. Cite the exact evidence FROM THE LOG for each technique it picks.
  3. Suggest a mitigation ONLY from the provided mitigations for that technique.
  4. Say so honestly if none of the provided techniques fit.
Because every ID and every mitigation the model is allowed to use comes from real
ATT&CK data we retrieved, the answer is grounded and citable by construction.

This module only BUILDS text (candidates in -> system+user strings out). It does
not call the model (that's llm.py) — so it's easy to read and test on its own.
"""

# The system prompt sets the model's role and the unbreakable rules. Keeping it
# separate from the per-log content is standard practice and makes the grounding
# rule easy to find and audit.
SYSTEM_PROMPT = """You are a precise cybersecurity analyst that maps security logs to MITRE ATT&CK techniques.

You will be given ONE log line and a numbered list of CANDIDATE ATT&CK techniques \
(each with its real ID, name, tactic, description, and known mitigations). These \
candidates were retrieved for you.

GROUNDING RULES — follow them exactly:
1. Choose the technique ID(s) ONLY from the provided candidate list. NEVER invent, \
guess, or recall a technique ID that is not in the list. Use the IDs exactly as written.
2. For each technique you select, quote the EXACT text from the log that is your \
evidence. If the log does not contain evidence for a candidate, do not select it.
3. Suggest a mitigation ONLY from the mitigations listed for the technique(s) you chose. \
Refer to it by its M-ID and name.
4. If none of the candidates genuinely match the log, say so plainly instead of forcing a match.
5. Be concise. Do not add techniques "just in case". Prefer the 1-2 best-supported matches.
6. Pick the right level of detail. Choose a sub-technique (e.g. T1055.002) ONLY if the log \
contains evidence specific to that sub-technique that would NOT fit its sibling sub-techniques. \
If the evidence fits several sub-techniques of the same parent equally well, choose the parent \
technique (e.g. T1055) instead.
7. List your PRIMARY technique first: the one that best describes the core action the log \
directly records. Add a second technique only if the log also directly shows a clearly separate action.
"""


# Cap each candidate's description in the prompt. The opening of an ATT&CK
# description defines the technique — that's what the LLM needs to choose between
# candidates. The full text of 5 candidates (~2,700 tokens) blew through the Groq
# free tier's 8,000 tokens/minute; trimmed, a prompt is roughly a third of that.
MAX_DESCRIPTION_CHARS = 600


def _shorten(text: str, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    """Trim to `limit` characters, cutting at the last full sentence if possible."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    last_period = cut.rfind(". ")
    return (cut[: last_period + 1] if last_period > limit // 2 else cut.rstrip()) + " …"


def _format_candidate(index: int, technique: dict) -> str:
    """Render one retrieved technique as a numbered block for the prompt."""
    tactics = ", ".join(technique["tactics"]) or "Unknown"

    # List the technique's grounded mitigations, or note there are none.
    if technique["mitigations"]:
        mitigations = "\n".join(f"     - {m}" for m in technique["mitigations"])
    else:
        mitigations = "     - (no mitigations listed in ATT&CK for this technique)"

    # The snippet's text already holds "ID | name | tactic\ndescription"; we show
    # the description part for context but present the ID/name/tactic cleanly.
    description = _shorten(technique["text"].split("\n", 1)[-1].strip())

    return (
        f"[{index}] {technique['attack_id']} — {technique['name']}  (Tactic: {tactics})\n"
        f"   Description: {description}\n"
        f"   Mitigations:\n{mitigations}"
    )


def build_user_prompt(log_line: str, candidates: list[dict]) -> str:
    """
    Build the user message: the log to analyse + the retrieved candidate techniques.

    `candidates` are the reranked top techniques from the retrieval core (each has
    attack_id, name, tactics, mitigations, text).
    """
    blocks = "\n\n".join(
        _format_candidate(i, tech) for i, tech in enumerate(candidates, start=1)
    )

    # We spell out the exact output shape we want so the answer is clean and
    # consistent on the command line.
    return f"""LOG LINE TO ANALYSE:
{log_line}

CANDIDATE ATT&CK TECHNIQUES (choose ONLY from these):
{blocks}

Now produce the mapping. Use this format:

Technique: <ID> <name>
Evidence: "<exact quote from the log>"
Mitigation: <M-ID> <name> — <one sentence on how it helps>

(Repeat the block if a second technique is clearly supported. If nothing fits, say so.)"""


def build_prompt(log_line: str, candidates: list[dict]) -> tuple[str, str]:
    """Convenience: return (system_prompt, user_prompt) ready for the LLM."""
    return SYSTEM_PROMPT, build_user_prompt(log_line, candidates)
