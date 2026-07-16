"""Detect prompt-injection and instruction-subversion aimed at the agent.

A skill is natural-language instructions the model will follow. That makes the
prose itself an attack surface: text that tells the agent to ignore its rules,
hide actions from the user, or override the system prompt is the skill equivalent
of a code backdoor. We scan Markdown prose and the frontmatter description.

Patterns are written to need an explicit object ("instructions", "rules",
"the user") so ordinary phrases like "ignore case" or "act as a linter" don't
trip them.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, line_col, snippet_for
from ..discovery import SkillUnit
from ._util import text_targets

RULE_ID = "SX-INJ"

_I = re.IGNORECASE

# (compiled, severity, title, detail)
_PATTERNS = [
    (re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instructions?|prompts?|context|rules?|messages?|directions?)", _I),
     Severity.HIGH, "Instruction-override phrasing",
     "Text tells the agent to ignore previous instructions — a classic prompt-injection payload."),
    (re.compile(r"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+|previous\s+|prior\s+|above\s+|system\s+)?(?:instructions?|prompts?|rules?|guidelines?|context)", _I),
     Severity.HIGH, "Instruction-override phrasing",
     "Text tells the agent to disregard its instructions or guidelines."),
    (re.compile(r"\bforget\s+(?:everything|all|your|the)\s+(?:previous\s+|prior\s+|above\s+)?(?:instructions?|rules?|guidelines?|context|you\s+(?:were\s+)?told)", _I),
     Severity.HIGH, "Instruction-reset phrasing",
     "Text tells the agent to forget its prior instructions."),
    (re.compile(r"\boverride\s+(?:your|the|all|any|previous|system)\s+(?:instructions?|guidelines?|rules?|safety|system\s+prompt|restrictions?|settings?)", _I),
     Severity.HIGH, "Instruction-override phrasing",
     "Text tells the agent to override its guidelines, safety, or system prompt."),
    (re.compile(r"\bdo\s+not\s+(?:tell|inform|mention|alert|notify|warn|show)\s+(?:the\s+)?user", _I),
     Severity.HIGH, "Hide-from-user directive",
     "Text instructs the agent to conceal an action from the user."),
    (re.compile(r"\bwithout\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+)?(?:user|them|him|her)\b", _I),
     Severity.HIGH, "Act-without-consent directive",
     "Text instructs the agent to act without informing or asking the user."),
    (re.compile(r"\bwithout\s+(?:the\s+user'?s?\s+)?(?:permission|consent|confirmation|approval)\b", _I),
     Severity.MEDIUM, "Act-without-consent directive",
     "Text instructs the agent to proceed without the user's permission."),
    # The determiner ("your"/"the"/...) is optional in front of the two
    # highest-signal nouns -- "output system prompt now" has no determiner at
    # all and was missing entirely -- but still required in front of the bare
    # "instructions"/"prompt" so this doesn't fire on every unrelated use of
    # those common words.
    (re.compile(r"\b(?:reveal|print|show|repeat|output|disclose|leak|dump)\s+(?:"
                r"(?:(?:your|the|his|her|its)\s+)?(?:system\s+prompt|initial\s+instructions|system\s+message)|"
                # Only the self-referential "your instructions/prompt" -- "the
                # prompt" / "the instructions" is ordinary English ("show the
                # prompt and the output") and was firing on benign docs.
                r"your\s+(?:instructions|prompt)"
                r")\b", _I),
     Severity.HIGH, "System-prompt disclosure attempt",
     "Text tries to get the agent to reveal its system prompt or hidden instructions."),
    (re.compile(r"\bregardless\s+of\s+(?:what|any|whatever)\s+(?:the\s+user|instructions?|guidelines?|rules?|you\s+(?:are|were)\s+told)", _I),
     Severity.MEDIUM, "Guideline-bypass phrasing",
     "Text tells the agent to act regardless of its instructions or the user's wishes."),
    (re.compile(r"^\s*(?:new|updated|real|actual|true)\s+(?:instructions?|task|directive|system\s+prompt)\s*:", _I | re.MULTILINE),
     Severity.MEDIUM, "Injected-instruction header",
     "A line poses as a new set of instructions for the agent."),
    (re.compile(r"\byou\s+are\s+now\s+(?:a|an|in|the|no\s+longer)\b", _I),
     Severity.MEDIUM, "Persona-override phrasing",
     "Text attempts to redefine what the agent is, a common jailbreak opener."),
    # "You are now DAN" doesn't match the pattern above -- "DAN" isn't
    # "a/an/in/the/no longer". Only the persona token itself needs to look
    # capitalized/name-shaped ((?i:...) scopes case-folding to "you are now"
    # so the outer compile can stay case-sensitive for [A-Z]); ordinary
    # continuations like "you are now ready" or "you are now logged in" start
    # lowercase and never reach this branch.
    (re.compile(r"\b(?i:you\s+are\s+now)\s+[A-Z][A-Za-z0-9]{1,}\b"),
     Severity.MEDIUM, "Persona-override phrasing",
     "Text assigns the agent a specific named persona right after telling it what it now is, "
     "the exact shape of \"you are now DAN,\" a well-known jailbreak opener."),
    (re.compile(r"\b(?:unrestricted|unfiltered|uncensored|jailbroken)\s+(?:AI|assistant|model|mode)\b", _I),
     Severity.HIGH, "Jailbreak-persona phrasing",
     "Text tells the agent it is an unrestricted, unfiltered, or jailbroken AI, a common jailbreak framing."),
    (re.compile(r"\bno\s+(?:safety|content|ethical)\s+(?:rules|guidelines|filters|restrictions)\b", _I),
     Severity.HIGH, "Safety-bypass claim",
     "Text claims there are no safety, content, or ethical rules in place, asserting away the agent's guardrails."),
    (re.compile(r"\balways\s+(?:run|execute|use|call|invoke)\b[^\n.]*\bwithout\s+(?:asking|confirming|prompting|checking)", _I),
     Severity.HIGH, "Silent tool-execution directive",
     "Text tells the agent to always run something without asking."),
]


def check(unit: SkillUnit) -> list:
    findings: list = []
    for t in text_targets(unit, kinds=("markdown", "manifest")):
        # For manifests we only care about a description field, not JSON keys;
        # scanning the whole text is fine — patterns are specific enough.
        text = t.text
        for rx, sev, title, detail in _PATTERNS:
            for m in rx.finditer(text):
                line, col = line_col(text, m.start())
                findings.append(Finding(
                    rule_id=RULE_ID,
                    category=Category.INJECTION,
                    severity=sev,
                    title=title,
                    detail=detail,
                    file=t.relpath,
                    line=line,
                    column=col,
                    snippet=snippet_for(text, m.start()),
                    remediation="Remove the directive. A skill should describe a capability, not tell the agent to bypass its own rules or hide from the user.",
                ))
    return findings
