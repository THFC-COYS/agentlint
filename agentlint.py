#!/usr/bin/env python3
"""agentlint: eslint for AI agents.

Audits an AI agent configuration file and prints an Agent Governance
Score (0-100) with a per-check report. Zero dependencies, stdlib only.

Usage:
    python3 agentlint.py <config-file>
    python3 agentlint.py --demo
    python3 agentlint.py --json <config-file>
    python3 agentlint.py --min-score 70 <config-file>

Exit code is non-zero when the score is below --min-score (default 50),
so CI can gate on it.

Inspired by the Governance pillar of the AGENT Framework by Greg Lucas.
"""

import argparse
import json
import re
import sys

# ---------------------------------------------------------------------------
# Key vocabularies. Config formats vary wildly, so each check accepts the
# common spellings for its concept.
# ---------------------------------------------------------------------------

TOOL_KEYS = {"tools", "allowed_tools", "enabled_tools", "functions",
             "capabilities", "tool_allowlist"}

APPROVAL_KEYS = {"human_approval", "require_approval", "approval_required",
                 "requires_approval", "human_in_the_loop", "hitl",
                 "confirm_before", "confirmation_required", "approval_gate",
                 "approval", "gates"}

STEP_KEYS = {"max_steps", "max_iterations", "max_turns", "max_actions",
             "max_loops", "max_tool_calls", "step_limit", "iteration_limit",
             "loop_limit"}

LOGGING_KEYS = {"logging", "audit_log", "audit_logging", "audit",
                "telemetry", "observability", "log_level", "logs"}

EVAL_KEYS = {"eval", "evals", "evaluation", "evaluations", "eval_hooks",
             "verification", "verify_outputs", "output_validation",
             "validation_hooks", "quality_checks", "human_review",
             "test_suite"}

EGRESS_KEYS = {"allowed_domains", "domain_allowlist", "allowed_hosts",
               "allowed_urls", "url_allowlist", "network_allowlist",
               "egress_allowlist", "allowed_egress", "allowed_endpoints",
               "allowlist"}

OWNER_KEYS = {"owner", "owner_email", "owner_name", "maintainer",
              "responsible", "responsible_party", "accountable",
              "accountable_owner", "contact_email", "on_call"}

DESTRUCTIVE_PATTERNS = [
    (r"shell|bash|terminal|command|exec", "shell/command execution"),
    (r"delete|remove|purge|destroy|drop_table", "data deletion"),
    (r"payment|pay_|charge|refund|billing|transfer_funds", "payments"),
    (r"send_email|email_send|smtp|send_sms|send_message", "outbound messaging"),
    (r"deploy|publish", "deploy/publish"),
]

NETWORK_PATTERNS = r"http|web_|browse|browser|fetch|url|api_call|request"

SECRET_PATTERNS = [
    (r"sk-ant-[A-Za-z0-9_\-]{16,}", "Anthropic-style API key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"ghp_[A-Za-z0-9]{30,}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained token"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"AIza[0-9A-Za-z_\-]{30,}", "Google API key"),
]

GENERIC_SECRET = re.compile(
    r"(api[_-]?key|client[_-]?secret|password|passwd|secret|access[_-]?token)"
    r"\s*[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']",
    re.IGNORECASE,
)

EMBEDDED_DEMO = {
    "name": "cowboy-agent",
    "model": "gpt-5",
    "tools": ["*"],
    "api_key": "sk-9f8e7d6c5b4a3210fedcba9876543210abcdef",
    "autonomy": "full",
    "logging": False,
    "system_prompt": "You are an autonomous agent. Do whatever it takes.",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def truthy(value):
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value > 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false", "no", "off",
                                             "none", "disabled")
    if isinstance(value, (dict, list)):
        return len(value) > 0
    return False


def find_values(obj, names):
    """All values whose key (lowercased) is in names, searched recursively."""
    found = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if str(key).lower() in names:
                found.append(val)
            found.extend(find_values(val, names))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(find_values(item, names))
    return found


def looks_placeholder(value):
    v = value.strip()
    low = v.lower()
    if v.startswith("${") or v.startswith("$"):
        return True
    if low.startswith(("env:", "vault:", "secret:")):
        return True
    if any(s in low for s in ("your-", "your_", "example", "placeholder",
                              "changeme", "redacted", "xxxx", "****")):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]{3,}", v):  # ENV_VAR_NAME reference
        return True
    return False


def extract_tools_from_values(values):
    tools = []
    for val in values:
        if isinstance(val, str):
            tools.append({"name": val, "gated": False})
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    tools.append({"name": item, "gated": False})
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("tool") \
                        or item.get("id") or "?"
                    gated = any(truthy(item.get(k)) for k in APPROVAL_KEYS
                                if k in item)
                    tools.append({"name": str(name), "gated": gated})
        elif isinstance(val, dict):
            for name in val.keys():
                tools.append({"name": str(name), "gated": False})
    return tools


def destructive_tools(tools):
    hits = []
    for tool in tools:
        for pattern, label in DESTRUCTIVE_PATTERNS:
            if re.search(pattern, tool["name"].lower()):
                hits.append((tool, label))
                break
    return hits


# ---------------------------------------------------------------------------
# Signal extraction: normalize JSON dicts and raw text into one shape.
# ---------------------------------------------------------------------------

def signals_from_dict(data, text):
    tools = extract_tools_from_values(find_values(data, TOOL_KEYS))
    wildcard = any(t["name"].strip() in ("*", "all", "all_tools", "any")
                   for t in tools)
    if isinstance(data.get("tools"), str) and \
            data["tools"].strip() in ("*", "all"):
        wildcard = True

    top_approval = any(truthy(data.get(k)) for k in APPROVAL_KEYS
                       if k in data)
    for container in ("governance", "safety", "guardrails", "controls"):
        sub = data.get(container)
        if isinstance(sub, dict):
            top_approval = top_approval or any(
                truthy(sub.get(k)) for k in APPROVAL_KEYS if k in sub)
    approval_anywhere = top_approval or any(
        truthy(v) for v in find_values(data, APPROVAL_KEYS))

    logging_vals = find_values(data, LOGGING_KEYS)
    if not logging_vals:
        logging_state = "absent"
    elif any(truthy(v) for v in logging_vals):
        logging_state = "on"
    else:
        logging_state = "off"

    network_access_vals = find_values(data, {"network_access",
                                             "internet_access"})
    network_restricted = any(v is False for v in network_access_vals)

    return {
        "tools": tools,
        "tools_declared": len(tools) > 0 or wildcard,
        "wildcard": wildcard,
        "approval_global": top_approval,
        "approval_anywhere": approval_anywhere,
        "secrets": find_secrets(text),
        "max_steps": any(truthy(v) for v in find_values(data, STEP_KEYS)),
        "logging_state": logging_state,
        "eval_hooks": any(truthy(v) for v in find_values(data, EVAL_KEYS)),
        "egress_allowlist": any(truthy(v)
                                for v in find_values(data, EGRESS_KEYS)),
        "network_restricted": network_restricted,
        "owner": any(isinstance(v, str) and v.strip()
                     for v in find_values(data, OWNER_KEYS)),
    }


def signals_from_text(text):
    low = text.lower()
    wildcard = bool(re.search(r"[\"']\*[\"']", text)) or \
        bool(re.search(r"tools\s*[:=]\s*all\b", low)) or \
        bool(re.search(r"^\s*-\s*[\"']?\*[\"']?\s*$", text, re.MULTILINE))
    tokens = ["shell", "bash", "exec", "delete", "payment", "send_email",
              "deploy", "publish", "http_request", "web_search", "browser",
              "read_file", "write_file"]
    tools = [{"name": t, "gated": False} for t in tokens if t in low]
    approval = bool(re.search(
        r"human[_\s-]?(approval|in[_\s-]the[_\s-]loop)|require[sd]?[_\s-]"
        r"approval|approval[_\s-]?required", low))
    logging_state = "absent"
    if re.search(r"(logging|audit[_\s-]?log)\s*[:=]\s*(true|enabled|on|"
                 r"\{)", low):
        logging_state = "on"
    elif re.search(r"(logging|audit[_\s-]?log)\s*[:=]\s*(false|off|none|"
                   r"disabled)", low):
        logging_state = "off"
    elif "logging" in low or "audit" in low:
        logging_state = "on"
    return {
        "tools": tools,
        "tools_declared": len(tools) > 0 or wildcard or "tools" in low,
        "wildcard": wildcard,
        "approval_global": approval,
        "approval_anywhere": approval,
        "secrets": find_secrets(text),
        "max_steps": bool(re.search(
            r"max[_\s-]?(steps|iterations|turns|actions|loops)", low)),
        "logging_state": logging_state,
        "eval_hooks": bool(re.search(
            r"\b(eval|evals|evaluation|verification|verify[_\s-]?outputs|"
            r"human[_\s-]?review)\b", low)),
        "egress_allowlist": bool(re.search(
            r"allowed[_\s-]?(domains|hosts|urls)|domain[_\s-]?allowlist|"
            r"allowlist", low)),
        "network_restricted": bool(re.search(
            r"network[_\s-]?access\s*[:=]\s*(false|no|off)", low)),
        "owner": bool(re.search(r"\b(owner|maintainer|responsible)\b"
                                r"\s*[:=]\s*\S+", low)),
    }


def find_secrets(text):
    found = []
    for pattern, label in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            token = match.group(0)
            if "xxxx" in token.lower() or "example" in token.lower():
                continue
            found.append(label)
    for match in GENERIC_SECRET.finditer(text):
        if not looks_placeholder(match.group(2)):
            found.append("hardcoded credential (%s)" % match.group(1))
    return sorted(set(found))


# ---------------------------------------------------------------------------
# The eight governance checks. Each returns (status, points, message).
# ---------------------------------------------------------------------------

def check_tool_scope(s):
    if s["wildcard"]:
        return ("FAIL", 0,
                "Wildcard grant: tools includes \"*\", so the agent can "
                "use every tool that exists now or gets added later.")
    if not s["tools_declared"]:
        return ("WARN", 7,
                "No tool list declared. The agent's scope cannot be "
                "verified, which is its own risk.")
    if len(s["tools"]) > 20:
        return ("WARN", 7,
                "Very broad tool surface: %d tools declared. Every tool "
                "is attack surface." % len(s["tools"]))
    return ("PASS", 15,
            "Tools are an explicit list of %d. No wildcard grants."
            % len(s["tools"]))


def check_destructive_gates(s):
    hits = destructive_tools(s["tools"])
    if s["wildcard"]:
        hits = [( {"name": "*", "gated": False}, "all of them")]
    if not hits:
        return ("PASS", 20,
                "No destructive capabilities declared (no shell, delete, "
                "payments, outbound send, or deploy tools).")
    labels = sorted(set(label for _, label in hits))
    if s["approval_global"]:
        return ("PASS", 20,
                "Destructive capabilities present (%s) but a human "
                "approval gate is configured." % ", ".join(labels))
    ungated = [t for t, _ in hits if not t["gated"]]
    if hits and not ungated:
        return ("PASS", 20,
                "Every destructive tool (%s) is individually marked as "
                "requiring approval." % ", ".join(labels))
    if s["approval_anywhere"]:
        return ("WARN", 10,
                "Some approval config exists, but destructive tools "
                "(%s) are not all clearly gated." % ", ".join(labels))
    return ("FAIL", 0,
            "Destructive capabilities (%s) with NO human approval gate. "
            "The agent can act on its own say-so." % ", ".join(labels))


def check_secrets(s):
    if s["secrets"]:
        return ("FAIL", 0,
                "Secrets embedded in the config or prompt: %s. Configs "
                "get committed, shared, and leaked. Use a secret manager "
                "or environment references." % ", ".join(s["secrets"]))
    return ("PASS", 15,
            "No embedded API keys or credentials found. Secrets are "
            "referenced, not stored.")


def check_autonomy(s):
    if s["max_steps"]:
        return ("PASS", 10,
                "Autonomy is bounded: a max steps / iteration cap is set, "
                "so a confused agent cannot loop forever.")
    return ("FAIL", 0,
            "No max steps or iteration cap. An agent that cannot stop "
            "itself will eventually spend money, spam someone, or both.")


def check_logging(s):
    if s["logging_state"] == "on":
        return ("PASS", 10,
                "Audit logging is enabled. When something goes wrong, "
                "there will be a record of what the agent did.")
    if s["logging_state"] == "off":
        return ("FAIL", 0,
                "Logging is explicitly disabled. An unlogged agent is an "
                "unaccountable agent.")
    return ("FAIL", 0,
            "No audit logging configured. If the agent misbehaves, you "
            "will have no trace of what it did or why.")


def check_eval_hooks(s):
    if s["eval_hooks"]:
        return ("PASS", 10,
                "Evaluation or verification hooks are present, so agent "
                "output gets checked before it counts.")
    return ("FAIL", 0,
            "No evaluation or verification hooks. Nothing checks the "
            "agent's work before it reaches the world.")


def check_egress(s):
    if s["egress_allowlist"]:
        return ("PASS", 10,
                "An allowlist restricts where the agent can reach. Open "
                "egress is how agents leak data.")
    if s["network_restricted"]:
        return ("PASS", 10,
                "Network access is disabled, so there is no egress to "
                "police.")
    has_network = s["wildcard"] or any(
        re.search(NETWORK_PATTERNS, t["name"].lower()) for t in s["tools"])
    if has_network:
        return ("FAIL", 0,
                "The agent has network-capable tools but no domain "
                "allowlist. It can send data anywhere on the internet.")
    return ("WARN", 5,
            "No egress policy declared. Fine for a fully offline agent, "
            "a hole the moment it gets network tools.")


def check_owner(s):
    if s["owner"]:
        return ("PASS", 10,
                "A named human owner is on the config. Somebody specific "
                "is accountable for this agent.")
    return ("FAIL", 0,
            "No named human owner. When this agent breaks something, "
            "nobody specific answers for it.")


CHECKS = [
    ("Tool permissions scoped", 15, check_tool_scope),
    ("Destructive actions gated by human approval", 20,
     check_destructive_gates),
    ("No secrets embedded in config", 15, check_secrets),
    ("Autonomy bounded (max steps / iteration cap)", 10, check_autonomy),
    ("Audit logging enabled", 10, check_logging),
    ("Evaluation / verification hooks present", 10, check_eval_hooks),
    ("Outbound access allowlisted", 10, check_egress),
    ("Named human owner", 10, check_owner),
]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def run_checks(signals):
    results = []
    total = 0
    for name, max_points, fn in CHECKS:
        status, points, message = fn(signals)
        results.append({
            "check": name,
            "status": status,
            "points": points,
            "max_points": max_points,
            "message": message,
        })
        total += points
    return results, total


def verdict(score):
    if score >= 85:
        return "Verdict: Governed. This agent is ready for production."
    if score >= 50:
        return "Verdict: Partially governed. Close the gaps above " \
               "before production."
    return "Verdict: Ungoverned. Do not deploy this agent."


def print_report(source, results, score):
    print("agentlint report: %s" % source)
    print("=" * 64)
    for r in results:
        print("[%s] %s (%d/%d)" % (r["status"], r["check"], r["points"],
                                   r["max_points"]))
        print("       %s" % r["message"])
    print("-" * 64)
    print("AGENT GOVERNANCE SCORE: %d/100" % score)
    print(verdict(score))


def load_signals(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    data = None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            data = parsed
    except (ValueError, TypeError):
        data = None
    if data is not None:
        return signals_from_dict(data, text)
    return signals_from_text(text)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="agentlint",
        description="Lint an AI agent config and score its governance.")
    parser.add_argument("config", nargs="?",
                        help="Path to the agent config file (JSON, YAML, "
                             "or text).")
    parser.add_argument("--demo", action="store_true",
                        help="Audit a built-in reckless demo agent.")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as JSON.")
    parser.add_argument("--min-score", type=int, default=50,
                        help="Exit non-zero if the score is below this "
                             "(default 50).")
    args = parser.parse_args(argv)

    if args.demo:
        signals = signals_from_dict(EMBEDDED_DEMO,
                                    json.dumps(EMBEDDED_DEMO))
        source = "built-in demo (reckless agent)"
    elif args.config:
        try:
            signals = load_signals(args.config)
        except OSError as exc:
            print("agentlint: cannot read %s: %s" % (args.config, exc),
                  file=sys.stderr)
            return 2
        source = args.config
    else:
        parser.print_usage(sys.stderr)
        print("agentlint: give a config file or use --demo",
              file=sys.stderr)
        return 2

    results, score = run_checks(signals)
    if args.json:
        print(json.dumps({
            "file": source,
            "score": score,
            "verdict": verdict(score),
            "checks": results,
        }, indent=2))
    else:
        print_report(source, results, score)
    return 0 if score >= args.min_score else 1


if __name__ == "__main__":
    sys.exit(main())
