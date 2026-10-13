# agentlint

**Your AI agent has production access and no brakes. agentlint finds out in 10 seconds.**
One command. One score. Know whether your agent is governed before it acts, not after it trends on incident day.
`agentlint` is eslint for AI agents: a zero-dependency Python CLI that audits an agent config and prints an **Agent Governance Score (0-100)**.

![Agent Governance Score](https://img.shields.io/badge/agent%20governance-score%20yours-brightgreen)

## Quickstart

No install. No dependencies. Python 3 standard library only.

```bash
git clone https://github.com/THFC-COYS/agentlint.git
cd agentlint

python3 agentlint.py --demo            # audit a built-in reckless agent
python3 agentlint.py your-agent.json   # audit your own config
```

JSON, YAML, and plain-text configs are all fair game. JSON gets a full structural audit; other formats get a best-effort pattern scan.

## What it looks like

Real output, from the demo config in this repo (`demo/bad-agent.json`):

```text
agentlint report: demo/bad-agent.json
================================================================
[FAIL] Tool permissions scoped (0/15)
       Wildcard grant: tools includes "*", so the agent can use every tool that exists now or gets added later.
[FAIL] Destructive actions gated by human approval (0/20)
       Destructive capabilities (all of them) with NO human approval gate. The agent can act on its own say-so.
[FAIL] No secrets embedded in config (0/15)
       Secrets embedded in the config or prompt: OpenAI-style API key, hardcoded credential (api_key). Configs get committed, shared, and leaked. Use a secret manager or environment references.
[FAIL] Autonomy bounded (max steps / iteration cap) (0/10)
       No max steps or iteration cap. An agent that cannot stop itself will eventually spend money, spam someone, or both.
[FAIL] Audit logging enabled (0/10)
       Logging is explicitly disabled. An unlogged agent is an unaccountable agent.
[FAIL] Evaluation / verification hooks present (0/10)
       No evaluation or verification hooks. Nothing checks the agent's work before it reaches the world.
[FAIL] Outbound access allowlisted (0/10)
       The agent has network-capable tools but no domain allowlist. It can send data anywhere on the internet.
[FAIL] Named human owner (0/10)
       No named human owner. When this agent breaks something, nobody specific answers for it.
----------------------------------------------------------------
AGENT GOVERNANCE SCORE: 0/100
Verdict: Ungoverned. Do not deploy this agent.
```

The governed config in `demo/good-agent.json` (allowlisted tools, approval gates on destructive actions, logging on, step caps, eval hooks, named owner) scores **100/100**. Run both and compare:

```bash
python3 agentlint.py demo/bad-agent.json    # 0/100, exit code 1
python3 agentlint.py demo/good-agent.json   # 100/100, exit code 0
python3 agentlint.py --json demo/good-agent.json   # machine-readable report
```

## The checks

| Check | Points | What it catches |
| --- | ---: | --- |
| Tool permissions scoped | 15 | Wildcard (`"*"`) or all-tools grants |
| Destructive actions gated by human approval | 20 | Shell, delete, payments, outbound send, or deploy tools with no approval gate |
| No secrets embedded in config | 15 | API keys and credentials hardcoded in config or prompt text |
| Autonomy bounded | 10 | No max steps / iteration cap, so the agent can loop forever |
| Audit logging enabled | 10 | Logging missing or explicitly disabled |
| Evaluation / verification hooks present | 10 | Nothing checks the agent's output before it ships |
| Outbound access allowlisted | 10 | Network-capable tools with no domain allowlist |
| Named human owner | 10 | No specific human accountable for the agent |

Scoring bands: **85-100** governed, ready for production. **50-84** partially governed, close the gaps. **Below 50** ungoverned, do not deploy. The CLI exits non-zero below 50 by default, so CI fails the build. Set your own bar with `--min-score 80`.

## Gate it in CI (GitHub Action)

```yaml
name: agent-governance
on: [push, pull_request]
jobs:
  agentlint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: THFC-COYS/agentlint@v1
        with:
          config: agent.json
          min-score: "70"
```

## Add the badge to your README

Run agentlint on your agent, then paste your score into a [shields.io](https://shields.io) badge:

```markdown
![Agent Governance Score](https://img.shields.io/badge/agent%20governance-100%2F100-brightgreen)
```

Swap in your number and a color that tells the truth: `brightgreen` for 85+, `yellow` for 50-84, `red` below 50.

## Why this exists

Agents are shipping faster than governance. Teams lint their code, scan their dependencies, and gate their deploys, then hand a language model shell access, a credit card, and a wildcard tool grant with no review at all.

agentlint operationalizes the **Governance** pillar of the [AGENT Framework](https://github.com/THFC-COYS) by Greg Lucas (Acumen, Governance, Evaluation, Navigation, Transformation): before an agent acts, prove it is scoped, gated, logged, evaluated, and owned. Governance is not a policy PDF. It is a check that runs in CI and fails the build.

## Contributing

New config dialects, new secret patterns, and new checks are welcome. Open an issue or a PR. The rule for contributions is the rule for agents: keep it scoped, keep it verifiable.

## License

MIT. Copyright (c) 2026 Greg Lucas.
