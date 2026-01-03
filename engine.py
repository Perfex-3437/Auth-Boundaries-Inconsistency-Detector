# engine.py
import requests
import json
import re

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-4o-mini"

FORBIDDEN_TERMS = [
    "attacker", "exploit", "stolen", "compromise",
    "blast radius", "abuse", "vulnerability"
]


def call_gpt(messages, api_key, temperature=0):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": messages,
        "temperature": temperature
    }

    response = requests.post(OPENAI_API_URL, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


# ---------------- STEP 1 ----------------
def parse_spec(api_spec, api_key):
 # system prompt for ensuring strict compliance to rules
    system = """You are a strict parser.
You only extract explicitly present information.
No inference. No commentary. JSON only."""
    
    user = f"""
Extract into JSON:
- endpoints (path, method, summary)
- declared authentication mechanisms
- declared scopes or roles
- responses
- security schemes

API SPEC:
{api_spec}
"""
    output = call_gpt(
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key
    )
    return json.loads(output)


# ---------------- STEP 2 ----------------
def build_graph(parsed_json, api_key):
    system = """You build structural models only.
No threat reasoning. No judgments."""
    
    user = f"""
Construct a graph with:
- nodes (endpoints, services, auth providers)
- edges (request flow, identity reuse, trust transition)
- tags (auth mechanisms, scopes, implied restriction indicators)

If enforcement is not explicit, tag as "no_visible_enforcement".
Do NOT emit findings.

INPUT:
{json.dumps(parsed_json)}
"""
    output = call_gpt(
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key
    )
    return json.loads(output)


# ---------------- STEP 3 ----------------
def evaluate_rules(graph_json, api_key):
    system = """You are a consistency checker.
Apply only the provided rules.
Forbidden concepts: attacker, exploit, stolen, compromise."""
    
    user = f"""
Apply ONLY these rules:

RULE A: Missing Enforcement
RULE B: Inconsistent Enforcement
RULE C: Boundary Trust Drift
RULE D: Identity Reuse Without Local Validation

Emit structured findings only:
- finding_summary
- supporting_evidence
- boundary_description
- confidence (High if declared, Medium if implied)

GRAPH:
{json.dumps(graph_json)}
"""
    output = call_gpt(
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key
    )
    return json.loads(output)


# ---------------- STEP 4 ----------------
def generate_report(findings, api_key):
    system = """Translate structured findings into neutral technical language.
No speculation. No recommendations."""
    
    user = f"""
Format each finding as:

🔴 Finding
⚠️ Why This Matters
🔗 Boundary
📊 Confidence

FINDINGS:
{json.dumps(findings)}
"""
    return call_gpt(
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key
    )


# ---------------- VALIDATION ----------------
def validate_report(report_text):
    lowered = report_text.lower()
    for term in FORBIDDEN_TERMS:
        if term in lowered:
            raise ValueError(f"Forbidden term detected: {term}")
    return report_text


# ---------------- ORCHESTRATOR ----------------
# main loop
def run_analysis(api_spec, api_key):
    parsed = parse_spec(api_spec, api_key)
    graph = build_graph(parsed, api_key)
    findings = evaluate_rules(graph, api_key)
    report = generate_report(findings, api_key)
    return validate_report(report)