# Auth Boundary Inconsistency Detector (v1)

This tool identifies **authorization and trust boundary inconsistencies**
by analyzing API specifications.

It performs **structural reasoning only**.

## What This Tool Does
- Parses API specifications
- Models trust and identity flow
- Detects inconsistencies between assumptions and enforcement
- Produces neutral, explainable findings

## What This Tool Does NOT Do
- No exploit simulation
- No attacker modeling
- No risk scoring
- No vulnerability claims
- No live testing

This tool highlights **reasoning gaps**, not vulnerabilities.

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

You will be prompted to provide:
An OpenAPI specification
Your own OpenAI API key
The key is used locally and is never stored.

## Intended Audience
    Security engineers
    Red teamers
    API developers
    Security reviewers

## Design Philosophy
Trust boundaries fail due to **assumption drift**, not missing tools. This project formalizes that reasoning.
