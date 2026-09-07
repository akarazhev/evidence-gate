# Threat model: <component>

- **Date:**
- **Author:**
- **Trigger:** <new feature | architecture change | incident follow-up>
- **Review again when:** <the architectural change that invalidates this>

## Component and scope

What is in scope, and explicitly what is not.

## Assets

What an attacker would want. Data, capability, availability, trust.

## Actors

Who interacts with this, and what each is trusted to do.

## Trust boundaries

Where data crosses from less trusted to more trusted. For systems with an
agent, every tool it can call is a boundary and every retrieval source is
untrusted input.

## Entry points

Concrete: handlers, consumers, uploads, webhooks, CLI arguments.

## Threats

| # | Threat | Boundary | Impact | Likelihood |
|---|---|---|---|---|

For AI systems also cover: prompt injection including the indirect variety,
retrieval poisoning, context and memory poisoning, unsafe tool use, output
handling into interpreters, training and data supply chain, excessive agency.

## Controls

What exists today. Separate implemented from planned.

## Residual risks

What remains after the controls, and who accepted it.

## Review triggers

What change would make this document wrong.
