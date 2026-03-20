# Voice And AI Interface Rules

This document defines the product rules and interface contracts for:

- voice interaction on `ESP32S3`
- AI-assisted advisory and proposal generation
- the boundary between companion software, AI services, the device, and `SatochipApplet`

Its purpose is to prevent future implementation drift. Voice and AI are optional product layers, but if they are added later they must obey the same closed-wallet authority model.

## Core rule

Voice and AI may assist.

Voice and AI may not authorize.

The only component allowed to approve a value-moving action is:

- the local user on the device

The only component allowed to produce a cryptographic signature is:

- `SatochipApplet`

## Authority model

| Capability | Companion | Voice Layer | AI Service | ESP32S3 | JavaCard |
|---|---|---|---|---|---|
| Show balances/history | Yes | Indirect | Indirect | Yes | Limited |
| Suggest an action | Yes | Limited | Yes | Yes | No |
| Build a draft proposal | Yes | Limited | Yes | Yes | No |
| Validate policy | No | No | No | Yes | Limited |
| Final user approval | No | No | No | Yes | No |
| Produce signature | No | No | No | No | Yes |
| Broadcast transaction | Yes | No | No | Optional | No |

## Permission classes

Every action exposed by voice or AI should be assigned one permission class.

### Class 0: informational

Examples:

- show portfolio summary
- show BTC balance
- show current Solana account
- explain why a market moved

Rule:

- no confirmation required

### Class 1: navigation

Examples:

- open Bitcoin screen
- switch to Solana
- show receive address
- open pending review

Rule:

- no signing authority
- no local physical confirmation required unless privacy policy demands it

### Class 2: draft preparation

Examples:

- prepare a transfer draft
- open a suggested trade proposal
- load a saved recipient

Rule:

- must produce a structured preview screen
- may not trigger signing

### Class 3: signing-critical

Examples:

- approve a transfer
- confirm an exchange
- confirm a DEX swap
- release a signature

Rule:

- voice and AI may never directly execute this class
- local physical confirmation is mandatory

## Voice model

Voice is an input convenience layer for `ESP32S3`.

It is not:

- a PIN entry channel
- a seed entry channel
- a final approval channel

### Voice operating modes

The product should support these modes only:

1. `voice_query`
2. `voice_navigation`
3. `voice_prepare`

It should not support:

4. `voice_sign`

### Allowed voice commands in early product stages

Allowed:

- open home
- open Bitcoin
- open Solana
- show balance
- show receive address
- next account
- previous account
- open pending proposal
- cancel current flow
- repeat last screen
- ask for market summary

Conditionally allowed later:

- prepare transfer draft from a saved address book entry
- open an AI proposal for review

Not allowed:

- approve transaction
- approve signing
- enter PIN
- reveal mnemonic
- speak private data aloud
- accept raw spoken address strings for live funds movement
- override risk controls

### Voice ambiguity rules

If voice parsing returns:

- low confidence
- multiple candidate intents
- conflicting numeric values
- unknown asset or recipient

The device must:

- refuse execution
- show a clarification screen
- require manual selection

### Voice confirmation rules

Voice may:

- open a review
- fill a draft
- navigate to a screen

Voice may not:

- complete a transaction
- commit a trade
- release a signature

### Voice input contract

The voice frontend should normalize speech into a structured intent record before the wallet layer sees it.

Suggested structure:

```text
voice_intent
  intent_id
  mode
  transcript
  intent_type
  confidence
  asset_symbol
  chain_id
  numeric_args
  recipient_ref
  created_at
```

Required rule:

- no wallet execution logic should consume raw transcript directly

Only parsed and classified intents may be passed onward.

## AI model

AI is an external reasoning and summarization service.

It may run in one of three locations:

- cloud service
- local server in the user environment
- companion-assisted inference path

`ESP32S3` itself should not be treated as the large-model runtime.

### AI operating levels

### Level 1: advisory

AI may:

- summarize markets
- summarize portfolio risk
- explain notable price or chain events
- suggest assets to watch

AI may not:

- create executable actions without device review

### Level 2: structured proposal

AI may:

- create a trade or transfer proposal
- suggest size
- attach rationale
- attach risk tags
- attach confidence

The device must still:

- validate supportability
- validate policy
- reconstruct review data
- require local user confirmation

### Level 3: constrained semi-automation

This is optional and out of early scope.

If ever enabled, it must be behind:

- strict wallet segregation
- strict risk limits
- explicit opt-in
- a separate policy engine

The main vault wallet should not default to autonomous AI execution.

## AI proposal interface

AI output must be structured. Natural-language advice alone is not executable.

Suggested proposal object:

```text
ai_proposal
  proposal_id
  created_at
  expires_at
  source_mode
  chain_id
  asset_symbol
  proposal_type
  action_type
  account_profile
  path_profile_id
  tx_kind
  human_summary
  machine_payload
  amount
  amount_unit
  max_slippage_bps
  venue_id
  confidence_score
  confidence_band
  rationale_lines[]
  risk_tags[]
  warnings[]
  data_sources[]
```

### Required fields for an executable proposal

- `proposal_id`
- `chain_id`
- `action_type`
- `path_profile_id`
- `tx_kind`
- `machine_payload`
- `expires_at`
- `confidence_band`
- `risk_tags`

If any required field is missing:

- the device must downgrade the result to advisory only

## Device-side validation rules

The device must never trust an incoming proposal directly, even if it comes from:

- a local server
- a cloud AI service
- the official companion app

Before a proposal may enter review, `ESP32S3` must validate:

1. chain is supported by current firmware
2. transaction type is supported in the current product phase
3. derivation path policy matches the selected wallet profile
4. proposal has not expired
5. size is within device risk policy
6. destination or venue is allowed by current user policy
7. transaction payload can be reconstructed into a reviewable form

If any step fails:

- no signing path may be opened

## Risk control interface

AI-assisted execution must always pass through a local rule engine.

Suggested device-side controls:

- asset whitelist
- chain whitelist
- max single action size
- daily spend limit
- venue whitelist
- slippage limit
- cooldown interval
- companion-required or companion-forbidden mode

Rule:

- AI proposals may request
- device policy decides

## Review screen rules for AI proposals

AI rationale must never replace transaction facts.

The device should display two separate sections:

### Section A: hard transaction facts

- chain
- action
- signer account
- destination or venue
- amount
- fee or fee estimate
- resulting asset movement

### Section B: AI context

- confidence band
- top rationale lines
- risk tags
- warnings

Display rule:

- transaction facts are primary
- AI rationale is secondary

## Confidence display rules

Confidence should be displayed as a bounded label, not as fake precision.

Recommended bands:

- `low`
- `medium`
- `high`

Optional internal numeric score may exist, but the user-facing device UI should not imply certainty the system does not really have.

## Companion interface rules

The companion app may send:

- raw market data
- unsigned transaction proposals
- structured AI proposals
- watch-only sync data

The companion app may not send:

- direct sign-now commands
- direct approve commands
- direct secure-element passthrough requests

The device should expose a proposal intake API, not a raw-signing API, for companion-facing use.

## Phase-specific product rules

### Phase 1

Allowed:

- voice query and navigation only
- AI advisory only

Not allowed:

- voice-based transfer drafting
- AI-generated executable trade proposals
- autonomous execution

### Phase 2

Allowed:

- structured AI proposals that open a review screen
- limited voice preparation for safe flows

Still forbidden:

- voice approval
- AI approval
- autonomous execution on the main wallet

### Later phases

Optional:

- segregated strategy wallet
- constrained AI proposals with strict on-device rules

Still required:

- local explicit user control for the main vault wallet

## Logging and privacy

Never log:

- mnemonic
- seed
- PIN
- private keys
- full sensitive transcripts if they include account secrets

Allowed logs:

- intent type
- confidence band
- proposal id
- chain id
- action type
- rule-engine accept or reject result

## Failure handling

If voice or AI fails, the fallback must be:

- degrade to manual UI

Never:

- silently execute best-effort guesses
- silently substitute missing fields
- auto-approve because confidence is high

## Recommended near-term implementation order

1. freeze the permission-class model
2. implement companion proposal intake as a structured interface
3. implement the local rule engine
4. add advisory AI display
5. add voice query and navigation
6. later add limited proposal-opening flows

## Related documents

- [PRODUCT_ARCHITECTURE_AND_ROADMAP.md](./PRODUCT_ARCHITECTURE_AND_ROADMAP.md)
- [ESP32_WALLET_PLATFORM_PLAN.md](./ESP32_WALLET_PLATFORM_PLAN.md)
- [DEVICE_STATE_MACHINE.md](./DEVICE_STATE_MACHINE.md)
- [ESP32_APPLET_CLIENT_API.md](./ESP32_APPLET_CLIENT_API.md)
- [TODO.md](../TODO.md)
