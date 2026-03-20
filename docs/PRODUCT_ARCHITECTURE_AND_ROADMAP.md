# Product Architecture And Roadmap

This document describes the full product direction for the closed hardware wallet platform built on:

- `ESP32S3 N16R16`
- `SatochipApplet` on JavaCard
- a companion desktop or mobile application
- optional cloud or local AI services

It is intentionally broader than the applet or firmware API documents. Its purpose is to answer:

- what the product is
- how the full system is structured
- how development should be staged
- what the final product should be able to do

## Product definition

The target product is a closed smart hardware wallet.

It is not:

- a JavaCard demo
- a card reader utility
- a PC-hosted wallet that happens to use a smartcard

It is:

- a self-contained wallet device
- a secure signing terminal
- a transaction review device
- a multi-chain account manager
- later, a voice-assisted and AI-assisted trading terminal

## Product goals

The final product should support:

1. on-device wallet creation and recovery
2. secure custody of multi-chain wallet material
3. on-device transaction review and signing
4. support for major crypto ecosystems
5. optional voice interaction for navigation and transaction preparation
6. optional AI-assisted market analysis and trade proposal generation

## Final user experience

The intended end-state user experience is:

- the user holds a dedicated hardware wallet
- the device can show account status, addresses, balances, and pending transactions
- the device can receive a transaction proposal from a companion or from its own network logic
- the user confirms the operation directly on the hardware wallet screen
- the secure element signs only after local confirmation
- the device can optionally accept voice commands for query and flow navigation
- the device can optionally consume AI-generated trade suggestions
- no AI or companion app can directly bypass device review or device confirmation

## System architecture

The system is a four-domain architecture.

```text
+------------------------------------------------------------+
| AI / Data Services                                          |
| - market feeds                                               |
| - chain analytics                                            |
| - news / sentiment / signal processing                       |
| - LLM reasoning and proposal generation                      |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
| Desktop / Mobile Companion                                  |
| - watch-only display                                         |
| - portfolio sync                                             |
| - blockchain relay                                           |
| - transaction proposal relay                                 |
| - signed transaction broadcast                               |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
| ESP32S3 Device                                               |
| - primary wallet host                                        |
| - display / buttons / optional voice front-end               |
| - BIP39 mnemonic engine                                      |
| - account policy and transaction parsing                     |
| - applet client and secure workflow control                  |
| - final user approval boundary                               |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
| JavaCard / SatochipApplet                                    |
| - secure channel                                              |
| - PIN / setup / policy                                        |
| - BIP32 + secp256k1                                           |
| - Ed25519 + SLIP-0010                                         |
| - long-term secret custody and signatures                     |
+------------------------------------------------------------+
```

## Trust boundaries

This product only remains secure if these trust boundaries stay fixed.

### JavaCard

Trusted for:

- long-term key custody
- path derivation
- signatures
- security-critical policy enforcement

Not trusted for:

- user-facing parsing
- rich transaction display
- AI logic

### ESP32S3

Trusted for:

- device state machine
- transaction parsing and confirmation
- wallet UX
- voice interaction handling
- enforcement of product path policy

Not trusted for:

- long-term cleartext seed retention

### Companion app

Trusted for:

- convenience only

Not trusted for:

- final transaction semantics
- final signing approval
- direct access to private key operations

### AI services

Trusted for:

- nothing security-critical

Allowed to do:

- suggest
- summarize
- classify
- rank opportunities
- produce structured proposals

Never allowed to do:

- directly authorize signing
- directly trigger funds movement without device approval

## Security model

The system uses a split-responsibility design.

- `JavaCard` protects keys
- `ESP32S3` protects the human approval loop
- the companion app improves connectivity and visibility
- AI improves information quality, not authority

The non-negotiable rule is:

- every value-moving operation must be confirmed locally on the device

## Core capability layers

### Layer 1: secure wallet core

- PIN
- seed import
- BIP32
- Ed25519
- transaction signing

### Layer 2: closed device workflow

- wallet setup and recovery
- local display
- local account browsing
- local review and approval

### Layer 3: multi-chain support

- Bitcoin
- Solana
- Ethereum / EVM
- selected Ed25519 chains

### Layer 4: smart interaction

- voice navigation
- AI portfolio summary
- AI trade suggestions
- rule-constrained semi-automation

## Coin strategy

The product should be built as a dual-curve platform.

### secp256k1 domain

Primary targets:

- Bitcoin
- Ethereum / EVM
- Litecoin
- Bitcoin Cash / eCash

### Ed25519 domain

Primary targets:

- Solana
- Aptos
- Sui
- Stellar
- Tezos
- NEAR

### Explicitly out of early scope

- Cardano
- Polkadot
- Monero

These require different derivation or signature models and should not block the core product.

## Device operating modes

The device should eventually support these operating modes:

1. setup mode
2. locked wallet mode
3. unlocked wallet mode
4. review and sign mode
5. companion-connected mode
6. voice-assistant mode
7. AI-advisory mode
8. recovery mode

The implementation base for the first four modes is already being defined in:

- [DEVICE_STATE_MACHINE.md](./DEVICE_STATE_MACHINE.md)

## Voice interaction model

Voice should be treated as an input convenience layer, not as a signing authority.

### Good uses of voice

- navigation
- account queries
- balance queries
- switching chain view
- opening a prepared transaction review screen
- asking for market summaries

### Unsafe uses of voice

- final signing approval without button or touch confirmation
- raw seed or PIN input in normal operating mode
- blind command execution from natural language alone

### Product rule

Voice may initiate a flow, but final approval must still require a local deliberate confirmation action.

Recommended pattern:

- voice command
  -> device interprets intent
  -> device renders structured preview
  -> user confirms physically
  -> applet signs

Detailed contract and rules:

- [VOICE_AI_INTERFACE_RULES.md](./VOICE_AI_INTERFACE_RULES.md)

## AI interaction model

AI should be productized in three maturity levels.

### Level 1: advisory AI

The AI may:

- summarize portfolio exposure
- summarize market conditions
- identify candidate entries or exits
- explain why a chain or asset is moving

The AI may not:

- create executable actions without device review

### Level 2: proposal AI

The AI may:

- generate a structured trade proposal
- suggest allocation size
- attach rationale and confidence
- attach risk tags

The device must then:

- validate the proposal
- show the exact resulting transaction
- require local user confirmation

### Level 3: constrained semi-automation

This is optional and much later.

The AI may propose trades under user-defined rules:

- asset whitelist
- max order size
- daily risk budget
- slippage cap
- venue whitelist

Even here, one of two safety models should apply:

- local confirmation still required for each value-moving action
- or use a separate limited-risk trading wallet rather than the main vault wallet

## Important AI constraint

`ESP32S3 N16R16` is not the place to run a large frontier model locally.

A realistic architecture is:

- lightweight local voice frontend on device
- cloud or local-server LLM off-device
- structured result sent back to device
- device performs rule validation and local approval

That means the product is:

- AI-assisted
- not AI-controlled

Detailed contract and rules:

- [VOICE_AI_INTERFACE_RULES.md](./VOICE_AI_INTERFACE_RULES.md)

## Product development phases

The work should be staged.

### Phase 0: secure foundation

- stabilize `SatochipApplet`
- complete Ed25519 integration hardening
- freeze known-good CAP baseline
- keep real-card regression passing

### Phase 1: closed-wallet MVP

- implement `ESP32S3` applet client
- implement device state machine
- implement BIP39 on device
- support Bitcoin and Solana
- allow on-device review and signing

Exit criteria:

- a user can create or recover a wallet on the device
- a user can sign Bitcoin and Solana transactions after local review

### Phase 2: companion productization

- add desktop companion app
- add optional mobile companion app
- add watch-only sync
- add signed transaction broadcast
- add version negotiation and diagnostics

Exit criteria:

- user can manage daily usage from companion surfaces without trusting them

### Phase 3: major-chain expansion

- add Ethereum / EVM
- improve multi-account support
- add more Ed25519 chains
- improve portfolio summary on device

Exit criteria:

- device supports a practical set of mainstream chains

### Phase 4: richer local UX

- improve address book and account naming
- improve history display
- add QR workflows if hardware permits
- add better recovery and troubleshooting UX

### Phase 5: voice assistant

- add wake word or explicit voice action mode
- add small-footprint speech frontend
- add intent parser integration
- add safe query and navigation flows

Exit criteria:

- user can query and navigate by voice without weakening signing safety

### Phase 6: AI-assisted trading

- ingest market and chain data
- connect external LLM or local inference service
- produce market summaries and trade suggestions
- convert suggestions into structured reviewable proposals

Exit criteria:

- AI can assist decision-making without bypassing hardware confirmation

### Phase 7: constrained strategy automation

- add rule engine
- add policy engine
- add per-strategy risk envelopes
- optionally enable limited auto-execution in segregated wallets

This phase is optional and should not be attempted until the earlier product is stable.

## Recommended implementation order right now

The current practical order should be:

1. finish applet hardening
2. finish `ESP32S3` applet client implementation
3. implement provisioning and BIP39
4. complete Bitcoin MVP
5. complete Solana MVP
6. add companion relay and broadcast
7. add Ethereum / EVM
8. add voice
9. add AI

## Final product outcome

If the roadmap is completed successfully, the product should become:

- a closed hardware wallet
- a multi-chain signing device
- a transaction review terminal
- a companion-connected but companion-independent wallet
- a voice-assisted secure wallet UI
- an AI-assisted crypto decision and execution terminal with strict local approval rules

## References

- [ESP32_WALLET_PLATFORM_PLAN.md](./ESP32_WALLET_PLATFORM_PLAN.md)
- [VOICE_AI_INTERFACE_RULES.md](./VOICE_AI_INTERFACE_RULES.md)
- [DEVICE_STATE_MACHINE.md](./DEVICE_STATE_MACHINE.md)
- [ESP32_APPLET_CLIENT_API.md](./ESP32_APPLET_CLIENT_API.md)
- [ED25519_INTEGRATION.md](./ED25519_INTEGRATION.md)
- [TODO.md](../TODO.md)
