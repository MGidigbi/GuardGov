# GuardGov: Automated Governance Attack Detection & DAO Management

## Table of Contents
* Introduction
* Core Features
* Technical Architecture
* Contract Configuration
* Governance Lifecycle
* Security Mechanism: Anti-Flash Loan Detection
* Detailed Function Reference
    * Private Functions
    * Public Functions
    * Read-Only Functions (Internal State)
* Error Codes
* Integration Guide
* Development and Testing
* Contribution Guidelines
* License

---

## Introduction
I present **GuardGov**, a sophisticated Clarity smart contract designed for the Stacks blockchain. GuardGov serves as a robust framework for Decentralized Autonomous Organizations (DAOs) that require more than just simple voting. It integrates an automated "Watchtower" system that monitors voting power shifts in real-time to prevent common DeFi exploits such as flash loan-assisted governance takeovers.

In traditional DAOs, an attacker can borrow a massive amount of tokens, vote on a malicious proposal, and return the tokens in the same block or shortly after. GuardGov mitigates this by enforcing power-increase thresholds and mandatory cooldown periods, ensuring that only "skin-in-the-game" participants can influence the protocol.

---

## Core Features
* **Dynamic Attack Detection:** Monitors `voting-power-snapshots` to detect anomalous spikes in voting weight.
* **Account Flagging:** Automatically blacklists principals exhibiting suspicious behavior, preventing them from creating proposals or voting.
* **Timelocked Execution:** Every passed proposal must undergo a mandatory delay period, allowing the community to react to outcomes.
* **Quorum Enforcement:** Ensures a minimum level of participation before any proposal is considered valid.
* **Administrative Oversight:** Provides the contract owner with tools to fine-tune security parameters and rehabilitate wrongly flagged accounts.

---

## Technical Architecture
GuardGov is built using **Clarity 2.0**. It leverages a state-machine approach to manage proposals, transitioning them through various stages: `status-active` -> `status-passed` -> `status-executed`.



The contract utilizes three primary data structures:
1.  **Proposals Map:** Stores the metadata, block heights, and vote tallies for every governance action.
2.  **Voting Power Snapshots:** A historical record of user power used to calculate the delta ($\Delta$) between interactions.
3.  **Flagged Accounts Map:** A persistent registry of addresses restricted from governance.

---

## Contract Configuration
The contract is governed by several constants and data variables that define its sensitivity to attacks:

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| `power-spike-threshold` | 1,000,000 | The maximum allowed increase in power within the cooldown window. |
| `voting-cooldown-blocks` | 10 | The number of blocks that must pass between power updates. |
| `voting-period-blocks` | 144 | Duration of the voting phase (~24 hours). |
| `timelock-delay-blocks` | 144 | The "grace period" between a successful vote and execution. |
| `quorum-threshold` | 5,000,000 | Total votes ($For + Against$) required for a valid result. |

---

## Governance Lifecycle
1.  **Creation:** A non-flagged user calls `create-proposal`.
2.  **Voting:** Users call `vote-on-proposal`. During this call, `detect-and-record-attack` is triggered.
3.  **Conclusion:** Once `end-block` is surpassed, voting stops.
4.  **Timelock:** The proposal enters a waiting period.
5.  **Execution:** If `quorum-met` and `is-passed`, the `execute-proposal` function can be triggered by any user.

---

## Security Mechanism: Anti-Flash Loan Detection
The heart of GuardGov is the `detect-and-record-attack` logic. It implements a mathematical check against rapid accumulation:

$$\text{Power Increase} = P_{new} - P_{old}$$
$$\text{Blocks Elapsed} = B_{current} - B_{last\_update}$$

An account is flagged if:
1.  $(P_{new} - P_{old}) > \text{power-spike-threshold}$
2.  **AND** $(B_{current} - B_{last\_update}) < \text{voting-cooldown-blocks}$



---

## Detailed Function Reference

### Private Functions

#### `is-flagged`
* **Input:** `(account principal)`
* **Logic:** Performs a `map-get?` on the `flagged-accounts` map.
* **Output:** Returns a boolean. Used internally to gate access to voting and proposal creation.

#### `get-proposal`
* **Input:** `(proposal-id uint)`
* **Logic:** Attempts to retrieve a proposal tuple.
* **Output:** Returns `(ok tuple)` or `err-invalid-proposal`.

---

### Public Functions

#### `update-detection-parameters`
Allows the `contract-owner` to adjust the sensitivity of the attack detection engine.
* **Access:** Admin Only.
* **Parameters:** `new-spike-threshold` (uint), `new-cooldown-blocks` (uint).

#### `unflag-account`
An administrative "pardon" function to restore voting rights to a principal.
* **Access:** Admin Only.
* **Parameters:** `account` (principal).

#### `detect-and-record-attack`
The primary security gate. It evaluates the voter's history and updates their snapshot if they pass the check.
* **Logic:** Calculates power delta and block delta. If the thresholds are breached, the user is permanently flagged until admin intervention.

#### `create-proposal`
Initializes a new governance record.
* **Requirements:** Sender must not be flagged.
* **Parameters:** `title` (string-ascii 50), `description` (string-ascii 256).

#### `vote-on-proposal`
Casts a vote and simultaneously runs the attack detection check.
* **Logic:** Verifies the voting window, checks for double-voting, runs the security check, and updates the `for-votes` or `against-votes` tally.

#### `execute-proposal`
The finalization trigger.
* **Logic:** Verifies that the voting period is over, the timelock has expired, and quorum has been met. If successful, it updates the status to `status-executed`.

---

### Read-Only Functions (Internal State)
*Note: While not explicitly defined with `define-read-only` in the snippet provided, the following maps are accessible via standard node RPC calls:*
* **`proposals`**: Query the state and vote count of any proposal.
* **`voting-power-snapshots`**: View the last recorded block and power for any user.
* **`flagged-accounts`**: Check the status of a specific principal.

---

## Error Codes
| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `u100` | `err-unauthorized` | The caller is not the owner or authorized. |
| `u102` | `err-suspicious-activity` | The account is flagged or an attack was detected. |
| `u105` | `err-voting-closed` | Attempted to vote after the `end-block`. |
| `u107` | `err-quorum-not-reached` | Proposal failed due to insufficient participation. |
| `u108` | `err-timelock-active` | Execution attempted before the delay period ended. |

---

## Integration Guide
To integrate GuardGov with a front-end application:
1.  **Fetch Proposals:** Use `get-map-entry` to pull proposal details for display.
2.  **Calculate Power:** Ensure your UI passes the correct `current-power` (often pulled from a separate token contract) to the `vote-on-proposal` function.
3.  **Monitor Events:** Listen for `governance-attack-detected` events to provide real-time security alerts.

---

## Development and Testing
To test GuardGov locally, use the **Clarinet** framework:
```bash
clarinet check
clarinet test
```
Recommended test cases include:
* Simulating a vote with a power increase of `u2000000` within 2 blocks to trigger the flag.
* Attempting to execute a proposal exactly 1 block before the timelock expires.

---

## Contribution Guidelines
I welcome contributions to GuardGov! Please follow these steps:
1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/AmazingSecurity`).
3.  Ensure all functions are documented with SIP-005 traits.
4.  Submit a Pull Request with detailed Clarinet test logs.

---

## License

MIT License

Copyright (c) 2026 GuardGov Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---
