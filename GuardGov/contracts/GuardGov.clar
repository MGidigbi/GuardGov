;; contract title
;; Automated Governance Attack Detection and DAO Management
;; 
;; This contract monitors voting behavior and power shifts to detect
;; and mitigate potential governance attacks, such as flash loan voting
;; or rapid malicious accumulation of voting power.
;; It also includes a full suite of DAO proposal creation, voting,
;; and execution with timelocks to ensure safe governance.

;; constants
;; ---------------------------------------------------------
;; Error codes for unauthorized access and malicious activity
(define-constant err-unauthorized (err u100))
(define-constant err-cooldown-active (err u101))
(define-constant err-suspicious-activity (err u102))
(define-constant err-invalid-proposal (err u103))
(define-constant err-already-voted (err u104))
(define-constant err-voting-closed (err u105))
(define-constant err-voting-active (err u106))
(define-constant err-quorum-not-reached (err u107))
(define-constant err-timelock-active (err u108))
(define-constant err-already-executed (err u109))

;; The owner of the contract, allowed to unflag accounts and update parameters
(define-constant contract-owner tx-sender)

;; Default Attack detection thresholds
(define-constant default-power-spike-threshold u1000000) ;; Max sudden power increase allowed
(define-constant default-voting-cooldown-blocks u10)     ;; Blocks to wait before voting after a power shift

;; Governance parameters
(define-constant voting-period-blocks u144) ;; ~1 day of blocks assuming 10min blocks
(define-constant timelock-delay-blocks u144) ;; ~1 day delay before execution
(define-constant quorum-threshold u5000000) ;; Minimum votes required to pass

;; Proposal status states (enum representation)
(define-constant status-pending u0)
(define-constant status-active u1)
(define-constant status-passed u2)
(define-constant status-rejected u3)
(define-constant status-executed u4)

;; data maps and vars
;; ---------------------------------------------------------
;; Dynamic configuration for attack detection
(define-data-var power-spike-threshold uint default-power-spike-threshold)
(define-data-var voting-cooldown-blocks uint default-voting-cooldown-blocks)

;; Stores the block height and voting power of the user's last update
(define-map voting-power-snapshots principal { last-block: uint, power: uint })

;; Tracks accounts that have exhibited attack-like patterns (true = flagged)
(define-map flagged-accounts principal bool)

;; Tracks the total number of proposals
(define-data-var proposal-count uint u0)

;; Stores proposals details
(define-map proposals
    uint
    {
        creator: principal,
        start-block: uint,
        end-block: uint,
        execution-block: uint,
        for-votes: uint,
        against-votes: uint,
        status: uint,
        title: (string-ascii 50),
        description: (string-ascii 256)
    }
)

;; Tracks whether an account has voted on a specific proposal
(define-map votes { proposal-id: uint, voter: principal } bool)

;; private functions
;; ---------------------------------------------------------

;; @desc Checks if an account is currently flagged as suspicious
;; @param account The principal to check
;; @returns A boolean indicating if the account is flagged
(define-private (is-flagged (account principal))
    (default-to false (map-get? flagged-accounts account))
)

;; @desc Retrieves proposal details or fails
;; @param proposal-id The ID of the proposal
;; @returns (response tuple uint)
(define-private (get-proposal (proposal-id uint))
    (ok (unwrap! (map-get? proposals proposal-id) err-invalid-proposal))
)

;; public functions
;; ---------------------------------------------------------

;; @desc Updates attack detection thresholds (Admin only)
;; @param new-spike-threshold The new power spike threshold
;; @param new-cooldown-blocks The new cooldown blocks
;; @returns (response bool uint)
(define-public (update-detection-parameters (new-spike-threshold uint) (new-cooldown-blocks uint))
    (begin
        ;; Validate the sender is the contract owner
        (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
        
        ;; Update variables to adjust the security strictness
        (var-set power-spike-threshold new-spike-threshold)
        (var-set voting-cooldown-blocks new-cooldown-blocks)
        
        ;; Emit event for transparency
        (print { event: "parameters-updated", spike-threshold: new-spike-threshold, cooldown-blocks: new-cooldown-blocks })
        (ok true)
    )
)

;; @desc Unflags an account, allowing them to participate again (Admin only)
;; @param account The principal to unflag
;; @returns (response bool uint)
(define-public (unflag-account (account principal))
    (begin
        ;; Ensure only the contract owner can unflag accounts
        (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
        
        ;; Remove the malicious flag, granting access back to the protocol
        (map-set flagged-accounts account false)
        
        ;; Log the administrative action
        (print { event: "account-unflagged", account: account })
        (ok true)
    )
)

;; @desc Analyzes a voter's power shift to detect flash loan or flash-voting attacks
;; @param voter The principal attempting to vote or update power
;; @param new-power The new voting power they are claiming
;; @returns (response bool uint)
(define-public (detect-and-record-attack (voter principal) (new-power uint))
    (let
        (
            ;; Get current block height to calculate elapsed time
            (current-block block-height)
            
            ;; Retrieve the last snapshot of the voter's power
            (snapshot (default-to { last-block: u0, power: u0 } (map-get? voting-power-snapshots voter)))
            (last-block (get last-block snapshot))
            (old-power (get power snapshot))
            
            ;; Calculate blocks elapsed since the last power update
            (blocks-elapsed (- current-block last-block))
            
            ;; Calculate the increase in voting power (if any)
            (power-diff (if (> new-power old-power) (- new-power old-power) u0))
            
            ;; Determine if the power increase exceeds the safe dynamic threshold
            (is-spike (> power-diff (var-get power-spike-threshold)))
            
            ;; Determine if the increase happened within the cooldown window
            (is-flash (< blocks-elapsed (var-get voting-cooldown-blocks)))
        )
        ;; Ensure only authorized entities or the voter themselves can trigger this check
        (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender voter)) err-unauthorized)

        ;; If account is already flagged, we reject immediately to prevent further action
        (asserts! (not (is-flagged voter)) err-suspicious-activity)

        ;; Check for flash loan / flash voting pattern:
        ;; High power increase in a very short block window is a strong indicator of an attack
        (if (and is-spike is-flash)
            (begin
                ;; Flag the account as malicious
                (map-set flagged-accounts voter true)
                
                ;; Log the malicious activity for off-chain monitoring
                (print {
                    event: "governance-attack-detected",
                    voter: voter,
                    old-power: old-power,
                    new-power: new-power,
                    blocks-elapsed: blocks-elapsed
                })
                
                ;; Return error to halt the calling transaction
                err-suspicious-activity
            )
            (begin
                ;; Update the snapshot if the pattern is normal and safe
                (map-set voting-power-snapshots voter {
                    last-block: current-block,
                    power: new-power
                })
                
                ;; Successfully updated without detecting an attack
                (ok true)
            )
        )
    )
)

;; @desc Creates a new governance proposal
;; @param title The title of the proposal
;; @param description The detailed description
;; @returns (response uint uint)
(define-public (create-proposal (title (string-ascii 50)) (description (string-ascii 256)))
    (let
        (
            (new-id (+ (var-get proposal-count) u1))
            (current-block block-height)
        )
        ;; Ensure the creator is not a flagged attacker
        (asserts! (not (is-flagged tx-sender)) err-unauthorized)

        ;; Save the new proposal with computed timestamps and default states
        (map-set proposals new-id {
            creator: tx-sender,
            start-block: current-block,
            end-block: (+ current-block voting-period-blocks),
            execution-block: (+ current-block voting-period-blocks timelock-delay-blocks),
            for-votes: u0,
            against-votes: u0,
            status: status-active,
            title: title,
            description: description
        })

        ;; Update the global proposal count to keep track of indices
        (var-set proposal-count new-id)

        ;; Emit a creation event so indexers and UI can pick it up
        (print { event: "proposal-created", proposal-id: new-id, creator: tx-sender })

        (ok new-id)
    )
)

;; @desc Casts a vote on a proposal, integrating the attack detection natively
;; @param proposal-id The ID of the proposal to vote on
;; @param vote-for True to vote in favor, false to vote against
;; @param current-power The current voting power of the user
;; @returns (response bool uint)
(define-public (vote-on-proposal (proposal-id uint) (vote-for bool) (current-power uint))
    (let
        (
            (proposal (try! (get-proposal proposal-id)))
            (current-block block-height)
        )
        ;; 1. Check if the current block height is within the active voting period
        (asserts! (<= current-block (get end-block proposal)) err-voting-closed)
        
        ;; 2. Ensure the user has not already voted to prevent double-voting
        (asserts! (is-none (map-get? votes { proposal-id: proposal-id, voter: tx-sender })) err-already-voted)

        ;; 3. Run attack detection to ensure this isn't a flash vote.
        ;; This internal check evaluates the voter's power history.
        ;; If the voter acquired massive power suddenly, this step fails and halts the vote.
        (try! (detect-and-record-attack tx-sender current-power))

        ;; 4. Record the user's vote status in the mapping
        (map-set votes { proposal-id: proposal-id, voter: tx-sender } true)

        ;; 5. Update the proposal's aggregate vote counts based on their choice
        (if vote-for
            (map-set proposals proposal-id (merge proposal { for-votes: (+ (get for-votes proposal) current-power) }))
            (map-set proposals proposal-id (merge proposal { against-votes: (+ (get against-votes proposal) current-power) }))
        )

        ;; 6. Emit a public event detailing the vote
        (print { event: "vote-cast", proposal-id: proposal-id, voter: tx-sender, vote-for: vote-for, power: current-power })

        (ok true)
    )
)

;; @desc Finalizes a proposal, applies timelock checks, and executes if passed
;; @param proposal-id The ID of the proposal to execute
;; @returns (response bool uint)
;;
;; This function handles the lifecycle conclusion of a governance proposal.
;; It verifies that the voting period has concluded, ensures the
;; timelock delay has elapsed (to allow users to react to the outcome),
;; checks if the quorum requirement was met, and validates the vote count.
;; If all checks pass, it transitions the proposal status to executed.
;; It is designed to be called by any user once the execution criteria are met,
;; acting as an automated trigger for DAO operations.
(define-public (execute-proposal (proposal-id uint))
    (let
        (
            (proposal (try! (get-proposal proposal-id)))
            (current-block block-height)
            (total-votes (+ (get for-votes proposal) (get against-votes proposal)))
            (is-passed (> (get for-votes proposal) (get against-votes proposal)))
            (quorum-met (>= total-votes quorum-threshold))
        )
        ;; Check 1: Ensure the proposal is still in an active or pending state.
        ;; Once a proposal is executed or rejected, it should not be processed again.
        (asserts! (is-eq (get status proposal) status-active) err-already-executed)

        ;; Check 2: Ensure the voting period has officially closed.
        ;; No execution can happen while voting is still active.
        (asserts! (> current-block (get end-block proposal)) err-voting-active)

        ;; Check 3: Ensure the mandatory timelock delay has expired.
        ;; This protects the DAO against malicious proposals being executed instantly,
        ;; giving innocent users a window to exit the system if a hostile takeover occurs.
        (asserts! (>= current-block (get execution-block proposal)) err-timelock-active)

        ;; Determine final status based on quorum and vote majority
        (if (and quorum-met is-passed)
            (begin
                ;; Proposal passed and meets quorum requirements.
                ;; Transition the proposal to the executed status.
                (map-set proposals proposal-id (merge proposal { status: status-executed }))
                
                ;; <Insert custom logic to execute the DAO action here>
                ;; Example operations:
                ;; - Transferring funds from the DAO treasury
                ;; - Updating protocol configuration parameters
                ;; - Minting or burning governance tokens
                
                ;; Emit successful execution event for indexers
                (print { event: "proposal-executed", proposal-id: proposal-id })
                (ok true)
            )
            (begin
                ;; Proposal failed either due to low votes or missing quorum.
                ;; Update status to rejected and halt execution logic.
                (map-set proposals proposal-id (merge proposal { 
                    status: (if quorum-met status-rejected status-pending) 
                }))
                
                ;; Emit failure event with the specific reason for transparency
                (print { 
                    event: "proposal-failed", 
                    proposal-id: proposal-id, 
                    reason: (if quorum-met "rejected-by-votes" "quorum-not-met") 
                })
                err-quorum-not-reached
            )
        )
    )
)


