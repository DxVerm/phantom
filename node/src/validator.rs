//! Validator Management Module
//!
//! Provides lifecycle management for validators in the PHANTOM network:
//! - Validator registration and deregistration
//! - Staking and unstaking with unbonding periods
//! - Epoch-based rewards distribution
//! - Slashing for protocol violations
//! - Delegation support

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;

/// Validator management errors
#[derive(Error, Debug)]
pub enum ValidatorError {
    #[error("Validator not found: {0}")]
    NotFound(String),

    #[error("Validator already exists: {0}")]
    AlreadyExists(String),

    #[error("Insufficient stake: have {have}, need {need}")]
    InsufficientStake { have: u64, need: u64 },

    #[error("Insufficient balance for operation")]
    InsufficientBalance,

    #[error("Validator is not active")]
    NotActive,

    #[error("Validator is jailed until epoch {0}")]
    Jailed(u64),

    #[error("Unbonding already in progress")]
    UnbondingInProgress,

    #[error("Invalid commission rate: {0}")]
    InvalidCommission(u16),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Delegation not found")]
    DelegationNotFound,

    #[error("Storage error: {0}")]
    Storage(String),
}

pub type ValidatorResult<T> = Result<T, ValidatorError>;

/// Validator status in the network
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Registered but not yet active
    Pending,
    /// Actively participating in consensus
    Active,
    /// Temporarily suspended (can reactivate)
    Inactive,
    /// In unbonding period (stake locked)
    Unbonding { release_epoch: u64 },
    /// Slashed and jailed
    Jailed { until_epoch: u64, reason: String },
    /// Fully exited from the network
    Exited,
}

/// Validator information
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    /// Unique validator ID (derived from public key)
    pub id: [u8; 32],
    /// Operator address (receives rewards)
    pub operator: [u8; 32],
    /// Post-quantum public key (Dilithium)
    pub public_key: Vec<u8>,
    /// VRF public key for witness selection
    pub vrf_key: [u8; 32],
    /// Self-bonded stake
    pub self_stake: u64,
    /// Total delegated stake
    pub delegated_stake: u64,
    /// Commission rate (basis points, max 10000 = 100%)
    pub commission: u16,
    /// Current status
    pub status: ValidatorStatus,
    /// Reputation score (0.0 to 1000.0)
    pub reputation: f64,
    /// Total attestations made
    pub attestations: u64,
    /// Successful attestations
    pub successful_attestations: u64,
    /// Registration epoch
    pub registered_epoch: u64,
    /// Last activity epoch
    pub last_active_epoch: u64,
    /// Accumulated rewards (unclaimed)
    pub pending_rewards: u64,
    /// Total slashed amount
    pub total_slashed: u64,
    /// Description/moniker
    pub description: String,
    /// Website URL
    pub website: String,
}

impl ValidatorInfo {
    /// Create new validator info
    pub fn new(
        id: [u8; 32],
        operator: [u8; 32],
        public_key: Vec<u8>,
        vrf_key: [u8; 32],
        stake: u64,
        commission: u16,
        current_epoch: u64,
    ) -> Self {
        Self {
            id,
            operator,
            public_key,
            vrf_key,
            self_stake: stake,
            delegated_stake: 0,
            commission: commission.min(10000),
            status: ValidatorStatus::Pending,
            reputation: 100.0,
            attestations: 0,
            successful_attestations: 0,
            registered_epoch: current_epoch,
            last_active_epoch: current_epoch,
            pending_rewards: 0,
            total_slashed: 0,
            description: String::new(),
            website: String::new(),
        }
    }

    /// Get total stake (self + delegated)
    pub fn total_stake(&self) -> u64 {
        self.self_stake.saturating_add(self.delegated_stake)
    }

    /// Check if validator is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// Check if validator is jailed
    pub fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed { .. })
    }

    /// Check if validator can participate in consensus
    pub fn can_attest(&self, min_stake: u64) -> bool {
        self.is_active()
            && self.total_stake() >= min_stake
            && self.reputation > 0.0
    }

    /// Calculate selection weight
    pub fn selection_weight(&self) -> u64 {
        if !self.is_active() || self.reputation <= 0.0 {
            return 0;
        }

        let reputation_multiplier = 0.5 + (self.reputation / 1000.0 * 1.5);
        (self.total_stake() as f64 * reputation_multiplier) as u64
    }

    /// Success rate
    pub fn success_rate(&self) -> f64 {
        if self.attestations == 0 {
            return 1.0;
        }
        self.successful_attestations as f64 / self.attestations as f64
    }
}

/// Delegation from a delegator to a validator
#[derive(Clone, Debug)]
pub struct Delegation {
    /// Delegator address
    pub delegator: [u8; 32],
    /// Validator ID
    pub validator_id: [u8; 32],
    /// Delegated amount
    pub amount: u64,
    /// Starting epoch
    pub start_epoch: u64,
    /// Accumulated rewards (unclaimed)
    pub pending_rewards: u64,
}

/// Unbonding entry for delayed stake withdrawal
#[derive(Clone, Debug)]
pub struct UnbondingEntry {
    /// Validator or delegator address
    pub address: [u8; 32],
    /// Validator ID (if delegation unbonding)
    pub validator_id: Option<[u8; 32]>,
    /// Amount being unbonded
    pub amount: u64,
    /// Epoch when unbonding started
    pub start_epoch: u64,
    /// Epoch when funds become available
    pub release_epoch: u64,
    /// Whether this is from a delegation
    pub is_delegation: bool,
}

/// Slashing record
#[derive(Clone, Debug)]
pub struct SlashingRecord {
    /// Validator ID
    pub validator_id: [u8; 32],
    /// Amount slashed
    pub amount: u64,
    /// Epoch when slashing occurred
    pub epoch: u64,
    /// Reason for slashing
    pub reason: SlashingReason,
    /// Whether validator was jailed
    pub jailed: bool,
}

/// Reasons for slashing
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingReason {
    /// Signed conflicting attestations
    DoubleAttestation,
    /// Attested to invalid state
    InvalidAttestation,
    /// Extended unavailability
    Unavailability,
    /// Other protocol violation
    ProtocolViolation(String),
}

/// Validator manager configuration
#[derive(Clone, Debug)]
pub struct ValidatorManagerConfig {
    /// Minimum self-stake to register as validator
    pub min_self_stake: u64,
    /// Minimum delegation amount
    pub min_delegation: u64,
    /// Unbonding period in epochs
    pub unbonding_epochs: u64,
    /// Maximum commission rate (basis points)
    pub max_commission: u16,
    /// Maximum commission change per epoch (basis points)
    pub max_commission_change: u16,
    /// Jail duration for minor offenses (epochs)
    pub jail_duration_minor: u64,
    /// Jail duration for major offenses (epochs)
    pub jail_duration_major: u64,
    /// Slash percentage for double attestation (basis points)
    pub slash_double_attestation: u16,
    /// Slash percentage for unavailability (basis points)
    pub slash_unavailability: u16,
    /// Epochs of inactivity before unavailability slash
    pub max_inactive_epochs: u64,
    /// Block reward per epoch
    pub epoch_reward: u64,
    /// Maximum validators in active set
    pub max_validators: usize,
}

impl Default for ValidatorManagerConfig {
    fn default() -> Self {
        Self {
            min_self_stake: 10_000_000, // 10M tokens
            min_delegation: 1_000,      // 1K tokens
            unbonding_epochs: 21,       // ~21 days with 1 day epochs
            max_commission: 5000,       // 50%
            max_commission_change: 100, // 1% per epoch
            jail_duration_minor: 7,     // 7 epochs
            jail_duration_major: 30,    // 30 epochs
            slash_double_attestation: 500,  // 5%
            slash_unavailability: 10,       // 0.1%
            max_inactive_epochs: 3,
            epoch_reward: 1_000_000_000, // 1B per epoch total
            max_validators: 100,
        }
    }
}

/// Validator manager state
pub struct ValidatorManager {
    config: ValidatorManagerConfig,
    /// Validators by ID
    validators: HashMap<[u8; 32], ValidatorInfo>,
    /// Delegations by (delegator, validator_id)
    delegations: HashMap<([u8; 32], [u8; 32]), Delegation>,
    /// Unbonding queue
    unbonding_queue: VecDeque<UnbondingEntry>,
    /// Slashing history
    slashing_history: Vec<SlashingRecord>,
    /// Current epoch
    current_epoch: u64,
    /// Total bonded stake
    total_bonded: u64,
}

impl ValidatorManager {
    /// Create new validator manager
    pub fn new(config: ValidatorManagerConfig) -> Self {
        Self {
            config,
            validators: HashMap::new(),
            delegations: HashMap::new(),
            unbonding_queue: VecDeque::new(),
            slashing_history: Vec::new(),
            current_epoch: 0,
            total_bonded: 0,
        }
    }

    /// Register a new validator
    pub fn register_validator(
        &mut self,
        id: [u8; 32],
        operator: [u8; 32],
        public_key: Vec<u8>,
        vrf_key: [u8; 32],
        stake: u64,
        commission: u16,
    ) -> ValidatorResult<()> {
        // Check if already exists
        if self.validators.contains_key(&id) {
            return Err(ValidatorError::AlreadyExists(hex::encode(&id[..8])));
        }

        // Validate stake
        if stake < self.config.min_self_stake {
            return Err(ValidatorError::InsufficientStake {
                have: stake,
                need: self.config.min_self_stake,
            });
        }

        // Validate commission
        if commission > self.config.max_commission {
            return Err(ValidatorError::InvalidCommission(commission));
        }

        // Validate public key (basic length check)
        if public_key.len() < 32 {
            return Err(ValidatorError::InvalidPublicKey);
        }

        let validator = ValidatorInfo::new(
            id,
            operator,
            public_key,
            vrf_key,
            stake,
            commission,
            self.current_epoch,
        );

        self.total_bonded = self.total_bonded.saturating_add(stake);
        self.validators.insert(id, validator);

        Ok(())
    }

    /// Activate a pending validator
    pub fn activate_validator(&mut self, id: &[u8; 32]) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        match validator.status {
            ValidatorStatus::Pending | ValidatorStatus::Inactive => {
                validator.status = ValidatorStatus::Active;
                validator.last_active_epoch = self.current_epoch;
                Ok(())
            }
            ValidatorStatus::Jailed { until_epoch, .. } => {
                Err(ValidatorError::Jailed(until_epoch))
            }
            ValidatorStatus::Unbonding { .. } => {
                Err(ValidatorError::UnbondingInProgress)
            }
            _ => Ok(()),
        }
    }

    /// Deactivate a validator (voluntary)
    pub fn deactivate_validator(&mut self, id: &[u8; 32]) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        if validator.is_active() {
            validator.status = ValidatorStatus::Inactive;
        }

        Ok(())
    }

    /// Start unbonding a validator's stake
    pub fn begin_unbonding(&mut self, id: &[u8; 32]) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        // Check not already unbonding
        if matches!(validator.status, ValidatorStatus::Unbonding { .. }) {
            return Err(ValidatorError::UnbondingInProgress);
        }

        let release_epoch = self.current_epoch + self.config.unbonding_epochs;
        validator.status = ValidatorStatus::Unbonding { release_epoch };

        // Queue unbonding entry
        self.unbonding_queue.push_back(UnbondingEntry {
            address: validator.operator,
            validator_id: Some(id.clone()),
            amount: validator.self_stake,
            start_epoch: self.current_epoch,
            release_epoch,
            is_delegation: false,
        });

        Ok(())
    }

    /// Add self-stake to validator
    pub fn add_stake(&mut self, id: &[u8; 32], amount: u64) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        // Cannot add stake while unbonding
        if matches!(validator.status, ValidatorStatus::Unbonding { .. }) {
            return Err(ValidatorError::UnbondingInProgress);
        }

        validator.self_stake = validator.self_stake.saturating_add(amount);
        self.total_bonded = self.total_bonded.saturating_add(amount);

        Ok(())
    }

    /// Delegate to a validator
    pub fn delegate(
        &mut self,
        delegator: [u8; 32],
        validator_id: [u8; 32],
        amount: u64,
    ) -> ValidatorResult<()> {
        // Validate amount
        if amount < self.config.min_delegation {
            return Err(ValidatorError::InsufficientStake {
                have: amount,
                need: self.config.min_delegation,
            });
        }

        // Get validator
        let validator = self.validators.get_mut(&validator_id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&validator_id[..8])))?;

        // Cannot delegate to unbonding validator
        if matches!(validator.status, ValidatorStatus::Unbonding { .. } | ValidatorStatus::Exited) {
            return Err(ValidatorError::NotActive);
        }

        // Update validator's delegated stake
        validator.delegated_stake = validator.delegated_stake.saturating_add(amount);
        self.total_bonded = self.total_bonded.saturating_add(amount);

        // Create or update delegation
        let key = (delegator, validator_id);
        if let Some(delegation) = self.delegations.get_mut(&key) {
            delegation.amount = delegation.amount.saturating_add(amount);
        } else {
            self.delegations.insert(key, Delegation {
                delegator,
                validator_id,
                amount,
                start_epoch: self.current_epoch,
                pending_rewards: 0,
            });
        }

        Ok(())
    }

    /// Begin undelegation
    pub fn begin_undelegation(
        &mut self,
        delegator: [u8; 32],
        validator_id: [u8; 32],
        amount: u64,
    ) -> ValidatorResult<()> {
        let key = (delegator, validator_id);
        let delegation = self.delegations.get_mut(&key)
            .ok_or(ValidatorError::DelegationNotFound)?;

        if amount > delegation.amount {
            return Err(ValidatorError::InsufficientBalance);
        }

        // Update validator's delegated stake
        if let Some(validator) = self.validators.get_mut(&validator_id) {
            validator.delegated_stake = validator.delegated_stake.saturating_sub(amount);
        }

        delegation.amount = delegation.amount.saturating_sub(amount);
        self.total_bonded = self.total_bonded.saturating_sub(amount);

        // Queue unbonding
        let release_epoch = self.current_epoch + self.config.unbonding_epochs;
        self.unbonding_queue.push_back(UnbondingEntry {
            address: delegator,
            validator_id: Some(validator_id),
            amount,
            start_epoch: self.current_epoch,
            release_epoch,
            is_delegation: true,
        });

        // Remove delegation if empty
        if delegation.amount == 0 {
            self.delegations.remove(&key);
        }

        Ok(())
    }

    /// Slash a validator
    pub fn slash_validator(
        &mut self,
        id: &[u8; 32],
        reason: SlashingReason,
    ) -> ValidatorResult<u64> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        // Calculate slash amount based on reason
        let slash_rate = match &reason {
            SlashingReason::DoubleAttestation => self.config.slash_double_attestation,
            SlashingReason::InvalidAttestation => self.config.slash_double_attestation,
            SlashingReason::Unavailability => self.config.slash_unavailability,
            SlashingReason::ProtocolViolation(_) => self.config.slash_double_attestation,
        };

        let slash_amount = (validator.total_stake() as u128 * slash_rate as u128 / 10000) as u64;

        // Apply slash to self-stake first, then delegated
        let self_slash = slash_amount.min(validator.self_stake);
        validator.self_stake = validator.self_stake.saturating_sub(self_slash);

        let delegated_slash = slash_amount.saturating_sub(self_slash);
        validator.delegated_stake = validator.delegated_stake.saturating_sub(delegated_slash);

        validator.total_slashed = validator.total_slashed.saturating_add(slash_amount);
        validator.reputation = (validator.reputation - 50.0).max(0.0);

        self.total_bonded = self.total_bonded.saturating_sub(slash_amount);

        // Jail for major offenses
        let jailed = matches!(reason, SlashingReason::DoubleAttestation | SlashingReason::InvalidAttestation);
        if jailed {
            let jail_duration = if matches!(reason, SlashingReason::DoubleAttestation) {
                self.config.jail_duration_major
            } else {
                self.config.jail_duration_minor
            };

            validator.status = ValidatorStatus::Jailed {
                until_epoch: self.current_epoch + jail_duration,
                reason: format!("{:?}", reason),
            };
        }

        // Record slashing event
        self.slashing_history.push(SlashingRecord {
            validator_id: *id,
            amount: slash_amount,
            epoch: self.current_epoch,
            reason,
            jailed,
        });

        Ok(slash_amount)
    }

    /// Unjail a validator
    pub fn unjail(&mut self, id: &[u8; 32]) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        if let ValidatorStatus::Jailed { until_epoch, .. } = validator.status {
            if self.current_epoch < until_epoch {
                return Err(ValidatorError::Jailed(until_epoch));
            }

            // Check minimum stake still met
            if validator.total_stake() < self.config.min_self_stake {
                return Err(ValidatorError::InsufficientStake {
                    have: validator.total_stake(),
                    need: self.config.min_self_stake,
                });
            }

            validator.status = ValidatorStatus::Active;
            validator.last_active_epoch = self.current_epoch;
        }

        Ok(())
    }

    /// Update commission rate
    pub fn update_commission(&mut self, id: &[u8; 32], new_commission: u16) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        if new_commission > self.config.max_commission {
            return Err(ValidatorError::InvalidCommission(new_commission));
        }

        // Check max change per epoch
        let change = if new_commission > validator.commission {
            new_commission - validator.commission
        } else {
            validator.commission - new_commission
        };

        if change > self.config.max_commission_change {
            return Err(ValidatorError::InvalidCommission(new_commission));
        }

        validator.commission = new_commission;
        Ok(())
    }

    /// Update validator reputation after attestation
    pub fn update_reputation(&mut self, id: &[u8; 32], successful: bool) -> ValidatorResult<()> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        validator.attestations += 1;

        if successful {
            validator.successful_attestations += 1;
            validator.reputation = (validator.reputation * 0.995 + 1.0).min(1000.0);
        } else {
            validator.reputation = (validator.reputation * 0.995 - 5.0).max(0.0);
        }

        validator.last_active_epoch = self.current_epoch;
        Ok(())
    }

    /// Process epoch transition
    pub fn process_epoch(&mut self) -> Vec<UnbondingEntry> {
        self.current_epoch += 1;

        // Process unbonding queue
        let mut completed = Vec::new();
        while let Some(entry) = self.unbonding_queue.front() {
            if entry.release_epoch <= self.current_epoch {
                completed.push(self.unbonding_queue.pop_front().unwrap());
            } else {
                break;
            }
        }

        // Finalize unbonding validators
        for entry in &completed {
            if let Some(validator_id) = entry.validator_id {
                if !entry.is_delegation {
                    if let Some(validator) = self.validators.get_mut(&validator_id) {
                        validator.status = ValidatorStatus::Exited;
                    }
                }
            }
        }

        // Check for inactive validators
        let inactive: Vec<[u8; 32]> = self.validators
            .iter()
            .filter(|(_, v)| {
                v.is_active() &&
                self.current_epoch.saturating_sub(v.last_active_epoch) > self.config.max_inactive_epochs
            })
            .map(|(id, _)| *id)
            .collect();

        for id in inactive {
            let _ = self.slash_validator(&id, SlashingReason::Unavailability);
        }

        // Decay all reputations slightly
        for validator in self.validators.values_mut() {
            validator.reputation *= 0.999;
        }

        completed
    }

    /// Distribute epoch rewards
    pub fn distribute_rewards(&mut self) -> HashMap<[u8; 32], u64> {
        let mut distributions = HashMap::new();

        // Get total weight of active validators
        let total_weight: u64 = self.validators
            .values()
            .filter(|v| v.is_active())
            .map(|v| v.selection_weight())
            .sum();

        if total_weight == 0 {
            return distributions;
        }

        // Distribute proportionally to weight
        for validator in self.validators.values_mut() {
            if !validator.is_active() {
                continue;
            }

            let weight = validator.selection_weight();
            let reward = (self.config.epoch_reward as u128 * weight as u128 / total_weight as u128) as u64;

            // Calculate commission
            let commission = (reward as u128 * validator.commission as u128 / 10000) as u64;
            let delegator_rewards = reward.saturating_sub(commission);

            // Validator gets commission
            validator.pending_rewards = validator.pending_rewards.saturating_add(commission);
            distributions.insert(validator.id, commission);

            // Distribute to delegators proportionally
            if validator.delegated_stake > 0 {
                let delegator_share_per_unit = delegator_rewards as u128 * 1_000_000 / validator.delegated_stake as u128;

                for delegation in self.delegations.values_mut() {
                    if delegation.validator_id == validator.id {
                        let share = (delegation.amount as u128 * delegator_share_per_unit / 1_000_000) as u64;
                        delegation.pending_rewards = delegation.pending_rewards.saturating_add(share);
                        *distributions.entry(delegation.delegator).or_insert(0) += share;
                    }
                }
            }
        }

        distributions
    }

    /// Claim pending rewards
    pub fn claim_rewards(&mut self, id: &[u8; 32]) -> ValidatorResult<u64> {
        let validator = self.validators.get_mut(id)
            .ok_or_else(|| ValidatorError::NotFound(hex::encode(&id[..8])))?;

        let amount = validator.pending_rewards;
        validator.pending_rewards = 0;
        Ok(amount)
    }

    /// Claim delegation rewards
    pub fn claim_delegation_rewards(
        &mut self,
        delegator: [u8; 32],
        validator_id: [u8; 32],
    ) -> ValidatorResult<u64> {
        let key = (delegator, validator_id);
        let delegation = self.delegations.get_mut(&key)
            .ok_or(ValidatorError::DelegationNotFound)?;

        let amount = delegation.pending_rewards;
        delegation.pending_rewards = 0;
        Ok(amount)
    }

    /// Get validator info
    pub fn get_validator(&self, id: &[u8; 32]) -> Option<&ValidatorInfo> {
        self.validators.get(id)
    }

    /// Get all validators
    pub fn all_validators(&self) -> Vec<&ValidatorInfo> {
        self.validators.values().collect()
    }

    /// Get active validators sorted by weight
    pub fn active_validators_by_weight(&self) -> Vec<&ValidatorInfo> {
        let mut validators: Vec<_> = self.validators
            .values()
            .filter(|v| v.is_active())
            .collect();
        validators.sort_by(|a, b| b.selection_weight().cmp(&a.selection_weight()));
        validators
    }

    /// Get delegation info
    pub fn get_delegation(&self, delegator: &[u8; 32], validator_id: &[u8; 32]) -> Option<&Delegation> {
        self.delegations.get(&(*delegator, *validator_id))
    }

    /// Get all delegations for a delegator
    pub fn delegations_by_delegator(&self, delegator: &[u8; 32]) -> Vec<&Delegation> {
        self.delegations
            .values()
            .filter(|d| &d.delegator == delegator)
            .collect()
    }

    /// Get all delegations to a validator
    pub fn delegations_to_validator(&self, validator_id: &[u8; 32]) -> Vec<&Delegation> {
        self.delegations
            .values()
            .filter(|d| &d.validator_id == validator_id)
            .collect()
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Get total bonded stake
    pub fn total_bonded(&self) -> u64 {
        self.total_bonded
    }

    /// Get validator count
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Get active validator count
    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_active()).count()
    }

    /// Get slashing history
    pub fn slashing_history(&self) -> &[SlashingRecord] {
        &self.slashing_history
    }

    /// Get unbonding queue length
    pub fn unbonding_count(&self) -> usize {
        self.unbonding_queue.len()
    }

    /// Get statistics
    pub fn statistics(&self) -> ValidatorStatistics {
        let active = self.active_count();
        let total = self.validator_count();
        let avg_stake = if total > 0 {
            self.total_bonded / total as u64
        } else {
            0
        };
        let avg_reputation = if total > 0 {
            self.validators.values().map(|v| v.reputation).sum::<f64>() / total as f64
        } else {
            0.0
        };

        ValidatorStatistics {
            total_validators: total,
            active_validators: active,
            total_bonded: self.total_bonded,
            average_stake: avg_stake,
            average_reputation: avg_reputation,
            total_delegations: self.delegations.len(),
            pending_unbondings: self.unbonding_queue.len(),
            total_slashing_events: self.slashing_history.len(),
        }
    }
}

/// Validator set statistics
#[derive(Clone, Debug)]
pub struct ValidatorStatistics {
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_bonded: u64,
    pub average_stake: u64,
    pub average_reputation: f64,
    pub total_delegations: usize,
    pub pending_unbondings: usize,
    pub total_slashing_events: usize,
}

/// Thread-safe validator manager
pub struct SharedValidatorManager(Arc<RwLock<ValidatorManager>>);

impl SharedValidatorManager {
    /// Create new shared manager
    pub fn new(config: ValidatorManagerConfig) -> Self {
        Self(Arc::new(RwLock::new(ValidatorManager::new(config))))
    }

    /// Get read access
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, ValidatorManager> {
        self.0.read()
    }

    /// Get write access
    pub fn write(&self) -> parking_lot::RwLockWriteGuard<'_, ValidatorManager> {
        self.0.write()
    }
}

impl Clone for SharedValidatorManager {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> ValidatorManager {
        ValidatorManager::new(ValidatorManagerConfig {
            min_self_stake: 1000,
            min_delegation: 100,
            unbonding_epochs: 3,
            ..Default::default()
        })
    }

    fn create_validator_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn register_test_validator(manager: &mut ValidatorManager, n: u8, stake: u64) -> [u8; 32] {
        let id = create_validator_id(n);
        let operator = create_validator_id(n + 100);
        manager.register_validator(
            id,
            operator,
            vec![0u8; 64],
            [0u8; 32],
            stake,
            1000, // 10%
        ).unwrap();
        id
    }

    #[test]
    fn test_register_validator() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 5000);

        let validator = manager.get_validator(&id).unwrap();
        assert_eq!(validator.self_stake, 5000);
        assert!(matches!(validator.status, ValidatorStatus::Pending));
    }

    #[test]
    fn test_register_insufficient_stake() {
        let mut manager = create_test_manager();
        let id = create_validator_id(1);

        let result = manager.register_validator(
            id,
            create_validator_id(101),
            vec![0u8; 64],
            [0u8; 32],
            500, // Below minimum
            1000,
        );

        assert!(matches!(result, Err(ValidatorError::InsufficientStake { .. })));
    }

    #[test]
    fn test_activate_validator() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 5000);

        manager.activate_validator(&id).unwrap();

        let validator = manager.get_validator(&id).unwrap();
        assert!(validator.is_active());
    }

    #[test]
    fn test_delegation() {
        let mut manager = create_test_manager();
        let validator_id = register_test_validator(&mut manager, 1, 5000);
        manager.activate_validator(&validator_id).unwrap();

        let delegator = create_validator_id(200);
        manager.delegate(delegator, validator_id, 1000).unwrap();

        let validator = manager.get_validator(&validator_id).unwrap();
        assert_eq!(validator.delegated_stake, 1000);
        assert_eq!(validator.total_stake(), 6000);

        let delegation = manager.get_delegation(&delegator, &validator_id).unwrap();
        assert_eq!(delegation.amount, 1000);
    }

    #[test]
    fn test_unbonding() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 5000);
        manager.activate_validator(&id).unwrap();

        manager.begin_unbonding(&id).unwrap();

        let validator = manager.get_validator(&id).unwrap();
        assert!(matches!(validator.status, ValidatorStatus::Unbonding { release_epoch: 3 }));

        // Process 3 epochs
        for _ in 0..3 {
            manager.process_epoch();
        }

        let validator = manager.get_validator(&id).unwrap();
        assert!(matches!(validator.status, ValidatorStatus::Exited));
    }

    #[test]
    fn test_slashing() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 10000);
        manager.activate_validator(&id).unwrap();

        let slashed = manager.slash_validator(&id, SlashingReason::DoubleAttestation).unwrap();

        // 5% slash
        assert_eq!(slashed, 500);

        let validator = manager.get_validator(&id).unwrap();
        assert_eq!(validator.self_stake, 9500);
        assert!(validator.is_jailed());
    }

    #[test]
    fn test_unjail() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 10000);
        manager.activate_validator(&id).unwrap();

        manager.slash_validator(&id, SlashingReason::Unavailability).unwrap();

        // Can't unjail immediately
        assert!(manager.unjail(&id).is_err());

        // Process enough epochs
        for _ in 0..8 {
            manager.process_epoch();
        }

        manager.unjail(&id).unwrap();
        let validator = manager.get_validator(&id).unwrap();
        assert!(validator.is_active());
    }

    #[test]
    fn test_reward_distribution() {
        let mut manager = create_test_manager();

        // Register and activate validators
        for i in 1..=3 {
            let id = register_test_validator(&mut manager, i, 10000 * i as u64);
            manager.activate_validator(&id).unwrap();
        }

        let rewards = manager.distribute_rewards();

        // Should have rewards for all 3 validators
        assert_eq!(rewards.len(), 3);

        // Higher stake = higher rewards
        let v1_rewards = rewards.get(&create_validator_id(1)).unwrap();
        let v3_rewards = rewards.get(&create_validator_id(3)).unwrap();
        assert!(v3_rewards > v1_rewards);
    }

    #[test]
    fn test_delegation_undelegation() {
        let mut manager = create_test_manager();
        let validator_id = register_test_validator(&mut manager, 1, 5000);
        manager.activate_validator(&validator_id).unwrap();

        let delegator = create_validator_id(200);
        manager.delegate(delegator, validator_id, 1000).unwrap();

        // Begin undelegation
        manager.begin_undelegation(delegator, validator_id, 500).unwrap();

        let delegation = manager.get_delegation(&delegator, &validator_id).unwrap();
        assert_eq!(delegation.amount, 500);

        let validator = manager.get_validator(&validator_id).unwrap();
        assert_eq!(validator.delegated_stake, 500);
    }

    #[test]
    fn test_commission_update() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 5000);

        // Valid update (within max change)
        manager.update_commission(&id, 1100).unwrap();

        let validator = manager.get_validator(&id).unwrap();
        assert_eq!(validator.commission, 1100);

        // Invalid update (exceeds max change)
        let result = manager.update_commission(&id, 2000);
        assert!(matches!(result, Err(ValidatorError::InvalidCommission(_))));
    }

    #[test]
    fn test_reputation_update() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 5000);
        manager.activate_validator(&id).unwrap();

        let initial_rep = manager.get_validator(&id).unwrap().reputation;

        // Successful attestation
        manager.update_reputation(&id, true).unwrap();
        let after_success = manager.get_validator(&id).unwrap().reputation;
        assert!(after_success > initial_rep * 0.995);

        // Failed attestation
        manager.update_reputation(&id, false).unwrap();
        let after_fail = manager.get_validator(&id).unwrap().reputation;
        assert!(after_fail < after_success);
    }

    #[test]
    fn test_statistics() {
        let mut manager = create_test_manager();

        for i in 1..=5 {
            let id = register_test_validator(&mut manager, i, 5000);
            if i <= 3 {
                manager.activate_validator(&id).unwrap();
            }
        }

        let stats = manager.statistics();
        assert_eq!(stats.total_validators, 5);
        assert_eq!(stats.active_validators, 3);
        assert_eq!(stats.total_bonded, 25000);
    }

    #[test]
    fn test_inactive_slashing() {
        let mut manager = ValidatorManager::new(ValidatorManagerConfig {
            min_self_stake: 1000,
            max_inactive_epochs: 2,
            slash_unavailability: 100, // 1%
            ..Default::default()
        });

        let id = register_test_validator(&mut manager, 1, 10000);
        manager.activate_validator(&id).unwrap();

        // Process epochs without activity
        for _ in 0..4 {
            manager.process_epoch();
        }

        let validator = manager.get_validator(&id).unwrap();
        assert!(validator.total_slashed > 0);
    }

    #[test]
    fn test_claim_rewards() {
        let mut manager = create_test_manager();
        let id = register_test_validator(&mut manager, 1, 10000);
        manager.activate_validator(&id).unwrap();

        // Distribute rewards
        manager.distribute_rewards();

        // Claim
        let claimed = manager.claim_rewards(&id).unwrap();
        assert!(claimed > 0);

        // Second claim should be 0
        let claimed2 = manager.claim_rewards(&id).unwrap();
        assert_eq!(claimed2, 0);
    }
}
