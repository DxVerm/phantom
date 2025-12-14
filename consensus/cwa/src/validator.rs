//! CWA Validator and ValidatorSet
//!
//! Validators participate in Cryptographic Witness Attestation by:
//! - Staking tokens to become eligible
//! - Being selected as witnesses via VRF
//! - Signing attestations for state updates
//! - Building reputation through honest participation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reputation parameters
const REPUTATION_DECAY: f64 = 0.995;
const REPUTATION_REWARD: f64 = 1.0;
const REPUTATION_PENALTY: f64 = 5.0;
const INITIAL_REPUTATION: f64 = 100.0;
const MIN_REPUTATION: f64 = 0.0;
const MAX_REPUTATION: f64 = 1000.0;

/// A validator in the CWA network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    /// Unique identifier (derived from public key)
    pub id: [u8; 32],
    /// Post-quantum public key (Dilithium)
    pub public_key: Vec<u8>,
    /// VRF public key for witness selection
    pub vrf_public_key: [u8; 32],
    /// Staked amount
    pub stake: u64,
    /// Whether actively participating
    pub active: bool,
    /// Reputation score (affects selection probability)
    pub reputation: f64,
    /// Total attestations made
    pub attestation_count: u64,
    /// Successful attestations
    pub successful_attestations: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last activity timestamp
    pub last_active: u64,
    /// Slashing history
    pub slashing_events: Vec<SlashingEvent>,
}

/// Record of a slashing event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvent {
    /// When the slashing occurred
    pub timestamp: u64,
    /// Amount slashed
    pub amount: u64,
    /// Reason for slashing
    pub reason: SlashingReason,
}

/// Reasons for slashing a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SlashingReason {
    /// Submitted conflicting attestations
    DoubleAttestation,
    /// Attested to invalid state
    InvalidAttestation,
    /// Extended offline period
    Unavailable,
    /// Other protocol violation
    ProtocolViolation(String),
}

impl Validator {
    /// Create a new validator
    pub fn new(
        id: [u8; 32],
        public_key: Vec<u8>,
        vrf_public_key: [u8; 32],
        stake: u64,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id,
            public_key,
            vrf_public_key,
            stake,
            active: true,
            reputation: INITIAL_REPUTATION,
            attestation_count: 0,
            successful_attestations: 0,
            registered_at: now,
            last_active: now,
            slashing_events: Vec::new(),
        }
    }

    /// Check if validator meets minimum requirements
    pub fn is_eligible(&self, min_stake: u64) -> bool {
        self.active
            && self.stake >= min_stake
            && self.reputation > MIN_REPUTATION
    }

    /// Calculate selection weight based on stake and reputation
    /// Higher stake and reputation = higher chance of selection
    pub fn selection_weight(&self) -> u64 {
        if !self.active || self.reputation <= 0.0 {
            return 0;
        }

        // Weight = stake * reputation_multiplier
        // Reputation multiplier ranges from 0.5 to 2.0
        let reputation_multiplier = 0.5 + (self.reputation / MAX_REPUTATION * 1.5);

        (self.stake as f64 * reputation_multiplier) as u64
    }

    /// Update reputation based on attestation outcome
    pub fn update_reputation(&mut self, successful: bool) {
        // Apply decay first
        self.reputation *= REPUTATION_DECAY;

        if successful {
            self.reputation += REPUTATION_REWARD;
            self.successful_attestations += 1;
        } else {
            self.reputation -= REPUTATION_PENALTY;
        }

        // Clamp to valid range
        self.reputation = self.reputation.clamp(MIN_REPUTATION, MAX_REPUTATION);

        self.attestation_count += 1;
        self.last_active = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Apply a slashing penalty
    pub fn slash(&mut self, amount: u64, reason: SlashingReason) {
        let actual_slash = amount.min(self.stake);
        self.stake = self.stake.saturating_sub(actual_slash);

        // Reputation hit for slashing
        self.reputation = (self.reputation - 50.0).max(MIN_REPUTATION);

        self.slashing_events.push(SlashingEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            amount: actual_slash,
            reason,
        });

        // Deactivate if stake too low
        if self.stake == 0 {
            self.active = false;
        }
    }

    /// Add stake
    pub fn add_stake(&mut self, amount: u64) {
        self.stake = self.stake.saturating_add(amount);
    }

    /// Remove stake (with unbonding period in production)
    pub fn remove_stake(&mut self, amount: u64) -> u64 {
        let actual = amount.min(self.stake);
        self.stake = self.stake.saturating_sub(actual);
        actual
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.attestation_count == 0 {
            return 1.0;
        }
        self.successful_attestations as f64 / self.attestation_count as f64
    }

    /// Deactivate validator
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Reactivate validator
    pub fn reactivate(&mut self) {
        self.active = true;
        self.last_active = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// A set of validators with efficient lookups
#[derive(Clone, Debug, Default)]
pub struct ValidatorSet {
    /// Validators by ID
    validators: HashMap<[u8; 32], Validator>,
    /// Total stake in the set
    total_stake: u64,
}

impl ValidatorSet {
    /// Create a new empty validator set
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: 0,
        }
    }

    /// Add a validator to the set
    pub fn add(&mut self, validator: Validator) {
        self.total_stake += validator.stake;
        self.validators.insert(validator.id, validator);
    }

    /// Remove a validator from the set
    pub fn remove(&mut self, id: &[u8; 32]) -> Option<Validator> {
        if let Some(validator) = self.validators.remove(id) {
            self.total_stake = self.total_stake.saturating_sub(validator.stake);
            Some(validator)
        } else {
            None
        }
    }

    /// Get a validator by ID
    pub fn get(&self, id: &[u8; 32]) -> Option<&Validator> {
        self.validators.get(id)
    }

    /// Get a mutable reference to a validator
    pub fn get_mut(&mut self, id: &[u8; 32]) -> Option<&mut Validator> {
        self.validators.get_mut(id)
    }

    /// Check if validator exists
    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.validators.contains_key(id)
    }

    /// Get all validators
    pub fn all(&self) -> Vec<&Validator> {
        self.validators.values().collect()
    }

    /// Get eligible validators (active with minimum stake)
    pub fn eligible(&self, min_stake: u64) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.is_eligible(min_stake))
            .collect()
    }

    /// Get active validators
    pub fn active(&self) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.active)
            .collect()
    }

    /// Get total number of validators
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get total stake
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Get total selection weight
    pub fn total_weight(&self) -> u64 {
        self.validators
            .values()
            .map(|v| v.selection_weight())
            .sum()
    }

    /// Update stake for a validator
    pub fn update_stake(&mut self, id: &[u8; 32], new_stake: u64) -> bool {
        if let Some(validator) = self.validators.get_mut(id) {
            self.total_stake = self.total_stake
                .saturating_sub(validator.stake)
                .saturating_add(new_stake);
            validator.stake = new_stake;
            true
        } else {
            false
        }
    }

    /// Slash a validator
    pub fn slash(&mut self, id: &[u8; 32], amount: u64, reason: SlashingReason) -> Option<u64> {
        if let Some(validator) = self.validators.get_mut(id) {
            let old_stake = validator.stake;
            validator.slash(amount, reason);
            let slashed = old_stake - validator.stake;
            self.total_stake = self.total_stake.saturating_sub(slashed);
            Some(slashed)
        } else {
            None
        }
    }

    /// Get validators sorted by selection weight (descending)
    pub fn by_weight(&self) -> Vec<&Validator> {
        let mut validators: Vec<_> = self.validators.values().collect();
        validators.sort_by(|a, b| b.selection_weight().cmp(&a.selection_weight()));
        validators
    }

    /// Get validators sorted by reputation (descending)
    pub fn by_reputation(&self) -> Vec<&Validator> {
        let mut validators: Vec<_> = self.validators.values().collect();
        validators.sort_by(|a, b| {
            b.reputation.partial_cmp(&a.reputation).unwrap_or(std::cmp::Ordering::Equal)
        });
        validators
    }

    /// Apply reputation decay to all validators
    pub fn decay_reputations(&mut self) {
        for validator in self.validators.values_mut() {
            validator.reputation *= REPUTATION_DECAY;
            validator.reputation = validator.reputation.max(MIN_REPUTATION);
        }
    }

    /// Get network statistics
    pub fn statistics(&self) -> ValidatorSetStats {
        let active_count = self.active().len();
        let total_count = self.len();
        let avg_reputation = if total_count > 0 {
            self.validators.values().map(|v| v.reputation).sum::<f64>() / total_count as f64
        } else {
            0.0
        };
        let avg_stake = if total_count > 0 {
            self.total_stake / total_count as u64
        } else {
            0
        };

        ValidatorSetStats {
            total_validators: total_count,
            active_validators: active_count,
            total_stake: self.total_stake,
            average_stake: avg_stake,
            average_reputation: avg_reputation,
        }
    }
}

/// Statistics about the validator set
#[derive(Clone, Debug)]
pub struct ValidatorSetStats {
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_stake: u64,
    pub average_stake: u64,
    pub average_reputation: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator(id: u8, stake: u64) -> Validator {
        let mut validator_id = [0u8; 32];
        validator_id[0] = id;
        Validator::new(validator_id, vec![0u8; 64], [0u8; 32], stake)
    }

    #[test]
    fn test_validator_creation() {
        let v = create_test_validator(1, 1_000_000);
        assert!(v.active);
        assert_eq!(v.stake, 1_000_000);
        assert_eq!(v.reputation, INITIAL_REPUTATION);
    }

    #[test]
    fn test_eligibility() {
        let v = create_test_validator(1, 1_000_000);
        assert!(v.is_eligible(500_000));
        assert!(!v.is_eligible(2_000_000));
    }

    #[test]
    fn test_reputation_updates() {
        let mut v = create_test_validator(1, 1_000_000);
        let initial = v.reputation;

        // Successful attestation increases reputation
        v.update_reputation(true);
        assert!(v.reputation > initial * REPUTATION_DECAY);

        // Failed attestation decreases reputation
        let after_success = v.reputation;
        v.update_reputation(false);
        assert!(v.reputation < after_success * REPUTATION_DECAY);
    }

    #[test]
    fn test_slashing() {
        let mut v = create_test_validator(1, 1_000_000);
        v.slash(100_000, SlashingReason::DoubleAttestation);

        assert_eq!(v.stake, 900_000);
        assert_eq!(v.slashing_events.len(), 1);
        assert!(v.reputation < INITIAL_REPUTATION);
    }

    #[test]
    fn test_validator_set() {
        let mut set = ValidatorSet::new();

        for i in 0..10 {
            set.add(create_test_validator(i, 1_000_000 * (i as u64 + 1)));
        }

        assert_eq!(set.len(), 10);
        assert_eq!(set.total_stake(), 55_000_000); // 1+2+...+10 million

        // Test eligibility
        let eligible = set.eligible(5_000_000);
        assert_eq!(eligible.len(), 6); // Validators 5-10
    }

    #[test]
    fn test_selection_weight() {
        let mut v = create_test_validator(1, 1_000_000);
        let base_weight = v.selection_weight();

        // Increase reputation
        for _ in 0..10 {
            v.update_reputation(true);
        }

        // Weight should increase with reputation
        assert!(v.selection_weight() > base_weight);
    }

    #[test]
    fn test_slash_to_zero() {
        let mut v = create_test_validator(1, 100_000);
        v.slash(200_000, SlashingReason::InvalidAttestation);

        assert_eq!(v.stake, 0);
        assert!(!v.active);
    }
}
