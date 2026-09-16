use serde::{Deserialize, Serialize};
use thiserror::Error;

// TEMEL BLOCKCHAIN ALFABESİ (PRIMITIVES)
pub type Hash = [u8; 32];
pub type Address = String;
pub type Signature = Vec<u8>;
pub type BlockNumber = u64;
pub type Nonce = u64;
pub type Balance = u128;

// EVRENSEL HATA YÖNETİMİ
#[derive(Debug, Clone, Serialize, Deserialize, Error)]
pub enum ZagrosError {
    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Transaction expired")]
    TransactionExpired,

    #[error("Gas limit exceeded")]
    GasLimitExceeded,

    #[error("Contract execution failed")]
    ContractExecutionFailed,

    #[error("Account not found")]
    AccountNotFound,

    #[error("Mempool is full")]
    MempoolFull,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Staking error: {0}")]
    StakingError(String),

    #[error("Bridge error: {0}")]
    BridgeError(String),

    #[error("Reentrancy attack detected")]
    Reentrancy,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("P2P error: {0}")]
    P2pError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Insufficient balance for gas")]
    InsufficientBalanceForGas,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ZagrosError>;
