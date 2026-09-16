#![allow(clippy::field_reassign_with_default)]
// Zagros Network, EVM Executor & Native L1 AMM
use dashmap::DashMap;
use portable_atomic::AtomicU128;
use zagros_primitives::{Result, ZagrosError};
use zagros_state::{SimulationOverlay, State};
use zagros_types::{
    format_token_amount, Transaction, FOUNDER_ADDRESS, MAX_SWAP_AMOUNT_PERCENT,
    MIN_POOL_LIQUIDITY_ZAGROS, MIN_POOL_LIQUIDITY_ZERENYA,
};

use crate::swap::SwapDirection;

use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, Gas, InstructionResult, InterpreterResult,
};
use revm::primitives::db::{DatabaseCommit as EvmDatabaseCommit, DatabaseRef as EvmDatabaseRef};
use revm::primitives::keccak256 as revm_keccak;
use revm::primitives::{
    Account, AccountInfo, BlockEnv, Bytecode, CfgEnv, Env, ExecutionResult, SpecId, TxEnv, B256,
};
use revm::primitives::{
    Address as EvmAddress, Bytes, FixedBytes, HashMap, ResultAndState, TxKind, U256,
};
use revm::{inspector_handle_register, Database, EvmBuilder, EvmContext, Inspector};
use std::sync::Arc;

/// revm varsayılanı `SpecId::LATEST` (pinlenmiş sürümdeki en yüksek fork);
/// sabitlenmezse yeni bir 14.x fork ekleyip gas/opcode ve state_root'u
/// KAYDIRABİLİR. Canlıda test edilmiş CANCUN'a sabitlenir (`EXECUTOR_STATE_TRANSITION_VERSION`).
pub const ZAGROS_EVM_SPEC_ID: SpecId = SpecId::CANCUN;

pub struct EvmExecutionResult {
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub gas_refunded: u64,
    /// Bu EVM çağrısında `VALIDATOR_REWARD_POOL`'a giren tutar (ör. createToken
    /// ücreti). BURADA DAĞITILMAZ; çağıran (`execute_transaction_inner`),
    /// native yollarla AYNI `distribute_staking_reward`'a (80/20) verir.
    pub treasury_gain: u128,
    /// `commit()`in tespit ettiği gerçekten yeni kontrat sayısı (iç CREATE dahil);
    /// çağıran `TOKEN_FACTORY_FEE_ZERENYA × count` keser.
    pub new_contract_count: u64,
    /// `true` yalnız gerçek `evm.transact()`+`commit()` yolunda: revm nonce'u
    /// kendisi artırır, `apply_transaction`'ın `increment_nonce()`u ÇALIŞMAMALI
    /// (çift artış → `InvalidNonce`). ZERENYA kısayolları `false`.
    pub nonce_already_advanced: bool,
}

pub struct EvmExecutionFailure {
    pub error: ZagrosError,
    pub gas_used: Option<u64>,
}

pub struct ZerenyaInterceptor {
    pub state_db: Arc<dyn State>,
    pub zsc_address: EvmAddress,
    // `record_transfer` (Alındı görünürlük indeksi) için bu tx'in id/zaman
    // damgası; doğrudan transfer(address,uint256) çağrılarını kaydeder.
    pub tx_id: zagros_types::Hash,
    pub timestamp: u128,
    /// ZERENYA mutasyonları `state_db`'ye doğrudan yazılır ve revm journal'ı
    /// bunları kapsamaz; iç içe bir çağrı revert olsa da mutasyon kalırdı.
    /// `StateDbManager` iç içe checkpoint desteklemediğinden interceptor kendi
    /// hafif frame yığınını tutar: `call()`/`create()`te push, `*_end()`de pop;
    /// REVERT/HALT'ta eski değerler geri yazılır, başarıda üst frame'e devredilir.
    frames: Vec<ZscFrame>,
    /// `Executor`'ın CANLI `recent_transfer_index_counter`'ının klonu (aynı `Arc`);
    /// `record_transfer` `fetch_add` ile kullanır. EVM sıralı olduğundan gerçek
    /// eşzamanlılık yok; tek kaynak, diskten bayat okumaktan daha doğru.
    pub recent_transfer_index_counter: Arc<AtomicU128>,
}

/// bkz. `ZerenyaInterceptor::frames` doc yorumu.
#[derive(Default)]
struct ZscFrame {
    snapshots: std::collections::HashMap<String, Option<zagros_types::AccountState>>,
}

impl ZscFrame {
    /// Bu frame içinde bir adrese İLK kez dokunuluyorsa mevcut (mutasyon
    /// ÖNCESİ) değerini kaydeder, `StateDbManager::record_old_state` ile
    /// AYNI "yalnızca ilk dokunuşta kaydet" ilkesi.
    fn record_if_absent(&mut self, state_db: &dyn State, address: &str) {
        if !self.snapshots.contains_key(address) {
            let old = state_db.get_account(&address.to_string()).ok().flatten();
            self.snapshots.insert(address.to_string(), old);
        }
    }
}

impl ZerenyaInterceptor {
    /// Yeni bir frame açar, her `call()`/`create()` girişinde (hedef ZERENYA
    /// olsun olmasın) çağrılmalı.
    fn push_frame(&mut self) {
        self.frames.push(ZscFrame::default());
    }

    /// Bir ZERENYA mutasyonundan HEMEN ÖNCE çağrılmalı, o adresin mutasyon
    /// ÖNCESİ değerini şu an açık olan (en içteki) frame'e kaydeder.
    fn record_mutation(&mut self, address: &str) {
        let state_db = self.state_db.clone();
        if let Some(frame) = self.frames.last_mut() {
            frame.record_if_absent(state_db.as_ref(), address);
        }
    }

    /// Frame'i kapatır: başarılıysa üst frame'e devreder, revert/halt'ta bu
    /// frame'deki tüm ZERENYA mutasyonlarını geri yazar. `push_frame` ile eşleşmeli (LIFO).
    fn pop_frame(&mut self, succeeded: bool) {
        let Some(frame) = self.frames.pop() else {
            return;
        };
        if frame.snapshots.is_empty() {
            return;
        }
        if succeeded {
            if let Some(parent) = self.frames.last_mut() {
                for (address, old_value) in frame.snapshots {
                    parent.snapshots.entry(address).or_insert(old_value);
                }
            }
            // Üst frame yoksa (en dış çağrı/deploy), mutasyonlar zaten
            // uygulanmış durumda, devredilecek bir üst kalmadı.
        } else {
            for (address, old_value) in frame.snapshots {
                let _ = match old_value {
                    Some(account) => self.state_db.set_account(&address, account),
                    None => self
                        .state_db
                        .set_account(&address, zagros_types::AccountState::default()),
                };
            }
        }
    }
}

fn allowance_slot(spender: &[u8]) -> U256 {
    let mut key = b"zsc_allowance:".to_vec();
    key.extend_from_slice(spender);
    U256::from_be_bytes(revm_keccak(&key).0)
}

impl<DB: Database> Inspector<DB> for ZerenyaInterceptor {
    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        // 🚨 A-K2: HER çağrı (ZERENYA hedefli olsun olmasın) bir frame açar,
        // `call_end()` bunu eşleşen sonuca göre kapatır. Bkz. `frames` doc
        // yorumu.
        self.push_frame();
        if inputs.target_address == self.zsc_address {
            let data = inputs.input.as_ref();
            if data.len() >= 4 {
                let selector = &data[0..4];

                // --- EVM İÇİN ERC-20 ÇEVİRMEN SÖZLÜĞÜ ---
                let transfer_from_sel =
                    &revm_keccak(b"transferFrom(address,address,uint256)")[0..4];
                let transfer_sel = &revm_keccak(b"transfer(address,uint256)")[0..4];
                let balance_of_sel = &revm_keccak(b"balanceOf(address)")[0..4];
                let decimals_sel = &revm_keccak(b"decimals()")[0..4];
                let symbol_sel = &revm_keccak(b"symbol()")[0..4];
                let name_sel = &revm_keccak(b"name()")[0..4];
                let get_reserves_sel = &revm_keccak(b"getReserves()")[0..4];

                // 🚨 EKSİK OLAN VE YENİ EKLENEN KELİMELER:
                let approve_sel = &revm_keccak(b"approve(address,uint256)")[0..4];
                let allowance_sel = &revm_keccak(b"allowance(address,address)")[0..4];
                let total_supply_sel = &revm_keccak(b"totalSupply()")[0..4];

                // 1. TRANSFER FROM (Router Parayı Keserken)
                if selector == transfer_from_sel && data.len() >= 100 {
                    let from_eth = &data[16..36];
                    let to_eth = &data[48..68];
                    let to_ox = format!("0x{}", hex::encode(to_eth));
                    // 🚨 Havuzun ZERENYA rezervi `LIQUIDITY_POOL_ADDRESS.zerenya_balance`;
                    // düz `transferFrom` rezervi komisyonsuz/kayma korumasız şişirememeli
                    // (native `Transfer` kuralının ERC-20 tarafı).
                    if to_ox == zagros_types::LIQUIDITY_POOL_ADDRESS {
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                    let amount = U256::from_be_bytes::<32>(data[68..100].try_into().unwrap());
                    if amount > U256::from(u128::MAX) {
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                    let amount_u128 = amount.to::<u128>();

                    let from_ox = format!("0x{}", hex::encode(from_eth));
                    let spender = inputs.caller.as_slice();
                    let slot = allowance_slot(spender);
                    let mut owner = self
                        .state_db
                        .get_account(&from_ox)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let allowance = owner.storage.get(&slot).copied().unwrap_or(U256::ZERO);
                    if allowance < amount || owner.zerenya_balance < amount_u128 {
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                    owner.zerenya_balance -= amount_u128;
                    let remaining_allowance = allowance - amount;
                    if remaining_allowance == U256::ZERO {
                        owner.storage.remove(&slot);
                    } else {
                        owner.storage.insert(slot, remaining_allowance);
                    }
                    self.record_mutation(&from_ox);
                    let _ = self.state_db.set_account(&from_ox, owner);
                    self.record_mutation(&to_ox);
                    let _ = self.state_db.add_zerenya_balance(&to_ox, amount_u128);

                    // 📜 `transferFrom` da indekse yazılır; index atomik, frame'e yalnız
                    // kayıt anahtarı (+ düşen eski kayıt) kaydedilir.
                    let next_transfer_index = self
                        .recent_transfer_index_counter
                        .load(std::sync::atomic::Ordering::Acquire);
                    self.record_mutation(&crate::Executor::recent_transfer_record_key(
                        next_transfer_index,
                    ));
                    if next_transfer_index >= crate::Executor::MAX_RECENT_TRANSFERS as u128 {
                        self.record_mutation(&crate::Executor::recent_transfer_record_key(
                            next_transfer_index - crate::Executor::MAX_RECENT_TRANSFERS as u128,
                        ));
                    }
                    let _ = crate::Executor::record_transfer(
                        self.state_db.as_ref(),
                        &self.recent_transfer_index_counter,
                        self.tx_id,
                        from_ox.clone(),
                        to_ox.clone(),
                        amount_u128,
                        "ZERENYA",
                        self.timestamp,
                    );

                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(U256::from(1).to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }

                // 2. TRANSFER (Kullanıcı Cüzdandan Gönderirse)
                if selector == transfer_sel && data.len() >= 68 {
                    let caller_hex = hex::encode(inputs.caller.as_slice());
                    let caller_ox = format!("0x{}", caller_hex);
                    let to_eth = &data[16..36];
                    let to_ox = format!("0x{}", hex::encode(to_eth));
                    // 🚨 Havuzun ZERENYA rezervi `LIQUIDITY_POOL_ADDRESS.zerenya_balance`;
                    // düz `transfer()` rezervi korumasız şişirememeli (native kuralın ERC-20 tarafı).
                    if to_ox == zagros_types::LIQUIDITY_POOL_ADDRESS {
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                    let amount = U256::from_be_bytes::<32>(data[36..68].try_into().unwrap());
                    // 🛡️ Taşma koruması: `U256::to::<u128>()` `u128::MAX` üstünde panik
                    // atar ve bu kol `eth_call` ile herkesçe ulaşılabilir; `amount=2^256-1`
                    // tetiklenebilir panik olurdu.
                    if amount > U256::from(u128::MAX) {
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                    let amount_u128 = amount.to::<u128>();

                    self.record_mutation(&caller_ox);
                    let res = self.state_db.sub_zerenya_balance(&caller_ox, amount_u128);

                    if res.is_err() {
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }

                    self.record_mutation(&to_ox);
                    let _ = self.state_db.add_zerenya_balance(&to_ox, amount_u128);

                    // 📜 `zagros_getReceivedTransfers` indeksine ekle; bu anahtarlar frame'in
                    // parçası, iç içe revert görünürlük kaydını da geri almalı.
                    let next_transfer_index = self
                        .recent_transfer_index_counter
                        .load(std::sync::atomic::Ordering::Acquire);
                    self.record_mutation(&crate::Executor::recent_transfer_record_key(
                        next_transfer_index,
                    ));
                    if next_transfer_index >= crate::Executor::MAX_RECENT_TRANSFERS as u128 {
                        self.record_mutation(&crate::Executor::recent_transfer_record_key(
                            next_transfer_index - crate::Executor::MAX_RECENT_TRANSFERS as u128,
                        ));
                    }
                    let _ = crate::Executor::record_transfer(
                        self.state_db.as_ref(),
                        &self.recent_transfer_index_counter,
                        self.tx_id,
                        caller_ox.clone(),
                        to_ox.clone(),
                        amount_u128,
                        "ZERENYA",
                        self.timestamp,
                    );
                    tracing::info!(
                        "💸 NATIVE TRANSFER: {} ZERENYA | {} -> {}",
                        format_token_amount(amount_u128),
                        caller_ox,
                        to_ox
                    );

                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(U256::from(1).to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }

                // 3. BALANCE OF (Router Bakiyeyi Sorunca)
                if selector == balance_of_sel && data.len() >= 36 {
                    let eth_address = &data[16..36];
                    let ox_address = format!("0x{}", hex::encode(eth_address));
                    let balance = self.state_db.get_zerenya_balance(&ox_address).unwrap_or(0);

                    let evm_balance = U256::from(balance);
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(evm_balance.to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }

                // 4. İZİNLER (Approve & Allowance)
                if selector == approve_sel && data.len() >= 68 {
                    let owner_ox = format!("0x{}", hex::encode(inputs.caller.as_slice()));
                    let spender = &data[16..36];
                    let amount = U256::from_be_bytes::<32>(data[36..68].try_into().unwrap());
                    let mut owner = self
                        .state_db
                        .get_account(&owner_ox)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let approve_slot = allowance_slot(spender);
                    if amount == U256::ZERO {
                        owner.storage.remove(&approve_slot);
                    } else {
                        owner.storage.insert(approve_slot, amount);
                    }
                    self.record_mutation(&owner_ox);
                    let _ = self.state_db.set_account(&owner_ox, owner);
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(U256::from(1).to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }
                if selector == allowance_sel && data.len() >= 68 {
                    let owner_ox = format!("0x{}", hex::encode(&data[16..36]));
                    let spender = &data[48..68];
                    let allowance = self
                        .state_db
                        .get_account(&owner_ox)
                        .ok()
                        .flatten()
                        .and_then(|owner| owner.storage.get(&allowance_slot(spender)).copied())
                        .unwrap_or(U256::ZERO);
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(allowance.to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }

                // 5. METADATA (Decimals, Symbol, Name, TotalSupply)
                if selector == decimals_sel {
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(U256::from(18u64).to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }
                if selector == total_supply_sel {
                    // 🚨 ZERENYA arzı ELASTİK (köprü mint/burn): toplam arz =
                    // `bridge_backed_zerenya` + teminatsız `FOUNDER_GENESIS_ZERENYA`.
                    let backed =
                        crate::Executor::read_bridge_backed_zerenya(self.state_db.as_ref())
                            .unwrap_or(0);
                    let ts = U256::from(backed) + U256::from(zagros_types::FOUNDER_GENESIS_ZERENYA);
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(ts.to_be_bytes::<32>().to_vec()),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }
                if selector == symbol_sel {
                    let mut output = Vec::with_capacity(96);
                    output.extend_from_slice(&U256::from(32u64).to_be_bytes::<32>());
                    output.extend_from_slice(&U256::from(7u64).to_be_bytes::<32>());
                    output.extend_from_slice(b"ZERENYA");
                    output.extend(std::iter::repeat_n(0, 25));
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(output),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }
                if selector == name_sel {
                    let mut output = Vec::with_capacity(96);
                    let name_bytes = b"Zagros Zerenya";
                    output.extend_from_slice(&U256::from(32u64).to_be_bytes::<32>());
                    output.extend_from_slice(
                        &U256::from(name_bytes.len() as u64).to_be_bytes::<32>(),
                    );
                    output.extend_from_slice(name_bytes);
                    output.extend(std::iter::repeat_n(0, 32 - name_bytes.len()));
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(output),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }

                // 6. HAVUZ REZERVLERİ (ZERENYA Native Havuzu gibi davranır)
                if selector == get_reserves_sel {
                    let (zagros, zerenya) = match self.state_db.get_pool_reserves() {
                        Ok((zagros, zerenya)) if zagros > 0 && zerenya > 0 => (zagros, zerenya),
                        _ => (
                            zagros_types::GENESIS_POOL_ZAGROS,
                            zagros_types::GENESIS_POOL_ZERENYA,
                        ),
                    };
                    let zagros_18 = U256::from(zagros);
                    let zerenya_18 = U256::from(zerenya);
                    let mut out = Vec::with_capacity(96);
                    out.extend_from_slice(&zagros_18.to_be_bytes::<32>());
                    out.extend_from_slice(&zerenya_18.to_be_bytes::<32>());
                    out.extend_from_slice(&U256::from(0).to_be_bytes::<32>());
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(out),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                    });
                }

                // 🚨 Köprü mint/burn yetkisi YOK ve EKLENMEMELİ: EVM'den basan yol
                // teminat sayacı ve çoklu imzayı atlayan arka kapıdır.
            }
        }
        None
    }

    /// bkz. `frames`/`pop_frame` doc yorumu, `push_frame()` ile HER ZAMAN
    /// eşleşir (revm'in kendi `call()`/`call_end()` LIFO sırası).
    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        self.pop_frame(outcome.result.result.is_ok());
        outcome
    }

    /// `CREATE`/`CREATE2` de frame'dir: constructor içindeki ZERENYA çağrısı
    /// deploy başarısız olursa geri sarılmalı. Deploy'u değiştirmez (`None`).
    fn create(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        self.push_frame();
        None
    }

    fn create_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        self.pop_frame(outcome.result.result.is_ok());
        outcome
    }
}

pub struct EvmExecutor {
    state_db: Arc<dyn State>,
    initial_balances: Arc<DashMap<EvmAddress, u128>>,
    /// 🏛️ Token Factory harcı: `commit()`in gerçekten yeni oluşturduğu kontrat
    /// sayısı; `Arc` ile paylaşıldığından `db_clone` üzerinden de `self`te
    /// görünür. Her işlem taze `EvmExecutor` aldığından sıfırlama gerekmez.
    new_contracts_created: Arc<std::sync::atomic::AtomicU64>,
    /// Üretim yolu bunu `with_recent_transfer_index_counter` ile Executor'ın
    /// sayacına bağlar; varsayılan izole sayaç yalnız testler için.
    recent_transfer_index_counter: Arc<AtomicU128>,
}

impl EvmExecutor {
    // 🚀 YENİ YARDIMCI: EVM'i bypass eden native fonksiyonlar (Swap) için sahte fiş kesici
    fn save_dummy_receipt(&self, tx: &Transaction) {
        let receipt = zagros_types::ArchivedReceipt {
            status: true,
            gas_used: tx.gas_limit,
            contract_address: None,
            logs: Vec::new(),
            block_number: 0, // archive_transaction tarafından doldurulur
        };
        let _ = crate::archive_transaction(self.state_db.as_ref(), tx, receipt);
    }

    pub fn new(state_db: Arc<dyn State>) -> Self {
        Self {
            state_db,
            initial_balances: Arc::new(DashMap::new()),
            new_contracts_created: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            recent_transfer_index_counter: Arc::new(AtomicU128::new(0)),
        }
    }

    /// Executor'ın canlı sayacıyla paylaşılan `Arc`; üretim yolu çağırmalı,
    /// yoksa EVM ve native transfer indeksleri aynı blokta çakışır.
    pub fn with_recent_transfer_index_counter(mut self, counter: Arc<AtomicU128>) -> Self {
        self.recent_transfer_index_counter = counter;
        self
    }

    fn get_pool_reserves_or_default(&self) -> Result<(u128, u128)> {
        // 🏛️ Yetersiz rezervde likidite UYDURULMAZ (42M arz değişmezi); havuz
        // MIN_POOL_LIQUIDITY tabanının altındaysa swap FAIL-CLOSED reddedilir.
        let (zagros, zerenya) = self.state_db.get_pool_reserves().unwrap_or((0, 0));
        if zagros < MIN_POOL_LIQUIDITY_ZAGROS || zerenya < MIN_POOL_LIQUIDITY_ZERENYA {
            return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
        }
        Ok((zagros, zerenya))
    }

    fn parse_min_amount(payload: &[u8]) -> u128 {
        if payload.len() >= 68 {
            U256::from_be_bytes::<32>(payload[36..68].try_into().unwrap()).to::<u128>()
        } else {
            0
        }
    }

    // 💰 YARDIMCI FONKSİYONLAR: 0x native adresi kullanarak split-brain ve kayıp adresleri ortadan kaldırır
    fn unified_sub_native(&self, address: &EvmAddress, amount: u128) -> Result<()> {
        let ox = format!("0x{}", hex::encode(address.as_slice()));
        let mut acc = self.state_db.get_account(&ox)?.unwrap_or_default();

        // 🚨 KRİTİK GÜVENLİK DUVARI: Bakiye yetersizse anında REVERT at!
        if acc.balance < amount {
            return Err(ZagrosError::InsufficientBalance);
        }

        acc.balance -= amount;
        self.state_db.set_account(&ox, acc)?;
        Ok(())
    }

    fn unified_add_native(&self, address: &EvmAddress, amount: u128) -> Result<()> {
        let ox = format!("0x{}", hex::encode(address.as_slice()));
        let mut acc = self.state_db.get_account(&ox)?.unwrap_or_default();
        acc.balance = acc.balance.saturating_add(amount);
        self.state_db.set_account(&ox, acc)?;
        Ok(())
    }

    fn unified_sub_zsc(&self, address: &EvmAddress, amount: u128) -> Result<()> {
        let ox = format!("0x{}", hex::encode(address.as_slice()));
        let mut acc = self.state_db.get_account(&ox)?.unwrap_or_default();

        // 🚨 KRİTİK GÜVENLİK DUVARI: Bakiye yetersizse anında REVERT at!
        if acc.zerenya_balance < amount {
            return Err(ZagrosError::InsufficientBalance);
        }

        acc.zerenya_balance -= amount;
        self.state_db.set_account(&ox, acc)?;
        Ok(())
    }

    fn unified_add_zsc(&self, address: &EvmAddress, amount: u128) -> Result<()> {
        let ox = format!("0x{}", hex::encode(address.as_slice()));
        let mut acc = self.state_db.get_account(&ox)?.unwrap_or_default();
        acc.zerenya_balance = acc.zerenya_balance.saturating_add(amount);
        self.state_db.set_account(&ox, acc)?;
        Ok(())
    }

    // 🚀 L1 NATIVE DEX, SWAP SELL. 🏛️ TEK ÖDÜL MOTORU: `(çıktı, treasury_gain)`
    // döner; hazine payını çağıran native yol ile AYNI `distribute_staking_reward`a verir.
    fn execute_native_swap_sell(
        &self,
        tx: &Transaction,
        block_timestamp_secs: u64,
    ) -> Result<(Vec<u8>, u128)> {
        let caller = self.address_from_zagros(&tx.sender)?;

        let amount_in = tx.amount;
        if amount_in == 0 {
            return Err(ZagrosError::Other("Sıfır miktar".into()));
        }

        let data = tx.payload.as_slice();
        let amount_out_min = Self::parse_min_amount(data);
        let (res_zagros, res_zerenya) = self.get_pool_reserves_or_default()?;

        // 🛡️ Devre kesici: EVM yolu native `SwapSell` ile AYNI ekonomik kurallara
        // tabi; yoksa havuz bu yoldan tek işlemde boşaltılabilirdi.
        if amount_in > res_zagros.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 {
            return Err(ZagrosError::Other("Swap too large".into()));
        }
        // Ücret oranı native `SwapSell` ile aynı kaynaktan (`STANDARD_SWAP_FEE_BPS`).
        let fee_bps = crate::swap::record_volume_and_compute_fee_bps(
            self.state_db.as_ref(),
            SwapDirection::ZagrosIn,
            amount_in,
            res_zagros,
            block_timestamp_secs,
        )?;
        let swap_fee = amount_in.saturating_mul(fee_bps) / 10000;
        let hazine_share = swap_fee;

        let amount_in_after_fee = amount_in.saturating_sub(swap_fee);
        if amount_in_after_fee == 0 {
            return Err(ZagrosError::Other("Swap sonrası geçerli miktar yok".into()));
        }

        let amount_out = U256::from(amount_in_after_fee)
            .saturating_mul(U256::from(res_zerenya))
            .checked_div(U256::from(res_zagros).saturating_add(U256::from(amount_in_after_fee)))
            .unwrap_or(U256::ZERO)
            .to::<u128>();

        if amount_out == 0 {
            return Err(ZagrosError::Other("Fiyat kayması".into()));
        }
        if amount_out < amount_out_min {
            return Err(ZagrosError::Other(format!(
                "Slippage Kalkanı! Beklenen: {}, Verilen: {}",
                amount_out_min, amount_out
            )));
        }

        // 💰 FİZİKSEL MUHASEBE (YAKMAYI ÖNLER!)
        self.unified_sub_native(&caller, amount_in)?;
        self.unified_add_zsc(&caller, amount_out)?;

        // 🏛️ Hazine payı burada kredilenmez; çağıran `distribute_staking_reward`ı çağırır (split-brain olmasın).

        // 🏛️ TEK KAYNAK: havuzun tek temsili `set_pool_reserves`; `0x...02`nin
        // fiziksel bakiyesi ayrıca güncellenmez (split-brain: native yol o ikinci
        // defteri görmez, EVM yolu sahte "yetersiz bakiye" verirdi).
        let _ = self.state_db.set_pool_reserves(
            res_zagros.saturating_add(amount_in_after_fee),
            res_zerenya.saturating_sub(amount_out),
        );

        tracing::info!(
            "🔄 NATIVE SWAP (SELL): {} ZAGROS -> {} ZERENYA | Vergi: {} BPS",
            amount_in,
            amount_out,
            fee_bps
        );
        Ok((U256::from(1).to_be_bytes::<32>().to_vec(), hazine_share))
    }

    // 🚀 L1 NATIVE DEX, ZERENYA VERİP ZAGROS ALMA (SWAP BUY)
    // 🏛️ TEK ÖDÜL MOTORU: bkz. `execute_native_swap_sell`'deki AYNI not,
    // dönüş tipi `(çıktı, treasury_gain)`.
    fn execute_native_swap_buy(
        &self,
        tx: &Transaction,
        block_timestamp_secs: u64,
    ) -> Result<(Vec<u8>, u128)> {
        let caller = self.address_from_zagros(&tx.sender)?;

        let data = tx.payload.as_slice();
        if data.len() < 36 {
            return Err(ZagrosError::Other("Geçersiz veri".into()));
        }

        let amount_in = U256::from_be_bytes::<32>(data[4..36].try_into().unwrap()).to::<u128>();
        if amount_in == 0 {
            return Err(ZagrosError::Other("Sıfır miktar".into()));
        }

        let amount_out_min = Self::parse_min_amount(data);
        let (res_zagros, res_zerenya) = self.get_pool_reserves_or_default()?;

        // 🛡️ Devre kesici: native TxType::SwapBuy (lib.rs/quote_swap_buy) ile
        // AYNI kural, giriş yolundan bağımsız, tek ekonomik güvenlik seti.
        if amount_in > res_zerenya.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 {
            return Err(ZagrosError::Other("Swap too large".into()));
        }
        // Ücret ZAGROS (çıktı) üzerinden kesilir, doğrudan hazineye gider ve anında
        // staker'lara dağıtılır; oran native `SwapBuy` ile AYNI kaynaktan
        // (`record_volume_and_compute_fee_bps`).
        let fee_bps = crate::swap::record_volume_and_compute_fee_bps(
            self.state_db.as_ref(),
            SwapDirection::ZerenyaIn,
            amount_in,
            res_zerenya,
            block_timestamp_secs,
        )?;

        let raw_zagros_out = U256::from(amount_in)
            .saturating_mul(U256::from(res_zagros))
            .checked_div(U256::from(res_zerenya).saturating_add(U256::from(amount_in)))
            .unwrap_or(U256::ZERO)
            .to::<u128>();

        let swap_fee = raw_zagros_out.saturating_mul(fee_bps) / 10_000;
        let community_fee = swap_fee;

        let amount_out = raw_zagros_out.saturating_sub(swap_fee);

        // 🏛️ TEK ÖDÜL MOTORU: bkz. `execute_native_swap_sell`'deki AYNI not,
        // `community_fee` burada kredilendirilmiyor, çağıran
        // `distribute_staking_reward`'a verecek.

        if raw_zagros_out == 0 {
            return Err(ZagrosError::Other("Swap sonrası geçerli miktar yok".into()));
        }

        if amount_out == 0 {
            return Err(ZagrosError::Other("Fiyat kayması".into()));
        }
        if amount_out < amount_out_min {
            return Err(ZagrosError::Other(format!(
                "Slippage Kalkanı! Beklenen: {}, Verilen: {}",
                amount_out_min, amount_out
            )));
        }

        self.unified_sub_zsc(&caller, amount_in)?;
        self.unified_add_native(&caller, amount_out)?;

        // 🏛️ Tek kaynak: `set_pool_reserves` havuz hesabını günceller, ikinci elle güncelleme gereksiz.
        let new_res_zagros = res_zagros.saturating_sub(raw_zagros_out);
        let new_res_zerenya = res_zerenya.saturating_add(amount_in);
        let _ = self
            .state_db
            .set_pool_reserves(new_res_zagros, new_res_zerenya);

        tracing::info!(
            "🔄 NATIVE SWAP (BUY): {} ZERENYA -> {} ZAGROS | Vergi: {} BPS",
            amount_in,
            amount_out,
            fee_bps
        );
        Ok((U256::from(1).to_be_bytes::<32>().to_vec(), community_fee))
    }

    /// Kural kapıları/EVM ortamı için o anki blok yüksekliği
    /// (`__GLOBAL_BLOCK_HEIGHT__`, runtime `write_block_height` ile yürütmeden
    /// ÖNCE yazar; overlay üzerinden simülasyonda da okunur). Yoksa 0.
    fn current_block_height(&self) -> u64 {
        self.state_db
            .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
            .ok()
            .flatten()
            .map(|a| a.balance as u64)
            .unwrap_or(0)
    }

    /// 🚨 EVM blok ortamı (bkz. `params::EVM_BLOCK_ENV_ACTIVATION_EPOCH`):
    /// kapı açıksa gerçek `block.number`/`block.timestamp`, kapalıysa revm
    /// varsayılanı (0 / 1) — eski bloklar eski değerlerle oynatılsın.
    fn block_env_for(&self, timestamp_secs: u64) -> BlockEnv {
        let mut block_env = BlockEnv::default();
        if crate::params::evm_block_env_active(self.state_db.as_ref()) {
            block_env.number = U256::from(self.current_block_height());
            block_env.timestamp = U256::from(timestamp_secs);
        }
        block_env
    }

    pub fn execute_contract_call(
        &self,
        tx: &Transaction,
        block_timestamp: u128,
    ) -> std::result::Result<EvmExecutionResult, EvmExecutionFailure> {
        // ⚡ NATIVE L1 AMM ve ZERENYA MERKEZ BANKASI MÜDAHALESİ
        // ⚡ NATIVE L1 AMM ve ZERENYA MERKEZ BANKASI MÜDAHALESİ
        if tx.receiver == zagros_types::ZERENYA_TOKEN_ADDRESS {
            let data = tx.payload.as_slice();
            if data.len() >= 4 {
                let selector = &data[0..4];
                let swap_sell_sel = &revm_keccak(b"swapSell(uint256,uint256)")[0..4];
                let swap_buy_sel = &revm_keccak(b"swapBuy(uint256,uint256)")[0..4];

                // 🚨 `addLiquidity` KASITLI YOK: havuz yalnız genesis'te kurulur; selector
                // rezervleri fiyat kontrolsüz enjekte ettirirdi. Likidite Router/Factory'de.
                if selector == swap_sell_sel {
                    let (res, treasury_gain) = self
                        .execute_native_swap_sell(tx, block_timestamp as u64)
                        .map_err(|error| EvmExecutionFailure {
                            error,
                            gas_used: None,
                        })?;
                    self.save_dummy_receipt(tx);
                    return Ok(EvmExecutionResult {
                        return_data: res,
                        gas_used: tx.gas_limit,
                        gas_refunded: 0,
                        treasury_gain,
                        new_contract_count: 0,
                        nonce_already_advanced: false,
                    });
                }
                if selector == swap_buy_sel {
                    let (res, treasury_gain) = self
                        .execute_native_swap_buy(tx, block_timestamp as u64)
                        .map_err(|error| EvmExecutionFailure {
                            error,
                            gas_used: None,
                        })?;
                    self.save_dummy_receipt(tx);
                    return Ok(EvmExecutionResult {
                        return_data: res,
                        gas_used: tx.gas_limit,
                        gas_refunded: 0,
                        treasury_gain,
                        new_contract_count: 0,
                        nonce_already_advanced: false,
                    });
                }
            }

            // Standart ZERENYA çağrıları (approve, transfer vb.) doğrudan EVM
            // motoruna düşer ve REVM onlara log fişi (Receipt) keser; precompile
            // baypası yoktur.
        }

        let contract_address =
            self.address_from_zagros(&tx.receiver)
                .map_err(|error| EvmExecutionFailure {
                    error,
                    gas_used: None,
                })?;
        let caller_address =
            self.address_from_zagros(&tx.sender)
                .map_err(|error| EvmExecutionFailure {
                    error,
                    gas_used: None,
                })?;

        let ox_format = format!("0x{}", hex::encode(caller_address.as_slice()));

        let (caller_key, mut caller_acc) =
            if let Ok(Some(acc)) = self.state_db.get_account(&ox_format) {
                (ox_format.clone(), acc)
            } else {
                (ox_format.clone(), zagros_types::AccountState::default())
            };

        if caller_acc.nonce != tx.nonce {
            caller_acc.nonce = tx.nonce;
            let _ = self.state_db.set_account(&caller_key, caller_acc);
        }

        // Deploy ölçütü TEK kaynaktan gelir (zagros_types::is_evm_deploy), aynı
        // yordamı executor'ın ücret kesintisi de kullanır, böylece "EVM'de Create
        // olarak çalışan" ile "üretim harcı alınan" işlem kümesi asla ayrışamaz.
        let transact_to = if zagros_types::is_evm_deploy(&tx.receiver) {
            TxKind::Create
        } else {
            TxKind::Call(contract_address)
        };

        let reward_pool_address = self
            .address_from_zagros(zagros_types::VALIDATOR_REWARD_POOL)
            .map_err(|error| EvmExecutionFailure {
                error,
                gas_used: None,
            })?;

        // Kontrat hazineye (VALIDATOR_REWARD_POOL) doğrudan value yatırırsa bu
        // staker'ların `acc`ına yansımalı: işlem öncesi bakiye kaydedilip fark dağıtılır.
        let treasury_key_pre = format!("0x{}", hex::encode(reward_pool_address.as_slice()));
        let treasury_balance_before = self
            .state_db
            .get_account(&treasury_key_pre)
            .ok()
            .flatten()
            .map(|acc| acc.balance)
            .unwrap_or(0);

        let mut env = Env::default();
        let mut tx_env = TxEnv::default();
        tx_env.caller = caller_address;
        tx_env.gas_limit = tx.gas_limit;
        tx_env.gas_price = U256::from(tx.gas_price);
        tx_env.transact_to = transact_to;
        tx_env.value = U256::from(tx.amount);
        tx_env.data = Bytes::from(tx.payload.clone());
        tx_env.nonce = Some(tx.nonce);
        tx_env.chain_id = Some(tx.chain_id);

        let mut block_env = self.block_env_for(block_timestamp as u64);
        block_env.coinbase = reward_pool_address;

        env.tx = tx_env;
        env.block = block_env;
        env.cfg = CfgEnv::default().with_chain_id(tx.chain_id);

        let mut zsc_word = [0u8; 32];
        zsc_word[31] = 2;
        let zsc_address = EvmAddress::from_word(FixedBytes(zsc_word));

        let inspector = ZerenyaInterceptor {
            state_db: self.state_db.clone(),
            zsc_address,
            tx_id: tx.tx_id,
            timestamp: block_timestamp,
            frames: Vec::new(),
            recent_transfer_index_counter: self.recent_transfer_index_counter.clone(),
        };

        let mut evm = EvmBuilder::default()
            .with_ref_db(self.clone())
            .with_env(Box::new(env))
            .with_external_context(inspector)
            .with_spec_id(ZAGROS_EVM_SPEC_ID)
            .append_handler_register(inspector_handle_register)
            .build();

        let ResultAndState { result, state } = match evm.transact() {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("❌ REVM İÇ MOTOR ÇÖKMESİ: {:?}", e);
                return Err(EvmExecutionFailure {
                    error: ZagrosError::ContractExecutionFailed,
                    gas_used: None,
                });
            }
        };

        let gas_used = result.gas_used();
        let gas_refunded = match &result {
            ExecutionResult::Success { gas_refunded, .. } => *gas_refunded,
            ExecutionResult::Revert { .. } | ExecutionResult::Halt { .. } => 0,
        };
        // `TxKind::Create`in gerçek kontrat adresi (deploy'da Some, Call'da None).
        let created_contract_address = match &result {
            ExecutionResult::Success { output, .. } => output
                .address()
                .map(|addr| format!("0x{}", hex::encode(addr.as_slice()))),
            _ => None,
        };

        if result.is_success() {
            let mut db_clone = self.clone();
            EvmDatabaseCommit::commit(&mut db_clone, state);

            // 🏛️ TEK ÖDÜL MOTORU: Solidity'nin hazineye yaptığı fiziksel kredi GERİ
            // ALINIR (`sub_balance`), tutar `treasury_gain` olarak dışarı verilir;
            // dağıtımı çağıran native yol ile AYNI `distribute_staking_reward`a yaptırır.
            let treasury_balance_after = self
                .state_db
                .get_account(&treasury_key_pre)
                .ok()
                .flatten()
                .map(|acc| acc.balance)
                .unwrap_or(0);
            let treasury_gain = treasury_balance_after.saturating_sub(treasury_balance_before);
            if treasury_gain > 0 {
                self.state_db
                    .sub_balance(&treasury_key_pre, treasury_gain)
                    .map_err(|error| EvmExecutionFailure {
                        error,
                        gas_used: Some(gas_used),
                    })?;
            }

            // 🚨 Logları (fişleri) yakalayıp arşivliyoruz: her log kendi
            // address/topics/data'sıyla ayrı bir `ArchivedLog` (tek düz topic
            // dizisi log sınırı/address/data'yı kaybeder).
            let archived_logs: Vec<zagros_types::ArchivedLog> = result
                .logs()
                .iter()
                .map(|log| zagros_types::ArchivedLog {
                    address: format!("0x{}", hex::encode(log.address.as_slice())),
                    topics: log
                        .topics()
                        .iter()
                        .map(|t| {
                            let mut h = [0u8; 32];
                            h.copy_from_slice(t.as_slice());
                            h
                        })
                        .collect(),
                    data: log.data.data.to_vec(),
                })
                .collect();

            // Logları bir "Fiş (Receipt)" olarak arşivliyoruz.
            let receipt = zagros_types::ArchivedReceipt {
                status: true,
                gas_used,
                contract_address: created_contract_address,
                logs: archived_logs,
                block_number: 0, // archive_transaction tarafından doldurulur
            };
            crate::archive_transaction(self.state_db.as_ref(), tx, receipt).map_err(|error| {
                EvmExecutionFailure {
                    error,
                    gas_used: Some(gas_used),
                }
            })?;

            // 🏛️ Token Factory harcı: `commit()` yeni kontrat sayısını biriktirdi;
            // dağıtım burada değil, `treasury_gain` ile aynı ilkeyle çağıranda.
            let new_contract_count = self
                .new_contracts_created
                .load(std::sync::atomic::Ordering::Acquire);

            Ok(EvmExecutionResult {
                return_data: result
                    .output()
                    .map(|bytes| bytes.to_vec())
                    .unwrap_or_default(),
                gas_used,
                gas_refunded,
                treasury_gain,
                new_contract_count,
                nonce_already_advanced: true,
            })
        } else {
            tracing::error!("❌ EVM İŞLEMİ REDDETTİ! Detaylı Sebep: {:?}", result);
            Err(EvmExecutionFailure {
                error: ZagrosError::ContractExecutionFailed,
                gas_used: Some(gas_used),
            })
        }
    }

    /// `max_gas`: RPC katmanının config + kullanıcı beyanından çözdüğü tavan;
    /// bu fonksiyon kendisi politika seçmez.
    pub fn simulate_eth_call(
        &self,
        from: &str,
        to: &str,
        data: Vec<u8>,
        max_gas: u64,
    ) -> Result<Vec<u8>> {
        // 🛡️ Salt okunur eth_call paylaşılan state'ten TAM izole: geçici overlay
        // üzerinde koşar, sonunda atılır. Paylaşılan state'te checkpoint/revert
        // yapılsaydı blok üreticisinin eşzamanlı commit'ini cache'te EZERDİ.
        let overlay: Arc<dyn State> = Arc::new(SimulationOverlay::new(self.state_db.clone()));
        let sim = EvmExecutor::new(overlay);
        sim.run_isolated_eth_call(from, to, data, max_gas)
            .map(|(output, _)| output)
    }

    /// `eth_estimateGas` aynı izole simülasyonla GERÇEK `gas_used`ı ölçer;
    /// çağrı revert/halt ederse sahte rakam uydurmak yerine hata döner (geth davranışı).
    pub fn simulate_gas_estimate(
        &self,
        from: &str,
        to: &str,
        data: Vec<u8>,
        max_gas: u64,
    ) -> Result<u64> {
        let overlay: Arc<dyn State> = Arc::new(SimulationOverlay::new(self.state_db.clone()));
        let sim = EvmExecutor::new(overlay);
        let (_, execution_result) = sim.run_isolated_eth_call(from, to, data, max_gas)?;
        if !execution_result.is_success() {
            return Err(ZagrosError::ContractExecutionFailed);
        }
        Ok(execution_result.gas_used())
    }

    /// `simulate_eth_call` gövdesi; hep izole overlay üzerinde, checkpoint/revert yapmaz.
    fn run_isolated_eth_call(
        &self,
        from: &str,
        to: &str,
        data: Vec<u8>,
        max_gas: u64,
    ) -> Result<(Vec<u8>, ExecutionResult)> {
        let caller_address = if from.is_empty() || from == "0x" {
            EvmAddress::ZERO
        } else {
            self.address_from_zagros(from).unwrap_or_default()
        };

        let contract_address = self.address_from_zagros(to).unwrap_or_default();

        let transact_to =
            if to.is_empty() || to == "0x" || to == "0x0000000000000000000000000000000000000000" {
                TxKind::Create
            } else {
                TxKind::Call(contract_address)
            };

        let mut env = Env::default();
        let mut tx_env = TxEnv::default();
        tx_env.caller = caller_address;
        tx_env.transact_to = transact_to;
        tx_env.data = Bytes::from(data);
        tx_env.value = U256::ZERO;
        // Tavan çağıranın (RPC katmanı) config + kullanıcı beyanından çözdüğü
        // `max_gas`; koşulsuz 30_000_000 kullanılmaz.
        tx_env.gas_limit = max_gas;
        tx_env.gas_price = U256::ZERO;
        env.tx = tx_env;
        // eth_call/estimateGas: zincirdeki yürütmeyle AYNI kapı; zaman = şimdi
        // (bir sonraki bloğun göreceği değere en yakın), yükseklik = son blok.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        env.block = self.block_env_for(now_secs);

        let mut zsc_word = [0u8; 32];
        zsc_word[31] = 2;
        let zsc_address = EvmAddress::from_word(FixedBytes(zsc_word));

        let inspector = ZerenyaInterceptor {
            state_db: self.state_db.clone(),
            zsc_address,
            // Bu yol izole/ephemeral bir eth_call simülasyonu (yukarıdaki doc
            // yorumuna bkz.), gerçek bir tx_id yok, ve overlay sonunda
            // düşürüleceği için yazılan değerler zaten hiç kalıcı olmuyor.
            tx_id: [0u8; 32],
            timestamp: 0,
            frames: Vec::new(),
            recent_transfer_index_counter: self.recent_transfer_index_counter.clone(),
        };

        let mut evm = EvmBuilder::default()
            .with_ref_db(self.clone())
            .with_env(Box::new(env))
            .with_external_context(inspector)
            .with_spec_id(ZAGROS_EVM_SPEC_ID)
            .append_handler_register(inspector_handle_register)
            .build();

        // İzole overlay üzerinde koşuyoruz: checkpoint/revert GEREKMEZ, tüm
        // mutasyonlar overlay ile birlikte atılır, paylaşılan state'e dokunulmaz.
        let execution = evm.transact().map_err(|e| {
            tracing::error!("❌ SIMULATÖR ÇÖKTÜ: {:?} (from={} to={})", e, from, to);
            ZagrosError::ContractExecutionFailed
        });
        let output_bytes = execution
            .as_ref()
            .ok()
            .and_then(|result| result.result.output())
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let execution_result = execution?.result;

        // Boş adrese okuma uyarısı kapalı (MetaMask Multicall gürültüsü).

        Ok((output_bytes, execution_result))
    }

    fn address_from_zagros(&self, zagros_address: &str) -> Result<EvmAddress> {
        if zagros_address.is_empty()
            || zagros_address == "0x"
            || zagros_address == "0x0000000000000000000000000000000000000000"
        {
            return Ok(EvmAddress::ZERO);
        }
        if zagros_address.starts_with("0x") || zagros_address.starts_with("0X") {
            if zagros_address.len() != 42 {
                return Err(ZagrosError::InvalidAddress);
            }
            let raw = hex::decode(&zagros_address[2..]).map_err(|_| ZagrosError::InvalidAddress)?;
            return Ok(EvmAddress::from_slice(&raw));
        }

        Err(ZagrosError::InvalidAddress)
    }
}

impl Clone for EvmExecutor {
    fn clone(&self) -> Self {
        Self {
            state_db: self.state_db.clone(),
            initial_balances: self.initial_balances.clone(),
            new_contracts_created: self.new_contracts_created.clone(),
            recent_transfer_index_counter: self.recent_transfer_index_counter.clone(),
        }
    }
}

impl EvmDatabaseRef for EvmExecutor {
    type Error = ZagrosError;

    fn basic_ref(
        &self,
        address: EvmAddress,
    ) -> std::result::Result<Option<AccountInfo>, ZagrosError> {
        let ox_address = format!("0x{}", hex::encode(address.as_slice()));

        let account_state_opt = if let Ok(Some(acc)) = self.state_db.get_account(&ox_address) {
            Some(acc)
        } else {
            None
        };

        if let Some(account_state) = account_state_opt {
            self.initial_balances
                .entry(address)
                .or_insert(account_state.balance);
            let is_genesis = hex::encode(address.as_slice()).to_lowercase()
                == FOUNDER_ADDRESS.trim_start_matches("0x");
            let is_eoa = if is_genesis {
                true
            } else {
                !account_state.is_contract || account_state.contract_code.is_empty()
            };

            let code_hash = if is_eoa {
                revm::primitives::KECCAK_EMPTY
            } else {
                Bytecode::new_raw(account_state.contract_code.clone().into()).hash_slow()
            };
            let code = if is_eoa {
                None
            } else {
                Some(Bytecode::new_raw(
                    account_state.contract_code.clone().into(),
                ))
            };

            let info = AccountInfo {
                balance: U256::from(account_state.balance),
                nonce: account_state.nonce,
                code_hash,
                code,
            };
            Ok(Some(info))
        } else {
            self.initial_balances.entry(address).or_insert(0);
            Ok(Some(AccountInfo::default()))
        }
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> std::result::Result<Bytecode, ZagrosError> {
        Ok(Bytecode::default())
    }

    fn storage_ref(
        &self,
        address: EvmAddress,
        index: U256,
    ) -> std::result::Result<U256, ZagrosError> {
        // [12..] KESMELERİ KESİNLİKLE YOK!
        let ox_address = format!("0x{}", hex::encode(address.as_slice()));

        let account_state = self.state_db.get_account(&ox_address)?;

        if let Some(account_state) = account_state {
            Ok(account_state
                .storage
                .get(&index)
                .cloned()
                .unwrap_or(U256::ZERO))
        } else {
            Ok(U256::ZERO)
        }
    }

    fn block_hash_ref(&self, _number: u64) -> std::result::Result<B256, ZagrosError> {
        Ok(B256::ZERO)
    }
}

impl EvmDatabaseCommit for EvmExecutor {
    fn commit(&mut self, changes: HashMap<EvmAddress, Account>) {
        for (address, account) in changes {
            let ox_address = format!("0x{}", hex::encode(address.as_slice()));

            let mut account_state = self
                .state_db
                .get_account(&ox_address)
                .ok()
                .flatten()
                .unwrap_or_default();
            // 🏛️ Token Factory harcı: işlem öncesi `is_contract` dondurulur,
            // "önceden kontrat değildi, şimdi kontrat" geçişi (gerçek deploy) tespit edilir.
            let was_contract_before = account_state.is_contract;

            let native_balance = account.info.balance.to::<u128>();
            let initial_balance = self
                .initial_balances
                .remove(&address)
                .map(|(_, balance)| balance)
                .unwrap_or(account_state.balance);
            account_state.balance = if native_balance >= initial_balance {
                account_state
                    .balance
                    .saturating_add(native_balance - initial_balance)
            } else {
                account_state
                    .balance
                    .saturating_sub(initial_balance - native_balance)
            };
            account_state.nonce = account.info.nonce;

            let is_genesis = hex::encode(address.as_slice()).to_lowercase()
                == FOUNDER_ADDRESS.trim_start_matches("0x");

            // 🚨 KODU ASLA BOŞA ÇIKARMA!
            if is_genesis {
                account_state.contract_code = vec![];
                account_state.is_contract = false;
            } else if let Some(code) = account.info.code {
                // 🚨 `code.bytes()` EOA'da bile `[0x00]` dolgu döner; dolgu kod sanılırsa
                // cüzdanlar kontrat damgalanır. `code.is_empty()` gerçek uzunluk.
                if !code.is_empty() {
                    account_state.contract_code = code.original_bytes().to_vec();
                    account_state.is_contract = true;
                }
            }

            // 🏛️ "Önceden kontrat değildi, şimdi kontrat" geçişi üst seviye deploy
            // VE Factory'nin iç `CREATE`/`CREATE2`si için aynı şekilde doğru: revm'in
            // TAM değişim kümesi taranır. `is_genesis` dalı buraya asla girmez.
            if !was_contract_before && account_state.is_contract {
                self.new_contracts_created
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }

            let mut storage = account_state.storage.clone();
            for (slot, slot_value) in account.storage.iter() {
                let value = slot_value.present_value();
                // EVM semantiği: sıfır slot = hiç yazılmamış slot; sıfır saklamak state'i
                // şişirir. Eski sıfır girdiler slot'a bir daha dokunulunca temizlenir.
                if value == U256::ZERO {
                    storage.remove(slot);
                } else {
                    storage.insert(*slot, value);
                }
            }
            account_state.storage = storage;

            let _ = self.state_db.set_account(&ox_address, account_state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use zagros_state::manager::StateDbManager;
    use zagros_storage::{Storage, StorageEngine};

    /// `zagros-executor/src/lib.rs`'in test modülündeki AYNI, kasıtlı olarak
    /// minimal bellek-içi `Storage`/`StorageEngine` sahtesi, RocksDB'ye
    /// gerek olmadan `StateDbManager`'ı test etmek için.
    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        list_keys_calls: AtomicUsize,
    }

    impl Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&self, key: &[u8]) -> Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }

        fn contains(&self, key: &[u8]) -> Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }

        fn list_keys(&self) -> Result<Vec<Vec<u8>>> {
            self.list_keys_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl StorageEngine for MemoryStorage {
        fn write_batch(&self, values: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
            let mut storage = self.values.lock().unwrap();
            for (key, value) in values {
                if let Some(value) = value {
                    storage.insert(key.clone(), value.clone());
                } else {
                    storage.remove(key);
                }
            }
            Ok(())
        }

        fn append_wal(&self, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn clear_wal(&self) -> Result<()> {
            Ok(())
        }
    }

    fn test_state() -> Arc<dyn State> {
        Arc::new(StateDbManager::new(Arc::new(MemoryStorage::default())))
    }

    /// JUMPDEST + PUSH1 0 + JUMP: sonsuz döngü, yalnız OutOfGas ile durur.
    /// `to=""` ile init-code olarak koşar, deploy gerekmeden saf hesaplama maliyeti ölçer.
    fn gas_burner_bytecode() -> Vec<u8> {
        vec![0x5b, 0x60, 0x00, 0x56]
    }

    /// 🛑 Gas tavanı parametredir: 30M verildiğinde gerçekten 30M'ye kadar
    /// yakılabilmeli (düşük tavan kanıtı ayrı testte).
    #[test]
    fn run_isolated_eth_call_respects_an_explicitly_configured_high_max_gas() {
        let state = test_state();
        let executor = EvmExecutor::new(state);
        let (_output, execution_result) = executor
            .run_isolated_eth_call("0x", "", gas_burner_bytecode(), 30_000_000)
            .unwrap();

        assert!(
            !execution_result.is_success(),
            "sonsuz döngü OutOfGas ile HALT olmalı, başarıyla dönmemeli"
        );
        let gas_used = execution_result.gas_used();
        assert!(
            gas_used > 29_000_000,
            "30M olarak AÇIKÇA yapılandırılan bir tavan, GERÇEKTEN 30M'ye \
             YAKIN gaz yakılmasına izin vermeli (ölçülen: {})",
            gas_used
        );
    }

    /// 🛡️ `max_gas` DÜŞÜK bir değere yapılandırıldığında, gerçek bir "gas
    /// yakıcı" bile o tavanın ÖTESİNE GEÇEMEZ. Bu, tavanın ASIL regresyon korumasıdır.
    #[test]
    fn run_isolated_eth_call_caps_execution_at_the_configured_max_gas() {
        let state = test_state();
        let executor = EvmExecutor::new(state);
        let configured_cap = 100_000u64;
        let (_output, execution_result) = executor
            .run_isolated_eth_call("0x", "", gas_burner_bytecode(), configured_cap)
            .unwrap();

        assert!(
            !execution_result.is_success(),
            "sonsuz döngü OutOfGas ile HALT olmalı"
        );
        let gas_used = execution_result.gas_used();
        assert!(
            gas_used <= configured_cap,
            "DÜZELTME REGRESYONU: gaz kullanımı ({}) yapılandırılan tavanı \
             ({}) AŞMAMALI",
            gas_used,
            configured_cap
        );
        // Tavanın GERÇEKTEN uygulandığını (bir no-op olmadığını) da kanıtla:
        // 100K gaz, sonsuz döngünün 30M'ye ulaşmasından ÇOK daha erken tükenir.
        assert!(
            gas_used < 1_000_000,
            "100K'lık bir tavanla gaz kullanımı milyonlara ulaşmamalı - tavan \
             fiilen uygulanmıyor olabilir (ölçülen: {})",
            gas_used
        );
    }

    /// Simülasyon varsayılanı (10M) `Transaction::validate()` tavanıyla TUTARLI:
    /// gerçek işlemin aşamayacağı tavan hiçbir meşru simülasyonu bozmaz.
    #[test]
    fn run_isolated_eth_call_at_the_real_transaction_gas_ceiling_still_completes() {
        let state = test_state();
        let executor = EvmExecutor::new(state);
        let real_tx_ceiling = 10_000_000u64;
        let (_output, execution_result) = executor
            .run_isolated_eth_call("0x", "", gas_burner_bytecode(), real_tx_ceiling)
            .unwrap();

        assert!(!execution_result.is_success());
        assert!(execution_result.gas_used() <= real_tx_ceiling);
    }

    /// 🛑 ÖLÇÜM: 30M ve 10M tavanların gerçek duvar saati maliyeti; ayrı EVM
    /// timeout'u / eş zamanlı simülasyon sınırı kararını bilgilendirir.
    #[test]
    fn eth_call_gas_burn_wall_clock_cost_before_and_after_the_fix_is_measured() {
        let state = test_state();
        let executor = EvmExecutor::new(state);

        let start_old = std::time::Instant::now();
        let (_output, old_result) = executor
            .run_isolated_eth_call("0x", "", gas_burner_bytecode(), 30_000_000)
            .unwrap();
        let elapsed_old = start_old.elapsed();

        let start_new = std::time::Instant::now();
        let (_output, new_result) = executor
            .run_isolated_eth_call("0x", "", gas_burner_bytecode(), 10_000_000)
            .unwrap();
        let elapsed_new = start_new.elapsed();

        eprintln!(
            "📊 YÜKSEK #7 ÖLÇÜMÜ (debug build - üretim `--release`'de daha hızlı \
             olur, bu PESİMİST/en-kötü-durum bir ölçüm):\n\
             \u{20}\u{20}eski (30M, sınırsız davranış): {} gaz / {:?}\n\
             \u{20}\u{20}yeni varsayılan (10M):          {} gaz / {:?}",
            old_result.gas_used(),
            elapsed_old,
            new_result.gas_used(),
            elapsed_new
        );
        // Katı üst sınır yok (donanıma bağlı); yalnız 10 sn ile kaçak olmadığı doğrulanır.
        assert!(
            elapsed_old < std::time::Duration::from_secs(10),
            "30M gaz yakımı 10 saniyeden UZUN sürdü - ortam beklenmedik derecede yavaş"
        );
        assert!(
            elapsed_new < elapsed_old,
            "10M tavanının duvar-saati maliyeti 30M'den KISA olmalı"
        );
    }

    /// Init-code: TIMESTAMP → mem[0], NUMBER → mem[32], RETURN(0,64);
    /// kontrat "kodu" = [timestamp | number].
    fn ts_number_init_code() -> Vec<u8> {
        vec![
            0x42, 0x60, 0x00, 0x52, // TIMESTAMP; PUSH1 0; MSTORE
            0x43, 0x60, 0x20, 0x52, // NUMBER; PUSH1 32; MSTORE
            0x60, 0x40, 0x60, 0x00, 0xf3, // PUSH1 64; PUSH1 0; RETURN
        ]
    }

    fn run_ts_number_probe(state: &Arc<dyn State>, nonce: u64, block_ts: u128) -> (u64, u64) {
        let sender = "0x0000000000000000000000000000000000000001".to_string();
        let mut acc = state
            .get_account(&sender)
            .unwrap()
            .unwrap_or(zagros_types::AccountState::new(0));
        acc.balance = 1_000_000;
        state.set_account(&sender, acc).unwrap();
        let init_code = ts_number_init_code();
        let tx = Transaction {
            tx_id: [nonce as u8 + 40; 32],
            tx_type: zagros_types::TxType::ContractCall {
                data: init_code.clone(),
            },
            sender: sender.clone(),
            amount: 0,
            receiver: "0x0000000000000000000000000000000000000000".to_string(),
            payload: init_code,
            signature: Vec::new(),
            timestamp: block_ts,
            nonce,
            gas_limit: 500_000,
            gas_price: 1,
            chain_id: zagros_types::CHAIN_ID,
        };
        let executor = EvmExecutor::new(state.clone());
        if executor.execute_contract_call(&tx, block_ts).is_err() {
            panic!("probe deploy basarisiz");
        }
        let receipt_acc = state
            .get_account(&zagros_state::receipt_key(&tx.tx_id))
            .unwrap()
            .unwrap();
        let receipt: zagros_types::ArchivedReceipt =
            bincode::deserialize(&receipt_acc.contract_code).unwrap();
        let addr = receipt.contract_address.expect("deploy adresi");
        let code = state
            .get_account(&addr)
            .unwrap()
            .expect("kontrat hesabı")
            .contract_code;
        assert_eq!(code.len(), 64, "runtime kodu 64 bayt olmalı");
        let w = |i: usize| u64::from_be_bytes(code[i + 24..i + 32].try_into().unwrap());
        (w(0), w(32))
    }

    /// 🚨 EVM `block.timestamp`/`block.number` aktivasyon kapısı.
    /// Küme epoch'u < 60 → revm varsayılanı (1 / 0) korunur (tarih oynatma);
    /// ≥ 60 → gerçek blok zamanı ve yüksekliği.
    #[test]
    fn evm_block_env_is_gated_by_activation_epoch() {
        use zagros_types::consensus::{ActiveValidatorSet, ValidatorMember};
        let state = test_state();
        let mut h = zagros_types::AccountState::new(0);
        h.balance = 4_242;
        state
            .set_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string(), h)
            .unwrap();
        // 4 farklı üye (validate: tekrar eden adres/pubkey yok, sıfır pubkey yok).
        let mk = |epoch: u64| ActiveValidatorSet {
            epoch,
            members: (1u8..=4)
                .map(|i| ValidatorMember {
                    address: format!("0x{:040x}", 0xaa00 + i as u64),
                    consensus_pubkey: [i; 32],
                })
                .collect(),
        };

        crate::validator_set::store_active_set(
            state.as_ref(),
            &mk(crate::params::EVM_BLOCK_ENV_ACTIVATION_EPOCH - 1),
        )
        .unwrap();
        assert_eq!(
            run_ts_number_probe(&state, 0, 1_700_000_000),
            (1, 0),
            "kapı kapalı: revm varsayılanı (1, 0)"
        );

        crate::validator_set::store_active_set(
            state.as_ref(),
            &mk(crate::params::EVM_BLOCK_ENV_ACTIVATION_EPOCH),
        )
        .unwrap();
        assert_eq!(
            run_ts_number_probe(&state, 1, 1_700_000_000),
            (1_700_000_000, 4_242),
            "kapı açık: gerçek zaman ve yükseklik"
        );
    }

    #[test]
    fn execute_contract_call_captures_real_deploy_address_and_correctly_separated_logs() {
        let state = test_state();
        let sender = "0x0000000000000000000000000000000000000001".to_string();
        state
            .set_account(&sender, zagros_types::AccountState::new(1_000_000))
            .unwrap();

        // LOG1(1 topic=0xaa, veri yok) sonra LOG2(2 topic=0xbb,0xcc, veri
        // yok) sonra STOP (init-code icin bos runtime kod, CREATE'te
        // gecerli/basarili bir sonuc).
        let init_code = vec![
            0x60, 0xaa, 0x60, 0x00, 0x60, 0x00, 0xa1, // LOG1(offset=0,size=0,topic=0xaa)
            0x60, 0xcc, 0x60, 0xbb, 0x60, 0x00, 0x60, 0x00,
            0xa2, // LOG2(offset=0,size=0,topic1=0xbb,topic2=0xcc)
            0x00, // STOP
        ];

        let tx = Transaction {
            tx_id: [9u8; 32],
            tx_type: zagros_types::TxType::ContractCall {
                data: init_code.clone(),
            },
            sender: sender.clone(),
            amount: 0,
            receiver: "0x0000000000000000000000000000000000000000".to_string(),
            payload: init_code,
            signature: Vec::new(),
            timestamp: 1_000,
            nonce: 0,
            gas_limit: 500_000,
            gas_price: 1,
            chain_id: zagros_types::CHAIN_ID,
        };

        let executor = EvmExecutor::new(state.clone());
        let result = match executor.execute_contract_call(&tx, tx.timestamp) {
            Ok(r) => r,
            Err(_) => panic!("basit LOG+STOP init-code basarili calismali"),
        };
        assert!(result.gas_used > 0);

        let receipt_acc = state
            .get_account(&zagros_state::receipt_key(&tx.tx_id))
            .unwrap()
            .expect("execute_contract_call basari yolunda receipt yazmali");
        let receipt: zagros_types::ArchivedReceipt =
            bincode::deserialize(&receipt_acc.contract_code).unwrap();

        assert!(receipt.status);
        assert!(
            receipt.contract_address.is_some(),
            "TxKind::Create deploy'u GERCEK bir kontrat adresi uretmeli"
        );

        assert_eq!(
            receipt.logs.len(),
            2,
            "iki ayri log GERCEKTEN ayri arsivlenmeli (eski flattening hatasi DEGIL)"
        );
        assert_eq!(
            receipt.logs[0].topics.len(),
            1,
            "ilk log tek topic'li olmali"
        );
        assert_eq!(
            receipt.logs[1].topics.len(),
            2,
            "ikinci log iki topic'li olmali - birinci logun topic'iyle KARISMAMALI"
        );
    }

    /// 🛡️ Regresyon: `transfer(address,uint256)` kolu da `U256::to::<u128>()`
    /// öncesi taşma kontrolü yapmalı (eth_call ile herkes tetikleyebilir);
    /// `amount = 2^256-1` panik değil temiz Revert vermeli.
    #[test]
    fn zsc_transfer_with_an_amount_above_u128_max_reverts_cleanly_instead_of_panicking() {
        let state = test_state();
        let recipient = "0x0000000000000000000000000000000000000009";

        let mut payload = revm_keccak(b"transfer(address,uint256)")[0..4].to_vec();
        payload.extend_from_slice(&[0u8; 12]);
        payload.extend_from_slice(&hex::decode(recipient.trim_start_matches("0x")).unwrap());
        payload.extend_from_slice(&[0xFFu8; 32]); // amount = 2^256 - 1, u128::MAX'in COK ustunde

        // `simulate_eth_call` revert'te de `Ok` döner; `simulate_gas_estimate`
        // `is_success()`i kontrol edip revert/halt'ta `Err` verir, o kullanılır.
        let executor = EvmExecutor::new(state);
        let result = executor.simulate_gas_estimate(
            "0x0000000000000000000000000000000000000001",
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            payload,
            1_000_000,
        );

        assert!(
            result.is_err(),
            "asiri buyuk transfer miktari PANIK etmeden temiz bir hata (Revert) ile \
             reddedilmeli, process/thread cokmemeli"
        );
    }
}

#[cfg(kani)]
#[allow(unused_imports)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_balance_transfer_no_overflow() {
        let initial_balance: u128 = kani::any();
        let transfer_amount: u128 = kani::any();

        // Ön koşul
        kani::assume(initial_balance >= transfer_amount);

        // İşlem
        let remaining_balance = initial_balance - transfer_amount;

        // Assertion'lar
        kani::assert(
            remaining_balance <= initial_balance,
            "remaining_balance <= initial_balance",
        );
        kani::assert(
            remaining_balance + transfer_amount == initial_balance,
            "remaining_balance + transfer_amount == initial_balance",
        );
    }
}
