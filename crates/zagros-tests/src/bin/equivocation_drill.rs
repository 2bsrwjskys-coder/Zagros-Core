//! 🚨 Tatbikat aracı: verilen konsensüs anahtarıyla aynı (height, round, phase)
//! için iki farklı hash'e geçerli imza atıp `ReportMalicious` payload'ı üretir;
//! ceza zinciri uçtan uca denensin diye. Kanıt sahte değildir, `verify_evidence` kabul eder.
//! ⚠️ Yalnız atılacak test zincirlerinde ve KENDİ anahtarınla.
//! ```text
//! cargo run --release -p zagros-tests --bin equivocation_drill -- \
//!     <keyfile.json> <genesis_hash_hex> <suclanan_adres> <height> [round]
//! ```
use zagros_crypto::{load_keyfile, sign_vote, verify_evidence};
use zagros_types::consensus::{
    ActiveValidatorSet, ConsensusDomain, Evidence, ValidatorMember, Vote, VotePhase,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "kullanim: {} <keyfile.json> <genesis_hash_hex> <suclanan_adres> <height> [round]",
            args[0]
        );
        std::process::exit(2);
    }
    let kp = load_keyfile(&args[1]).expect("keyfile okunamadi");
    let genesis = hex::decode(args[2].trim_start_matches("0x")).expect("genesis hash hex degil");
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&genesis);
    let accused = args[3].to_ascii_lowercase();
    let height: u64 = args[4].parse().expect("height sayi olmali");
    let round: u32 = args
        .get(5)
        .map(|r| r.parse().expect("round sayi olmali"))
        .unwrap_or(0);

    let chain_id: u64 = std::env::var("ZAGROS_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21_072_026);
    let epoch: u64 = std::env::var("ZAGROS_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let idx: u16 = std::env::var("ZAGROS_VALIDATOR_IDX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let domain = ConsensusDomain::new(chain_id, genesis_hash);
    let mk = |hash_byte: u8| {
        let mut v = Vote {
            height,
            round,
            phase: VotePhase::Precommit,
            block_hash: [hash_byte; 32],
            validator_idx: idx,
            shadow: false,
            sig: Vec::new(),
        };
        sign_vote(&kp, &domain, epoch, &mut v);
        v
    };
    let evidence = Evidence::DoubleVote {
        a: mk(0xAA),
        b: mk(0xBB),
    };

    // 🚨 Araç, DOĞRULANMAMIŞ kanıt basmamalı: zincirin kullandığı doğrulayıcının
    // aynısıyla kontrol et. Aksi halde tatbikatta "kanıt üretildi" sanıp
    // aslında reddedilecek bir payload'la ilerlerdik, tam olarak kaçınmaya
    // çalıştığımız "denenmemiş güvenlik makinesi" durumu.
    let set = ActiveValidatorSet {
        epoch,
        members: (0..=idx)
            .map(|i| ValidatorMember {
                address: if i == idx {
                    accused.clone()
                } else {
                    format!("0x{i:040x}")
                },
                consensus_pubkey: if i == idx { kp.public_key() } else { [0u8; 32] },
            })
            .collect(),
    };
    if let Err(e) = verify_evidence(&evidence, &domain, &set) {
        eprintln!("🛑 uretilen kanit DOGRULANAMADI: {e:?}");
        std::process::exit(1);
    }

    let payload = zagros_types::EquivocationReport::ConsensusEvidence(evidence).to_bytes();

    println!("# GERCEK equivocation kaniti uretildi");
    println!("# suclanan   : {accused}");
    println!("# height     : {height}  round: {round}  epoch: {epoch}  validator_idx: {idx}");
    println!("# pubkey     : {}", hex::encode(kp.public_key()));
    println!("receiver={accused}");
    println!("selector=6216e6f0");
    println!("payload_hex={}", hex::encode(&payload));
    println!("calldata=0x6216e6f0{}", hex::encode(&payload));
}
