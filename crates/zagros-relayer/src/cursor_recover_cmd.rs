//! `cursor_recover` ikilisinin test edilebilir çekirdeği; stdin onayı bilerek
//! ikilide (I/O test edilemez, onaysız çağrı istenmez). Cursor gap'te operatör
//! mevcut/hedef imleci ve atlanacak kayıt sayısını görerek kurtarma yapar.
//! ```bash
//! cargo run --release -p zagros-relayer --bin cursor_recover -- show --config relayer.toml
//! ```

use crate::config::RelayerConfig;
use crate::store::RelayerStore;
use std::sync::Arc;
use zagros_storage::rocksdb_impl::RocksDbStorage;

pub struct CursorSnapshot {
    pub outbound_cursor: u128,
    pub inbound_cursor: Option<u64>,
}

/// R6: mevcut/hedef imleç + atlanacak kayıt sayısı, operatöre onaydan ÖNCE
/// göstermek için.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOutboundCursorPlan {
    pub current_cursor: u128,
    pub target_cursor: u128,
    /// `target > current` ise atlanacak kayıt sayısı (bu aralık bir daha
    /// ASLA taranmaz). `target <= current` iken 0, bu durumda atlanan bir
    /// aralık yoktur, tam tersine `is_rewind` true olur.
    pub events_to_skip: u128,
    /// `target < current`, bir "geri sarma": daha önce işlenmiş kayıtlar
    /// YENİDEN taranacak (idempotency katmanları bunu güvenli kılar, ama
    /// gereksiz ağ trafiği/gecikme anlamına gelir). Operatör bunu bilerek
    /// yapıyor olmalı.
    pub is_rewind: bool,
}

/// SAF hesaplama (ağsız/diskssiz), `plan_set_outbound_cursor` testleri
/// gerçek storage açmadan çalışır.
pub fn plan_set_outbound_cursor(current: u128, target: u128) -> SetOutboundCursorPlan {
    SetOutboundCursorPlan {
        current_cursor: current,
        target_cursor: target,
        events_to_skip: target.saturating_sub(current),
        is_rewind: target < current,
    }
}

fn open_store(config_path: &str) -> Result<RelayerStore, String> {
    let config = RelayerConfig::from_file(config_path)
        .map_err(|e| format!("{} okunamadı: {}", config_path, e))?;
    let storage = RocksDbStorage::open(&config.data_dir).map_err(|e| {
        format!(
            "RocksDB açılamadı ({}) - relayer hâlâ çalışıyor olabilir, önce durdurun: {}",
            config.data_dir, e
        )
    })?;
    Ok(RelayerStore::new(Arc::new(storage)))
}

/// `Show` alt-komutu: mevcut outbound/inbound imleçlerini okur, HİÇBİR ŞEY
/// YAZMAZ.
pub fn show(config_path: &str) -> Result<CursorSnapshot, String> {
    let store = open_store(config_path)?;
    let outbound_cursor = store.get_outbound_cursor().map_err(|e| e.to_string())?;
    let inbound_cursor = store.get_inbound_cursor().map_err(|e| e.to_string())?;
    Ok(CursorSnapshot {
        outbound_cursor,
        inbound_cursor,
    })
}

/// `SetOutboundCursor` alt-komutunun ONAY ÖNCESİ adımı: mevcut imleci okuyup
/// planı hesaplar, HİÇBİR ŞEY YAZMAZ, çağıran (binary) bu planı operatöre
/// gösterip onay aldıktan SONRA `write_outbound_cursor`'ı çağırmalı.
pub fn plan_set_outbound_cursor_from_store(
    config_path: &str,
    target: u128,
) -> Result<SetOutboundCursorPlan, String> {
    let store = open_store(config_path)?;
    let current = store.get_outbound_cursor().map_err(|e| e.to_string())?;
    Ok(plan_set_outbound_cursor(current, target))
}

/// Onaydan SONRA çağrılacak, GERÇEKTEN yazan adım, kasıtlı olarak
/// `plan_set_outbound_cursor_from_store`'dan AYRI bir fonksiyon, ki onaysız
/// tek bir çağrıyla yanlışlıkla yazma riski olmasın.
pub fn write_outbound_cursor(config_path: &str, target: u128) -> Result<(), String> {
    let store = open_store(config_path)?;
    store.set_outbound_cursor(target).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_reports_skip_count_when_advancing_forward() {
        let plan = plan_set_outbound_cursor(100, 5_000);
        assert_eq!(plan.current_cursor, 100);
        assert_eq!(plan.target_cursor, 5_000);
        assert_eq!(plan.events_to_skip, 4_900);
        assert!(!plan.is_rewind);
    }

    #[test]
    fn plan_flags_rewind_and_reports_zero_skip_when_target_is_behind_current() {
        let plan = plan_set_outbound_cursor(5_000, 100);
        assert_eq!(plan.events_to_skip, 0);
        assert!(plan.is_rewind);
    }

    #[test]
    fn plan_is_a_noop_when_target_equals_current() {
        let plan = plan_set_outbound_cursor(42, 42);
        assert_eq!(plan.events_to_skip, 0);
        assert!(!plan.is_rewind);
    }

    fn write_test_config(config_path: &std::path::Path, data_dir: &std::path::Path) {
        let mut config = crate::config::sample_config_for_tests();
        config.data_dir = data_dir.to_string_lossy().to_string();
        config.to_file(config_path).unwrap();
    }

    #[test]
    fn show_reports_defaults_before_anything_has_been_persisted() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("relayer.toml");
        write_test_config(&config_path, &root.path().join("data"));

        let snapshot = show(&config_path.to_string_lossy()).unwrap();
        assert_eq!(snapshot.outbound_cursor, 0);
        assert_eq!(snapshot.inbound_cursor, None);
    }

    #[test]
    fn write_outbound_cursor_then_show_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("relayer.toml");
        let config_path_str = config_path.to_string_lossy().to_string();
        write_test_config(&config_path, &root.path().join("data"));

        write_outbound_cursor(&config_path_str, 12_345).unwrap();
        let snapshot = show(&config_path_str).unwrap();
        assert_eq!(snapshot.outbound_cursor, 12_345);
    }

    /// R6'nın asıl kanıtı: `plan_set_outbound_cursor_from_store` mevcut
    /// (persisted) imleci OKUR ama YAZMAZ, ardından `show` ile tekrar
    /// okunduğunda hâlâ eski değer görülür.
    #[test]
    fn plan_from_store_reads_current_cursor_without_writing_anything() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("relayer.toml");
        let config_path_str = config_path.to_string_lossy().to_string();
        write_test_config(&config_path, &root.path().join("data"));
        write_outbound_cursor(&config_path_str, 1_000).unwrap();

        let plan = plan_set_outbound_cursor_from_store(&config_path_str, 9_999).unwrap();
        assert_eq!(plan.current_cursor, 1_000);
        assert_eq!(plan.target_cursor, 9_999);
        assert_eq!(plan.events_to_skip, 8_999);

        // Hâlâ yazılmadı, `show` eski değeri görmeli.
        let snapshot = show(&config_path_str).unwrap();
        assert_eq!(
            snapshot.outbound_cursor, 1_000,
            "plan hesaplama HİÇBİR ŞEY yazmamalı"
        );

        write_outbound_cursor(&config_path_str, plan.target_cursor).unwrap();
        let snapshot_after_write = show(&config_path_str).unwrap();
        assert_eq!(snapshot_after_write.outbound_cursor, 9_999);
    }
}
