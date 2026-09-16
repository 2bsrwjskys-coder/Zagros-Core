// Zagros tarafı izleyici: `zagros_getRecentBridgeBurns`ü imleçle artımlı tarar
// (event-log sistemi yok). Saf ayrıştırma + imleç mantığı, ağsız test edilebilir.

use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnRecord {
    pub index: u128,
    pub tx_id_hex: String,
    pub sender: String,
    pub amount: u128,
}

/// 🛡️ İmleç sunucunun en eski kaydından geride kalınca FAIL-CLOSED hata: aradaki
/// burn'ler budanmıştır, sessizce atlamak yerine durup alarm/yeniden senkron.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorGapError {
    /// Relayer'ın talep ettiği imleç.
    pub requested_since_index: u128,
    /// Sunucunun saklı EN ESKİ index'i (bunun altındaki kayıtlar budandı).
    pub oldest_available_index: u128,
}

impl fmt::Display for CursorGapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bridge-burn cursor gap: requested since_index {} but oldest available is {} - \
             {} record(s) were trimmed and are unrecoverable; relayer must re-sync (do NOT skip)",
            self.requested_since_index,
            self.oldest_available_index,
            self.oldest_available_index
                .saturating_sub(self.requested_since_index)
        )
    }
}

impl std::error::Error for CursorGapError {}

/// 🛡️ Cursor gap tespiti (saf): `since_index < oldest_index` ise aradaki
/// kayıtlar budanmıştır → `Err(CursorGapError)`; aksi halde `Ok(())`.
pub fn detect_cursor_gap(
    since_index: u128,
    oldest_index: Option<u128>,
) -> Result<(), CursorGapError> {
    if let Some(oldest) = oldest_index {
        if since_index < oldest {
            return Err(CursorGapError {
                requested_since_index: since_index,
                oldest_available_index: oldest,
            });
        }
    }
    Ok(())
}

/// 🛡️ `zagros_getRecentBridgeBurns` yanıtını fail-closed ayrıştırır: önce
/// `oldest_index` ile gap kontrolü, gap varsa kayıt döndürmeden hata.
pub fn parse_burns_response(
    value: &Value,
    since_index: u128,
) -> Result<Vec<BurnRecord>, CursorGapError> {
    let oldest_index = value
        .get("oldest_index")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    detect_cursor_gap(since_index, oldest_index)?;

    let records = value
        .get("burns")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_burn_record).collect())
        .unwrap_or_default();
    Ok(records)
}

/// Tek JSON girdisini ayrıştırır; alan eksikliğinde panic yerine `None`.
pub fn parse_burn_record(value: &Value) -> Option<BurnRecord> {
    Some(BurnRecord {
        index: value.get("index")?.as_str()?.parse().ok()?,
        tx_id_hex: value.get("tx_id")?.as_str()?.to_string(),
        sender: value.get("sender")?.as_str()?.to_string(),
        amount: value.get("amount")?.as_str()?.parse().ok()?,
    })
}

/// Bir tarama turundan sonra bir sonraki `since_index`'i hesaplar, alınan
/// kayıtların en yükseği + 1 (kayıt yoksa imleç değişmez).
pub fn next_cursor(current: u128, records: &[BurnRecord]) -> u128 {
    records
        .iter()
        .map(|r| r.index + 1)
        .max()
        .unwrap_or(current)
        .max(current)
}

/// Başarısız index'lerden güvenli sonraki imleci hesaplar: başarısızlık yoksa
/// `next_cursor`; varsa EN KÜÇÜK başarısız index (index+1 değil, tekrar denensin).
/// `handle_new_burn` idempotent olduğundan sonraki kayıtlar no-op tekrar görülür.
pub fn next_cursor_after_partial_failure(
    current: u128,
    records: &[BurnRecord],
    failed_indices: &[u128],
) -> u128 {
    match failed_indices.iter().copied().min() {
        Some(failed_at) => failed_at.max(current),
        None => next_cursor(current, records),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_well_formed_burn_record() {
        let value = json!({
            "index": "3",
            "tx_id": "0xabc",
            "sender": "0x0000000000000000000000000000000000000001",
            "amount": "1500000000000000000",
            "timestamp": "1700000000",
        });
        let record = parse_burn_record(&value).unwrap();
        assert_eq!(record.index, 3);
        assert_eq!(record.amount, 1_500_000_000_000_000_000);
    }

    #[test]
    fn returns_none_when_a_field_is_missing() {
        let value = json!({ "index": "3", "tx_id": "0xabc" });
        assert!(parse_burn_record(&value).is_none());
    }

    #[test]
    fn cursor_advances_past_the_highest_seen_index() {
        let records = vec![
            BurnRecord {
                index: 5,
                tx_id_hex: "0x1".into(),
                sender: "0x1".into(),
                amount: 1,
            },
            BurnRecord {
                index: 7,
                tx_id_hex: "0x2".into(),
                sender: "0x2".into(),
                amount: 1,
            },
        ];
        assert_eq!(next_cursor(0, &records), 8);
    }

    #[test]
    fn cursor_never_goes_backwards_when_no_new_records() {
        assert_eq!(next_cursor(10, &[]), 10);
    }

    // ---- F-outbound-cursor-safe-advance: kısmi başarısızlık ----

    fn burn_record(index: u128) -> BurnRecord {
        BurnRecord {
            index,
            tx_id_hex: format!("0x{index}"),
            sender: "0x1".into(),
            amount: 1,
        }
    }

    #[test]
    fn next_cursor_after_partial_failure_stops_at_the_first_failed_record() {
        // 100 başarılı, 101 handle_new_burn'de hata verdi, 102 başarılı.
        let records = vec![burn_record(100), burn_record(101), burn_record(102)];
        let next = next_cursor_after_partial_failure(0, &records, &[101]);
        assert_eq!(
            next, 101,
            "cursor 101'i geçmemeli - başarısız kayıt bir dahaki turda tekrar denenmeli"
        );
    }

    #[test]
    fn next_cursor_after_partial_failure_ignores_out_of_order_failures() {
        // Başarısızlık listesi sırasız/karışık gelse bile en küçük index esas alınır.
        let records = vec![
            burn_record(100),
            burn_record(101),
            burn_record(102),
            burn_record(103),
        ];
        let next = next_cursor_after_partial_failure(0, &records, &[103, 101]);
        assert_eq!(next, 101);
    }

    #[test]
    fn next_cursor_after_partial_failure_matches_next_cursor_when_nothing_failed() {
        let records = vec![burn_record(5), burn_record(6)];
        assert_eq!(
            next_cursor_after_partial_failure(0, &records, &[]),
            next_cursor(0, &records)
        );
    }

    #[test]
    fn next_cursor_after_partial_failure_never_retreats_below_current() {
        // Teorik olarak bile olsa, başarısız index mevcut cursor'ın altında
        // gelirse (olmamalı ama savunmacı) imleç geri gitmemeli.
        let records = vec![burn_record(50)];
        assert_eq!(next_cursor_after_partial_failure(60, &records, &[50]), 60);
    }

    // ---- 🛡️ [7]: cursor gap tespiti ----

    #[test]
    fn no_gap_when_cursor_is_at_or_ahead_of_oldest() {
        // Tam sırada.
        assert!(detect_cursor_gap(5, Some(5)).is_ok());
        // Relayer ileride (istediği index saklı en eskiden büyük).
        assert!(detect_cursor_gap(9, Some(5)).is_ok());
        // Hiç kayıt yok → boşluk yok.
        assert!(detect_cursor_gap(7, None).is_ok());
        // İlk taramada (since_index 0), oldest 0.
        assert!(detect_cursor_gap(0, Some(0)).is_ok());
    }

    #[test]
    fn gap_detected_when_cursor_is_behind_oldest() {
        // Relayer 3'ten itibaren istiyor ama sunucunun en eskisi 8 → 3,4,5,6,7 budandı.
        let err = detect_cursor_gap(3, Some(8)).unwrap_err();
        assert_eq!(err.requested_since_index, 3);
        assert_eq!(err.oldest_available_index, 8);
    }

    #[test]
    fn parse_burns_response_fails_closed_on_gap_and_does_not_return_records() {
        // Sunucu budama sonrası en eski index'i 100 diyor ama biz 10'dan istedik.
        let value = json!({
            "burns": [
                { "index": "100", "tx_id": "0xaa", "sender": "0x1", "amount": "1", "timestamp": "1" }
            ],
            "oldest_index": "100",
        });
        let result = parse_burns_response(&value, 10);
        assert!(
            result.is_err(),
            "must fail closed instead of silently skipping trimmed burns"
        );
    }

    #[test]
    fn parse_burns_response_returns_records_when_no_gap() {
        let value = json!({
            "burns": [
                { "index": "5", "tx_id": "0xaa", "sender": "0x1", "amount": "2", "timestamp": "1" },
                { "index": "6", "tx_id": "0xbb", "sender": "0x2", "amount": "3", "timestamp": "1" }
            ],
            "oldest_index": "5",
        });
        let records = parse_burns_response(&value, 5).expect("no gap");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].index, 5);
        assert_eq!(records[1].index, 6);
    }

    #[test]
    fn parse_burns_response_ok_when_oldest_index_is_null_empty_list() {
        // Hiç burn yok: oldest_index null → boşluk yok, boş liste döner.
        let value = json!({ "burns": [], "oldest_index": null });
        let records = parse_burns_response(&value, 0).expect("empty is not a gap");
        assert!(records.is_empty());
    }
}
