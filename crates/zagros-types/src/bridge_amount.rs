//! 🔢 Köprü tutar ölçeklemesi (ZERENYA 18 ondalık → hedef ERC20). PAXG de 18
//! ondalıklı, dönüşüm fiilen 1:1; fonksiyonlar yine genel. 🚨 PAYLAŞILMIŞ modül:
//! relayer dijeste bu tutarı koyar, düğüm aynı dijesti yeniden hesaplar; iki
//! ayrı kopya dijestleri tutmaz, çıkış yönü sessizce çalışmazdı.

/// ZERENYA'nın zincirdeki ondalık sayısı.
pub const ZERENYA_DECIMALS: u32 = 18;

/// Ölçekleme sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaledAmount {
    /// Hedef ERC20 biriminde ödenecek tutar (aşağı yuvarlanmış).
    pub token_amount: u128,
    /// Aşağı yuvarlamada düşen artık ZERENYA; kullanıcıya ÖDENMEZ, üst sınırı
    /// `10^(18-decimals) - 1` (PAXG için hep 0).
    pub dust: u128,
}

/// ZERENYA ham tutarını hedef ERC20 ondalığına ölçekler. `None`: desteklenmeyen
/// ondalık ya da sonuç 0. 🚨 Sıfır hata sayılır: `claimTokens` `require(_amount > 0)`
/// ile revert eder, kullanıcı gas yakar ve yaktığı ZERENYA'yı geri alamaz; fiş hiç üretilmemeli.
pub fn scale_zerenya_to_token(zerenya_amount: u128, token_decimals: u32) -> Option<ScaledAmount> {
    if token_decimals > ZERENYA_DECIMALS {
        return None;
    }
    let divisor = 10u128.checked_pow(ZERENYA_DECIMALS - token_decimals)?;
    let token_amount = zerenya_amount / divisor;
    if token_amount == 0 {
        return None;
    }
    Some(ScaledAmount {
        token_amount,
        dust: zerenya_amount % divisor,
    })
}

// 📌 KARAR (kalıcı): `dust` kaybı kabul edilmiş davranıştır (PAXG için hep 0).
// Yakma tutarını adıma zorlamak zincir kuralı değişikliği ve UX bedeli ister, tercih edilmedi.

/// Hedef ERC20 tutarını ZERENYA'ya ölçekler (giriş ayağı, tam tersi). Ölçekleme
/// giriş ayağında da tek paylaşılan yerde durmalı. `None`: desteklenmeyen
/// ondalık, tutar 0 ya da taşma (`checked_mul`, sessiz sarma uydurma bakiye üretirdi).
pub fn scale_token_to_zerenya(token_amount: u128, token_decimals: u32) -> Option<u128> {
    if token_decimals > ZERENYA_DECIMALS || token_amount == 0 {
        return None;
    }
    let multiplier = 10u128.checked_pow(ZERENYA_DECIMALS - token_decimals)?;
    token_amount.checked_mul(multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PAXG (18 ondalık), köprünün fiili teminat varlığı: 1 ZERENYA -> 1 PAXG,
    /// ondalıklar eşit olduğundan ölçekleme kimlik (identity) dönüşümüdür, dust yok.
    #[test]
    fn one_zerenya_becomes_one_paxg_with_matching_decimals() {
        let scaled = scale_zerenya_to_token(1_000_000_000_000_000_000, 18).unwrap();
        assert_eq!(scaled.token_amount, 1_000_000_000_000_000_000);
        assert_eq!(scaled.dust, 0);
    }

    #[test]
    fn scaling_is_identity_when_decimals_match() {
        let scaled = scale_zerenya_to_token(12_345, 18).unwrap();
        assert_eq!(scaled.token_amount, 12_345);
        assert_eq!(scaled.dust, 0);
    }

    /// Genel fonksiyon farklı (daha düşük) ondalıklı bir varlık için de doğru
    /// çalışmaya devam etmeli, PAXG dışında bir teminat varlığına geçilirse diye.
    #[test]
    fn indivisible_amounts_round_down_and_report_dust_for_lower_decimal_assets() {
        // 1.5 ZERENYA + 7 ham birim, 6 ondalıklı varsayımsal bir hedef varlığa göre
        let scaled = scale_zerenya_to_token(1_500_000_000_000_000_007, 6).unwrap();
        assert_eq!(scaled.token_amount, 1_500_000);
        assert_eq!(scaled.dust, 7);
    }

    /// 🚨 EN KRİTİK UÇ DURUM: düşük ondalıklı bir hedefte, 1 birimin altındaki
    /// bir yakma 0'a ölçeklenir. Fiş üretilmemeli, üretilseydi `claimTokens`
    /// `require(_amount > 0)` ile revert eder, kullanıcı gas'ını yakar ve
    /// ZERENYA'sını da geri alamazdı.
    #[test]
    fn amounts_below_one_token_unit_are_rejected_instead_of_becoming_zero() {
        assert!(scale_zerenya_to_token(999_999_999_999, 6).is_none());
        assert!(scale_zerenya_to_token(0, 6).is_none());
        // Tam sınır: 1e12 = 1 birim (6 ondalıklı hedefte) -> kabul.
        assert_eq!(
            scale_zerenya_to_token(1_000_000_000_000, 6)
                .unwrap()
                .token_amount,
            1
        );
    }

    #[test]
    fn rejects_token_decimals_above_zerenya() {
        assert!(scale_zerenya_to_token(1_000_000_000_000_000_000, 19).is_none());
    }

    /// 🚨 GİRİŞ AYAĞI: 2 PAXG (18 ondalık) -> 2 ZERENYA (18 ondalık), kimlik dönüşümü.
    #[test]
    fn deposit_scales_token_units_up_to_zerenya() {
        assert_eq!(
            scale_token_to_zerenya(2_000_000_000_000_000_000, 18).unwrap(),
            2_000_000_000_000_000_000
        );
        assert_eq!(
            scale_token_to_zerenya(2_000_000, 6).unwrap(),
            2_000_000_000_000_000_000
        );
        assert_eq!(scale_token_to_zerenya(1, 6).unwrap(), 1_000_000_000_000);
    }

    /// İki yön birbirinin tersi olmalı: tam bölünen tutarlarda gidiş-dönüş
    /// AYNI sayıyı vermeli. Ayrışırlarsa köprü para basar veya yakar.
    #[test]
    fn deposit_and_withdraw_scaling_are_exact_inverses() {
        for token_amount in [1u128, 5, 1_000_000, 3_720_000, 999_999_999] {
            let zerenya = scale_token_to_zerenya(token_amount, 6).unwrap();
            let back = scale_zerenya_to_token(zerenya, 6).unwrap();
            assert_eq!(back.token_amount, token_amount);
            assert_eq!(back.dust, 0);
        }
        // PAXG (18 ondalık) yolunda da aynı özellik kimlik dönüşümüyle geçerli.
        for token_amount in [1u128, 5, 1_000_000_000_000_000_000] {
            let zerenya = scale_token_to_zerenya(token_amount, 18).unwrap();
            let back = scale_zerenya_to_token(zerenya, 18).unwrap();
            assert_eq!(back.token_amount, token_amount);
            assert_eq!(back.dust, 0);
        }
    }

    #[test]
    fn deposit_scaling_rejects_zero_and_bad_decimals() {
        assert!(scale_token_to_zerenya(0, 6).is_none());
        assert!(scale_token_to_zerenya(1_000_000, 19).is_none());
        // Taşma sessizce sarmamalı.
        assert!(scale_token_to_zerenya(u128::MAX, 6).is_none());
    }
}
