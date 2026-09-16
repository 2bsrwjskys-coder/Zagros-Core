//! 🛠️ Manuel cursor kurtarma aracı: `auto_recover_cursor_gap=false` iken cursor
//! gap'te relayer imleci ilerletmez, operatör bu araçla bilinçli kurtarma yapar.
//! ```bash
//! # ÖNCE relayer'ı durdurun (RocksDB tek yazar).
//! cargo run --release -p zagros-relayer --bin cursor_recover -- show --config relayer.toml
//! cargo run --release -p zagros-relayer --bin cursor_recover -- \
//!     set-outbound-cursor --cursor 12345 --config relayer.toml
//! ```
//! `set-outbound-cursor` yazmadan önce `y/N` onayı ister (`--yes` atlar).

use std::io::Write;
use zagros_relayer::cursor_recover_cmd;

#[derive(clap::Parser)]
#[command(
    name = "cursor_recover",
    about = "Zagros relayer cursor kurtarma aracı"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// `relayer.toml` yolu, kalıcı depoya (idempotency/cursor) buradan erişilir.
    #[arg(long, default_value = "relayer.toml", global = true)]
    config: String,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Mevcut outbound + inbound imleçlerini gösterir. HİÇBİR ŞEY YAZMAZ.
    Show,
    /// Outbound (Zagros burn tarama) imlecini elle belirtilen değere ayarlar.
    /// `CursorGapError` sonrası fail-closed kilitlenmeyi manuel çözmek için.
    SetOutboundCursor {
        #[arg(long)]
        cursor: u128,
        /// Onay isteme adımını atla (örn. otomasyon/scripting), VARSAYILAN
        /// KAPALI: interaktif y/N istemi olmadan yazma yapılmaz.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

fn main() {
    use clap::Parser;
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Show => show(&cli.config),
        Command::SetOutboundCursor { cursor, yes } => set_outbound_cursor(&cli.config, cursor, yes),
    };

    if let Err(e) = result {
        eprintln!("🛑 {}", e);
        std::process::exit(1);
    }
}

fn show(config_path: &str) -> Result<(), String> {
    let snapshot = cursor_recover_cmd::show(config_path)?;
    println!(
        "Outbound cursor (Zagros burn tarama) : {}",
        snapshot.outbound_cursor
    );
    match snapshot.inbound_cursor {
        Some(c) => println!("Inbound cursor (Ethereum event tarama): {}", c),
        None => println!("Inbound cursor (Ethereum event tarama): (henüz hiç taranmadı)"),
    }
    Ok(())
}

fn set_outbound_cursor(
    config_path: &str,
    target: u128,
    skip_confirmation: bool,
) -> Result<(), String> {
    let plan = cursor_recover_cmd::plan_set_outbound_cursor_from_store(config_path, target)?;

    println!("Mevcut outbound cursor : {}", plan.current_cursor);
    println!("Hedef outbound cursor  : {}", plan.target_cursor);
    if plan.is_rewind {
        println!(
            "⚠️  GERİ SARMA: hedef mevcut imleçten KÜÇÜK - önceden işlenmiş burn'ler YENİDEN \
             taranacak (idempotency katmanı çift-işlemeyi engeller, ama gereksiz gecikmeye \
             yol açar)."
        );
    } else if plan.events_to_skip > 0 {
        println!(
            "🚨 {} kayıt KALICI OLARAK ATLANACAK - bu aralıktaki burn'ler bu relayer \
             tarafından bir daha ASLA görülmeyecek. Yedekli relayer'ların bu aralığı \
             kapsadığından emin olun.",
            plan.events_to_skip
        );
    } else {
        println!("Değişiklik yok (hedef mevcut imleçle aynı).");
    }

    if !skip_confirmation {
        print!("\nDevam edilsin mi? Bu işlem GERİ ALINAMAZ. [y/N]: ");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| e.to_string())?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("İptal edildi - hiçbir şey yazılmadı.");
            return Ok(());
        }
    }

    cursor_recover_cmd::write_outbound_cursor(config_path, target)?;
    println!(
        "✅ Outbound cursor {} olarak kalıcı hale getirildi.",
        target
    );
    Ok(())
}
