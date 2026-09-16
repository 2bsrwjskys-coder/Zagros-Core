//! G13: dondurulmuş `zagros-data/state`ten replay_guard dosyası üretir (private
//! zincir durdurulduktan sonra). Kullanım: replay_guard_export <state-dizini> [cikti];
//! dosya mainnet config'inde `[genesis] replay_guard_file` olarak gösterilir.
use zagros_cli::replay_guard;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(state_dir) = args.next() else {
        eprintln!("Kullanım: replay_guard_export <state-dizini> [cikti-dosyasi]");
        std::process::exit(2);
    };
    let entries = match replay_guard::export_from_state_dir(&state_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("HATA: {e:?}");
            std::process::exit(1);
        }
    };
    let text = replay_guard::to_file_format(&entries);
    match args.next() {
        Some(out) => {
            if let Err(e) = std::fs::write(&out, &text) {
                eprintln!("HATA: {out} yazilamadi: {e}");
                std::process::exit(1);
            }
            eprintln!(
                "✅ {} adres → {}",
                (entries.nonces.len() + entries.processed_sources.len()),
                out
            );
        }
        None => print!("{text}"),
    }
}
