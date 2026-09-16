//! `/zagros/sync/1` için bincode kodlayıcı; libp2p'nin kendi `json::codec`
//! deseniyle aynı (akış elle kapatılmaz, `take(max_size).read_to_end` ile sınırlanır).

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use std::io;

use crate::messages::{Sync2Request, Sync2Response, SyncRequest, SyncResponse};

/// Bozuk/kötü niyetli bir peer'ın sınırsız bir gövde bildirip belleği
/// tüketmesini önlemek için, bir blok-aralığı yanıtının makul üst sınırı
/// (bkz. `sync_batch_size` config alanı, varsayılan 500 blok).
const MAX_SYNC_MESSAGE_SIZE: u64 = 32 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl libp2p::request_response::Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<SyncRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_SYNC_MESSAGE_SIZE).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<SyncResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_SYNC_MESSAGE_SIZE).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: SyncRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes =
            bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: SyncResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes =
            bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await
    }
}

/// G6: `/zagros/sync/2` kodlayıcısı, aynı bincode/size-cap deseni.
#[derive(Clone, Default)]
pub struct Sync2Codec;

#[async_trait]
impl libp2p::request_response::Codec for Sync2Codec {
    type Protocol = StreamProtocol;
    type Request = Sync2Request;
    type Response = Sync2Response;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Sync2Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_SYNC_MESSAGE_SIZE).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Sync2Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_SYNC_MESSAGE_SIZE).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Sync2Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes =
            bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Sync2Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes =
            bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::SyncBlock;
    use libp2p::futures::io::Cursor;
    use libp2p::request_response::Codec as _;
    use zagros_types::{ArchivedBlockHeader, Transaction, TxType};

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/zagros/sync/1")
    }

    fn sample_header(number: u64) -> ArchivedBlockHeader {
        ArchivedBlockHeader {
            number,
            parent_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            timestamp: 1_000,
            tx_hashes: vec![[0xCC; 32]],
        }
    }

    fn sample_transaction() -> Transaction {
        Transaction {
            tx_id: [1u8; 32],
            tx_type: TxType::Transfer,
            sender: "0x0000000000000000000000000000000000000001".to_string(),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: 1,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 1_000,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: 21072026,
        }
    }

    // 🛡️ Kod çözücü peer'dan gelen her bayta karşı ilk savunma hattı: gerçek
    // mesajlar round-trip eder, çöp baytlar panic değil `Err` ile reddedilir.

    #[tokio::test]
    async fn get_status_request_round_trips() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(Vec::new());
        codec
            .write_request(&protocol(), &mut buf, SyncRequest::GetStatus)
            .await
            .unwrap();
        buf.set_position(0);
        let decoded = codec.read_request(&protocol(), &mut buf).await.unwrap();
        assert!(matches!(decoded, SyncRequest::GetStatus));
    }

    #[tokio::test]
    async fn get_block_range_request_round_trips() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(Vec::new());
        let request = SyncRequest::GetBlockRange { from: 5, to: 500 };
        codec
            .write_request(&protocol(), &mut buf, request)
            .await
            .unwrap();
        buf.set_position(0);
        let decoded = codec.read_request(&protocol(), &mut buf).await.unwrap();
        match decoded {
            SyncRequest::GetBlockRange { from, to } => {
                assert_eq!(from, 5);
                assert_eq!(to, 500);
            }
            other => panic!("beklenmeyen varyant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn status_response_round_trips() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(Vec::new());
        codec
            .write_response(
                &protocol(),
                &mut buf,
                SyncResponse::Status { tip_number: 42 },
            )
            .await
            .unwrap();
        buf.set_position(0);
        let decoded = codec.read_response(&protocol(), &mut buf).await.unwrap();
        match decoded {
            SyncResponse::Status { tip_number } => assert_eq!(tip_number, 42),
            other => panic!("beklenmeyen varyant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn not_available_response_round_trips() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(Vec::new());
        codec
            .write_response(&protocol(), &mut buf, SyncResponse::NotAvailable)
            .await
            .unwrap();
        buf.set_position(0);
        let decoded = codec.read_response(&protocol(), &mut buf).await.unwrap();
        assert!(matches!(decoded, SyncResponse::NotAvailable));
    }

    #[tokio::test]
    async fn block_range_response_with_real_blocks_round_trips() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(Vec::new());
        let blocks = vec![
            SyncBlock {
                header: sample_header(1),
                transactions: vec![sample_transaction()],
                bridge_proposals: Vec::new(),
            },
            SyncBlock {
                header: sample_header(2),
                transactions: Vec::new(),
                bridge_proposals: Vec::new(),
            },
        ];
        codec
            .write_response(
                &protocol(),
                &mut buf,
                SyncResponse::BlockRange(blocks.clone()),
            )
            .await
            .unwrap();
        buf.set_position(0);
        let decoded = codec.read_response(&protocol(), &mut buf).await.unwrap();
        match decoded {
            SyncResponse::BlockRange(decoded_blocks) => {
                assert_eq!(decoded_blocks.len(), 2);
                assert_eq!(decoded_blocks[0].header.number, 1);
                assert_eq!(decoded_blocks[0].transactions.len(), 1);
                assert_eq!(decoded_blocks[1].header.number, 2);
                assert!(decoded_blocks[1].transactions.is_empty());
            }
            other => panic!("beklenmeyen varyant: {other:?}"),
        }
    }

    // 🚨 GÜVENLİK: bozuk/kötü niyetli bir peer'ın gönderdiği anlamsız baytlar
    // `bincode::deserialize`'ı BAŞARISIZ etmeli, `map_err` ile düzgün bir
    // `io::Error` dönmeli, ASLA panic/unwrap ile süreci çökertmemeli.
    #[tokio::test]
    async fn garbage_bytes_are_rejected_as_an_error_not_a_panic_on_read_request() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(vec![0xFFu8; 64]);
        let result = codec.read_request(&protocol(), &mut buf).await;
        assert!(
            result.is_err(),
            "çöp baytlar bir Err döndürmeli, panic değil"
        );
    }

    #[tokio::test]
    async fn garbage_bytes_are_rejected_as_an_error_not_a_panic_on_read_response() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(vec![0x00u8; 3]);
        let result = codec.read_response(&protocol(), &mut buf).await;
        assert!(
            result.is_err(),
            "çöp baytlar bir Err döndürmeli, panic değil"
        );
    }

    /// Bir peer bağlantıyı hiç veri göndermeden kapatırsa (`read_to_end` anında
    /// EOF görür, boş bir `Vec` kalır), `bincode::deserialize(&[])` de
    /// düzgün bir `Err` dönmeli, panic değil.
    #[tokio::test]
    async fn empty_stream_is_rejected_as_an_error_not_a_panic() {
        let mut codec = SyncCodec;
        let mut buf = Cursor::new(Vec::<u8>::new());
        let result = codec.read_request(&protocol(), &mut buf).await;
        assert!(result.is_err(), "boş akış bir Err döndürmeli, panic değil");
    }
}
