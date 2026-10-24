//! Property-based testing for HQFBP reassembly invariants under packet reordering and duplication.

use proptest::prelude::*;
use std::time::Duration;

use hardy_hqfbp_cla::{ContentEncoding, RxSessionManager};
use hqfbp_rs::generator::PDUGenerator;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_reassembly_under_chunk_reordering(
        payload in proptest::collection::vec(any::<u8>(), 32..2048),
        chunk_size in 32usize..128usize,
    ) {
        let encodings = vec![
            ContentEncoding::Chunk(chunk_size),
            ContentEncoding::H,
            ContentEncoding::Crc32,
        ];
        let mut pdu_generator = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            Some("CQ".to_string()),
            Some(encodings),
            None,
            1,
        );

        let pdus = pdu_generator.generate(&payload, None).expect("generation succeeds");
        prop_assert!(!pdus.is_empty());

        let mut rx_manager = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));

        // Deliver chunks in reverse order to test reordering tolerance
        for pdu in pdus.iter().rev() {
            let res = rx_manager.process_pdu(pdu);
            prop_assert!(res.is_ok());
        }

        let completed = rx_manager.drain_completed_messages();
        prop_assert_eq!(completed.len(), 1);
        prop_assert_eq!(completed[0].payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn prop_reassembly_under_chunk_duplication(
        payload in proptest::collection::vec(any::<u8>(), 32..1024),
        chunk_size in 32usize..128usize,
    ) {
        let encodings = vec![
            ContentEncoding::Chunk(chunk_size),
            ContentEncoding::H,
            ContentEncoding::Crc32,
        ];
        let mut pdu_generator = PDUGenerator::new(
            Some("ON4KST".to_string()),
            None,
            Some(encodings),
            None,
            42,
        );

        let pdus = pdu_generator.generate(&payload, None).expect("generation succeeds");

        let mut rx_manager = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));

        // Deliver every chunk twice
        for pdu in &pdus {
            rx_manager.process_pdu(pdu).expect("first delivery succeeds");
            rx_manager.process_pdu(pdu).expect("duplicate delivery is idempotent");
        }

        let completed = rx_manager.drain_completed_messages();
        prop_assert_eq!(completed.len(), 1);
        prop_assert_eq!(completed[0].payload.as_ref(), payload.as_slice());
    }
}
