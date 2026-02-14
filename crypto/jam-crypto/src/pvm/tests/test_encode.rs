use super::*;
use jam_codec::Decode;

#[test]
fn test_accumulate_item_roundtrip() {
    let record = WorkItemRecord {
        package: WorkPackageHash([1u8; 32]),
        exports_root: SegmentTreeRoot([2u8; 32]),
        authorizer_hash: AuthorizerHash([3u8; 32]),
        payload: PayloadHash([4u8; 32]),
        gas_limit: 1000,
        result: Ok(WorkOutput(vec![0xaa, 0xbb, 0xcc])),
        auth_output: AuthTrace(vec![0xdd, 0xee]),
    };

    let item = AccumulateItem::WorkItem(record);
    let encoded = item.encode();

    let decoded = AccumulateItem::decode(&mut &encoded[..]);
    assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded.err());

    // Vec round-trip
    let record2 = WorkItemRecord {
        package: WorkPackageHash([1u8; 32]),
        exports_root: SegmentTreeRoot([2u8; 32]),
        authorizer_hash: AuthorizerHash([3u8; 32]),
        payload: PayloadHash([4u8; 32]),
        gas_limit: 1000,
        result: Ok(WorkOutput(vec![0xaa, 0xbb, 0xcc])),
        auth_output: AuthTrace(vec![0xdd, 0xee]),
    };
    let items = vec![AccumulateItem::WorkItem(record2)];
    let encoded_vec = items.encode();
    let decoded_vec = Vec::<AccumulateItem>::decode(&mut &encoded_vec[..]);
    assert!(decoded_vec.is_ok(), "Failed to decode Vec: {:?}", decoded_vec.err());
}

#[test]
fn test_real_accumulate_item() {
    let record = WorkItemRecord {
        package: WorkPackageHash([0xcd, 0x49, 0xf9, 0x88, 0xa7, 0x08, 0x33, 0x3a,
                                  0x27, 0x70, 0x49, 0x7a, 0x37, 0x78, 0x16, 0x98,
                                  0x89, 0x24, 0xd8, 0xb8, 0x76, 0x1d, 0x2e, 0x90,
                                  0x75, 0xdf, 0x8a, 0x59, 0x27, 0xae, 0x7f, 0x00]),
        exports_root: SegmentTreeRoot([0u8; 32]),
        authorizer_hash: AuthorizerHash([0u8; 32]),
        payload: PayloadHash([0u8; 32]),
        gas_limit: 10_000_000,
        result: Ok(WorkOutput(vec![0xaa; 132])),
        auth_output: AuthTrace(vec![0xbb; 7]),
    };

    let item = AccumulateItem::WorkItem(record);
    let encoded = item.encode();
    let decoded = AccumulateItem::decode(&mut &encoded[..]);
    assert!(decoded.is_ok(), "Decode failed: {:?}", decoded.err());

    // Vec round-trip
    let record2 = WorkItemRecord {
        package: WorkPackageHash([0xcd; 32]),
        exports_root: SegmentTreeRoot([0u8; 32]),
        authorizer_hash: AuthorizerHash([0u8; 32]),
        payload: PayloadHash([0u8; 32]),
        gas_limit: 10_000_000,
        result: Ok(WorkOutput(vec![0xaa; 132])),
        auth_output: AuthTrace(vec![0xbb; 7]),
    };
    let items = vec![AccumulateItem::WorkItem(record2)];
    let encoded_vec = items.encode();
    let decoded_vec = Vec::<AccumulateItem>::decode(&mut &encoded_vec[..]);
    assert!(decoded_vec.is_ok(), "Vec decode failed: {:?}", decoded_vec.err());
}

/// Verify compact encoding of count prefix and decode the actual block 38 blob.
#[test]
fn test_compact_count_encoding() {
    use jam_codec::Compact;

    // Check what Compact(5u32) encodes to
    let mut buf = Vec::new();
    Compact(5u32).encode_to(&mut buf);
    println!("Compact(5u32) encodes to: {:02x?} (len={})", buf, buf.len());

    // Check gas_limit encoding
    let mut buf2 = Vec::new();
    Compact(2_000_000u64).encode_to(&mut buf2);
    println!("Compact(2000000u64) encodes to: {:02x?} (len={})", buf2, buf2.len());

    // Also check what Vec<AccumulateItem> uses for the count prefix
    let record = WorkItemRecord {
        package: WorkPackageHash([1u8; 32]),
        exports_root: SegmentTreeRoot([2u8; 32]),
        authorizer_hash: AuthorizerHash([3u8; 32]),
        payload: PayloadHash([4u8; 32]),
        gas_limit: 1000,
        result: Ok(WorkOutput(vec![0xaa])),
        auth_output: AuthTrace(vec![]),
    };
    let items = vec![AccumulateItem::WorkItem(record)];
    let encoded = items.encode();
    println!("Vec<AccumulateItem> (1 item) first bytes: {:02x?}", &encoded[..std::cmp::min(10, encoded.len())]);
    println!("  First byte (count prefix): 0x{:02x} = {}", encoded[0], encoded[0]);

    // Compare with our manual encoding
    let mut manual = Vec::new();
    Compact(1u32).encode_to(&mut manual);
    println!("Compact(1u32) encodes to: {:02x?}", manual);
    assert_eq!(encoded[0], manual[0], "Vec encoding and manual Compact should match");
}

/// Decode the ACTUAL AccumulateItems blob from block 38.
/// The dump file uses SCALE compact prefix (0x14); the Rust blob uses JAM compact (0x05).
/// We replace the first byte and decode using jam-types.
#[test]
fn test_decode_actual_block38_blob() {
    use jam_codec::Decode;

    // Read the hex dump file — it uses SCALE compact prefix 0x14 for count=5.
    // The actual PVM blob uses JAM compact 0x05 for count=5.
    let hex_str = "1400974172158A3F133F96B01C616894217E42A40AFAB262F810E91F00725B4AC54B00000000000000000000000000000000000000000000000000000000000000002357426F2313559A271D6782DC00197B379F79CBE3C6A1E72F61F7B592C509F811C2EF9B9844089324DFA6750F273C588B8486D786A3A043E374A72A4FF31B89DE8084008084011600042F3E6FA9BEADE7B65E9AC413B96D8B720493C35CA984CF7B6E2151D16213FF1EA06E698D52E508FD4EC877F65411FB5CE0E03C89F4ACB87D42581B5F7FA760692D3878BF730E52FC9323E26ECFAB467F714CB402365A1F6DDEB90E47C7BCA2A65ECB7FB55B883FCA5207EBD3C5F522105DE03CEBA063035896EDA97274C412930000974172158A3F133F96B01C616894217E42A40AFAB262F810E91F00725B4AC54B00000000000000000000000000000000000000000000000000000000000000002357426F2313559A271D6782DC00197B379F79CBE3C6A1E72F61F7B592C509F85447EB62D1F015D5D0D475333CD304006BCF5163E437374F11007CC3866F79A4DE808400808701050420CF372F985FBC735CFC201CF8787330470F51B65A0F06D31EFE431AB8DAEC77F82099A654CFCD351FCEE90356EBF00CCBBFF6DBF7200C558BD9C308D4DF43CE9FE52097C41F0FA4A974E7ED4A9BF1F4952C3F58882B6692E568E35C6341CD60ECE61820717F7119404AE6347E13EA28241C45405020C12EC92EF87CD265F85D92F469B40000974172158A3F133F96B01C616894217E42A40AFAB262F810E91F00725B4AC54B00000000000000000000000000000000000000000000000000000000000000002357426F2313559A271D6782DC00197B379F79CBE3C6A1E72F61F7B592C509F8BC566DC343F67141BA51C563D336B0341E6416BF24C7F1141A883ABF517AAF2DDE8084006401160003AE509663529E793D4972AC64C1EC9AE5726AC00E4F8FF531EC77FD67A75AD70E645337402141253BC2B3E6AB8E02525CA1B129F0D6636C36437C75C8FB8CAD96BDDDD29B4A45B1BC6EEA95D28C044A30679DD408B1A3C4FDFAB54A5F214C746F0000974172158A3F133F96B01C616894217E42A40AFAB262F810E91F00725B4AC54B00000000000000000000000000000000000000000000000000000000000000002357426F2313559A271D6782DC00197B379F79CBE3C6A1E72F61F7B592C509F8EFD8889D19DB42FFEDD6B803151234B4879A123DD7A4FE443733944FA980FBDDDE80840080C901050620DD08F7B56F7A8777276233D447ACE2BF4548A33A1F7205638E618B191DCB332520AE509663529E793D4972AC64C1EC9AE5726AC00E4F8FF531EC77FD67A75AD70E203C461D7DA031DB480C94190FA11B48129B67643CAD534BA0EBC53DCE640008EA206259889A0D6B251C9CDC3415345A7ED1D7C879BB943601D6D10327C8B6645A3A20A1E0D9702CC04CAA7ABE401D06DEF5BD15F986E9BE21561D7A9F95A288640AE920CF372F985FBC735CFC201CF8787330470F51B65A0F06D31EFE431AB8DAEC77F80000974172158A3F133F96B01C616894217E42A40AFAB262F810E91F00725B4AC54B00000000000000000000000000000000000000000000000000000000000000002357426F2313559A271D6782DC00197B379F79CBE3C6A1E72F61F7B592C509F8C1383B0A9350CE96DFB1882A55B50E0FB22BCDF0441A0FC5E593432AA9050A25DE808400814D01050A20B6A5A3544432987988F01C64D75F33DAEF1D022DDE1CD1AB49930F0A01DF6C5A2097C41F0FA4A974E7ED4A9BF1F4952C3F58882B6692E568E35C6341CD60ECE618203C461D7DA031DB480C94190FA11B48129B67643CAD534BA0EBC53DCE640008EA2099A654CFCD351FCEE90356EBF00CCBBFF6DBF7200C558BD9C308D4DF43CE9FE52064FFA7D0B1560BF0ED4B6227191E6E478E82BB23C87C8A568C4177C244E232C820BB87245B820E5DA9E7C1B3652A763E85DDDBDAF36BCA6FC0D5A8ABCF2A5272062021C62EEE5565E6B7438C73AF16E3C1152C10C2ACAB7BBC923D9648DA402DEAC220CE38DF79D1184F1D65E4458C54DEC2021826F85012AEEFDF5558ECB43582B2D72048A1EAA9020A7E014F2D1D8AD814A31AF888FEC6F3853681B3E0FFEC624A160220AE509663529E793D4972AC64C1EC9AE5726AC00E4F8FF531EC77FD67A75AD70E00";

    let mut bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i+2], 16).unwrap())
        .collect();

    println!("Dump file blob: {} bytes, first byte: 0x{:02x}", bytes.len(), bytes[0]);

    // Fix: replace SCALE compact prefix (0x14) with JAM compact prefix (0x05)
    assert_eq!(bytes[0], 0x14, "Expected SCALE compact prefix 0x14");
    bytes[0] = 0x05;  // JAM compact for 5

    println!("Fixed blob: {} bytes, first byte: 0x{:02x}", bytes.len(), bytes[0]);

    // Attempt to decode
    let decoded = Vec::<AccumulateItem>::decode(&mut &bytes[..]);
    match &decoded {
        Ok(items) => {
            println!("\n✅ Successfully decoded {} items", items.len());
            for (i, item) in items.iter().enumerate() {
                match item {
                    AccumulateItem::WorkItem(r) => {
                        let result_len = r.result.as_ref().map(|o| o.0.len()).unwrap_or(0);
                        let is_err = r.result.is_err();
                        println!("  [{}] WorkItem gas={} payload={:02x?}.. result={} auth={}",
                            i, r.gas_limit,
                            &r.payload.0[..4],
                            if is_err { format!("Err") } else { format!("Ok({} bytes)", result_len) },
                            r.auth_output.0.len());
                    }
                    AccumulateItem::Transfer(t) => {
                        println!("  [{}] Transfer src={} dst={} amt={} gas={}",
                            i, t.source, t.destination, t.amount, t.gas_limit);
                    }
                }
            }
        }
        Err(e) => {
            println!("\n❌ Decode FAILED: {:?}", e);
            println!("Blob around failure point:");
            // Try to decode items one by one to find the problematic item
            let mut cursor = &bytes[1..]; // skip count byte
            for i in 0..5 {
                let before_len = cursor.len();
                match AccumulateItem::decode(&mut cursor) {
                    Ok(item) => {
                        let consumed = before_len - cursor.len();
                        match &item {
                            AccumulateItem::WorkItem(r) => {
                                println!("  [{}] OK: {} bytes consumed, gas={}", i, consumed, r.gas_limit);
                            }
                            AccumulateItem::Transfer(t) => {
                                println!("  [{}] OK: {} bytes consumed, transfer", i, consumed);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  [{}] FAILED at remaining {} bytes: {:?}", i, cursor.len(), e);
                        println!("  Bytes at failure: {:02x?}", &cursor[..20.min(cursor.len())]);
                        break;
                    }
                }
            }
        }
    }

    let items = decoded.expect("Must decode all 5 items");
    assert_eq!(items.len(), 5, "Expected 5 items, got {}", items.len());

    // CRITICAL: verify our encode_accumulate_items_list produces identical blob
    // to Vec<AccumulateItem>::encode()
    let re_encoded = items.encode();
    if re_encoded == bytes {
        println!("\n✅ Our blob exactly matches Vec<AccumulateItem>::encode() roundtrip");
    } else {
        println!("\n❌ MISMATCH: our blob differs from Vec<AccumulateItem>::encode()");
        println!("  Our blob: {} bytes, Re-encoded: {} bytes", bytes.len(), re_encoded.len());
        for (i, (a, b)) in bytes.iter().zip(re_encoded.iter()).enumerate() {
            if a != b {
                println!("  First difference at byte {}: ours=0x{:02x} theirs=0x{:02x}", i, a, b);
                break;
            }
        }
    }

    // Also compare our manual encode_accumulate_items_list with Vec::encode
    let item_blobs: Vec<Vec<u8>> = items.iter().map(|item| item.encode()).collect();
    let manual_blob = super::super::host_calls::encode_accumulate_items_list(&item_blobs);
    if manual_blob == re_encoded {
        println!("✅ encode_accumulate_items_list == Vec::encode (identical)");
    } else {
        println!("❌ encode_accumulate_items_list != Vec::encode");
        println!("  Manual: {} bytes, Vec::encode: {} bytes", manual_blob.len(), re_encoded.len());
        for (i, (a, b)) in manual_blob.iter().zip(re_encoded.iter()).enumerate() {
            if a != b {
                println!("  First diff at byte {}: manual=0x{:02x} vec=0x{:02x}", i, a, b);
                break;
            }
        }
    }
}
