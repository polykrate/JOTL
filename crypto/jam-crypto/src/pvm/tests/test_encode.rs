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
