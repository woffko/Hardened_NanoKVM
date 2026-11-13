use super::*;

#[test]
fn the_startup_plan_codec_round_trips_managed_assets() {
    let record = super::super::super::tests::record(7, Phase::Accepted);
    let plan = Plan {
        config: Zeroizing::new(b"{}".to_vec()),
        security: Zeroizing::new(b"".to_vec()),
        internal: Zeroizing::new("synthetic-internal-value".into()),
        internal_new: false,
        pair_write: false,
        assets: vec![Asset {
            path: "skills/kvm-control/SKILL.md".into(),
            before: Some(asset_digest(b"old skill")),
            desired: Zeroizing::new(b"new skill".to_vec()),
            executable: false,
        }],
    };
    let bytes = encode_plan(&record, &plan).unwrap();
    assert_eq!(&bytes[..8], b"NKPPLN02");
    let decoded = decode_plan(&record, &bytes).unwrap();
    assert_eq!(decoded.assets.len(), 1);
    assert_eq!(decoded.assets[0].path, plan.assets[0].path);
    assert_eq!(decoded.assets[0].before, plan.assets[0].before);
    assert_eq!(decoded.assets[0].desired.as_slice(), b"new skill");
    assert!(!decoded.pair_write);
    let mut damaged = bytes.to_vec();
    damaged[96 + 1] ^= 1;
    assert!(decode_plan(&record, &damaged).is_err());
}
