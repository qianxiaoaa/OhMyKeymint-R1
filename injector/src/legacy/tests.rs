use super::should_use_legacy_aaid_provider;

#[test]
fn legacy_aaid_provider_boundary_is_android_14() {
    for version in [Some(12), Some(13), Some(14)] {
        assert!(should_use_legacy_aaid_provider(version));
    }

    for version in [None, Some(15), Some(16), Some(17)] {
        assert!(!should_use_legacy_aaid_provider(version));
    }
}
