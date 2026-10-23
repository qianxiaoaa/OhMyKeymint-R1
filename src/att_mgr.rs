use std::sync::Mutex;

use kmr_common::km_err;
use kmr_ta::device::RetrieveAttestationIds;
use kmr_wire::AttestationIdInfo;

use crate::{config::config, pif_spoof};

pub struct AttestationIdMgr;

static ATTESTATION_IDS: Mutex<Option<CachedAttestationIds>> = Mutex::new(None);

#[derive(Clone, PartialEq, Eq)]
struct CachedAttestationIds {
    alignment: Option<pif_spoof::PifIdentity>,
    ids: AttestationIdInfo,
}

impl RetrieveAttestationIds for AttestationIdMgr {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        self.get_ids()?
            .ok_or_else(|| km_err!(CannotAttestIds, "attestation ID info not available"))
    }

    fn get_ids(&self) -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
        let alignment = match pif_spoof::aligned_identity() {
            Ok(alignment) => alignment,
            Err(error) => {
                log::warn!("failed to load the PIF profile for identity alignment: {error:#}");
                None
            }
        };

        let mut cached = ATTESTATION_IDS
            .lock()
            .map_err(|_| km_err!(UnknownError, "attestation ID cache lock poisoned"))?;
        if let Some(entry) = cached.as_ref() {
            if entry.alignment == alignment {
                return Ok(Some(entry.ids.clone()));
            }
        }

        let needs_resolution = |device: &crate::config::DeviceProperty| {
            !device.override_telephony_properties
                && (device.imei.trim().is_empty()
                    || device.imei2.trim().is_empty()
                    || device.meid.trim().is_empty())
        };
        let guard = config()
            .read()
            .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?;
        let device = if needs_resolution(&guard.device) {
            drop(guard);
            match crate::plat::device_ids::resolve_runtime_device_ids() {
                Ok(Some(device)) => device,
                Ok(None) => return Ok(None),
                Err(error) => {
                    log::warn!("failed to resolve runtime attestation IDs: {error:#}");
                    return Ok(None);
                }
            }
        } else {
            guard.device.clone()
        };

        let mut ids = AttestationIdInfo {
            brand: device.brand.into_bytes(),
            device: device.device.into_bytes(),
            product: device.product.into_bytes(),
            serial: device.serial.into_bytes(),
            imei: device.imei.into_bytes(),
            imei2: device.imei2.into_bytes(),
            meid: device.meid.into_bytes(),
            manufacturer: device.manufacturer.into_bytes(),
            model: device.model.into_bytes(),
        };
        merge_alignment(&mut ids, alignment.as_ref());
        *cached = Some(CachedAttestationIds {
            alignment: alignment.clone(),
            ids: ids.clone(),
        });
        Ok(Some(ids))
    }

    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        // ignore this
        Ok(())
    }
}

/// Replaces only the identity fields the PIF profile carries. Telephony IDs and
/// the serial stay bound to the configured device because the profile has no
/// substitutes for them.
fn merge_alignment(ids: &mut AttestationIdInfo, identity: Option<&pif_spoof::PifIdentity>) {
    let Some(identity) = identity else {
        return;
    };
    log::info!(
        "attestation identity aligned with the PIF profile (model={} product={})",
        identity.model,
        identity.product
    );
    ids.brand = identity.brand.clone().into_bytes();
    ids.device = identity.device.clone().into_bytes();
    ids.product = identity.product.clone().into_bytes();
    ids.manufacturer = identity.manufacturer.clone().into_bytes();
    ids.model = identity.model.clone().into_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_ids() -> AttestationIdInfo {
        AttestationIdInfo {
            brand: b"real-brand".to_vec(),
            device: b"real-device".to_vec(),
            product: b"real-product".to_vec(),
            serial: b"real-serial".to_vec(),
            imei: b"111111111111111".to_vec(),
            imei2: b"222222222222222".to_vec(),
            meid: b"A1000000000001".to_vec(),
            manufacturer: b"real-mfr".to_vec(),
            model: b"real-model".to_vec(),
        }
    }

    fn identity() -> pif_spoof::PifIdentity {
        pif_spoof::PifIdentity {
            brand: "google".to_string(),
            device: "oriole".to_string(),
            product: "oriole".to_string(),
            manufacturer: "Google".to_string(),
            model: "Pixel 6".to_string(),
        }
    }

    #[test]
    fn alignment_replaces_only_the_identity_fields() {
        let mut ids = base_ids();
        merge_alignment(&mut ids, Some(&identity()));
        assert_eq!(ids.brand, b"google".to_vec());
        assert_eq!(ids.device, b"oriole".to_vec());
        assert_eq!(ids.product, b"oriole".to_vec());
        assert_eq!(ids.manufacturer, b"Google".to_vec());
        assert_eq!(ids.model, b"Pixel 6".to_vec());
        assert_eq!(ids.serial, b"real-serial".to_vec());
        assert_eq!(ids.imei, b"111111111111111".to_vec());
        assert_eq!(ids.imei2, b"222222222222222".to_vec());
        assert_eq!(ids.meid, b"A1000000000001".to_vec());
    }

    #[test]
    fn no_alignment_keeps_the_configured_identity() {
        let mut ids = base_ids();
        merge_alignment(&mut ids, None);
        assert_eq!(ids.brand, b"real-brand".to_vec());
        assert_eq!(ids.model, b"real-model".to_vec());
        assert_eq!(ids.manufacturer, b"real-mfr".to_vec());
    }
}
