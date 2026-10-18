//! Shared Soter blob codec used by the software TA and Tencent test compatibility.
//!
//! Keep the public TA API while sharing the exact wire format and RSA-PSS
//! implementation without pulling HAL state or remote transport into consumers.

pub use pif_common::soter_blob::*;
