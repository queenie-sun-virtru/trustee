// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod sample;
pub mod resource;
#[cfg(feature = "nebula-ca-plugin")]
pub mod nebula_ca;
pub mod spiffe_resource; 
#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "nebula-ca-plugin")]
pub use nebula_ca::{NebulaCaPlugin, NebulaCaPluginConfig};
#[cfg(feature = "pkcs11")]
pub use pkcs11::{Pkcs11Backend, Pkcs11Config};
pub use resource::{RepositoryConfig, ResourceStorage};
pub use sample::{Sample, SampleConfig};
pub use spiffe_resource::{SpiffeResourcePlugin, SpiffeResourceConfig}; 

