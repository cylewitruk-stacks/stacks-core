use clarity_types::types::{PrincipalData, StandardPrincipalData};
use stacks_primitives::address::StacksAddress;

pub fn standard_principal_from_address(addr: StacksAddress) -> StandardPrincipalData {
    let (version, bytes) = addr.destruct();
    StandardPrincipalData::new(version, bytes.0)
        .expect("FATAL: could not convert StacksAddress to StandardPrincipalData")
}

pub fn principal_from_address(addr: StacksAddress) -> PrincipalData {
    PrincipalData::Standard(standard_principal_from_address(addr))
}
