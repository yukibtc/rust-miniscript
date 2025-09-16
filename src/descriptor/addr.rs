// SPDX-License-Identifier: CC0-1.0

//! # Address Output Descriptors
//!
//! Implementation of `addr()` descriptors (BIP-385).
//!

use core::fmt;
use core::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf, Weight};

use crate::descriptor::{write_descriptor, DefiniteDescriptorKey};
use crate::expression::{self, FromTree};
use crate::miniscript::satisfy::{Placeholder, Satisfaction, Witness};
use crate::plan::AssetProvider;
use crate::policy::{semantic, Liftable};
use crate::{Error, ForEachKey, FromStrKey, MiniscriptKey};

/// An Address descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr<Pk: MiniscriptKey> {
    /// The address
    address: Address<NetworkUnchecked>,
    /// Phantom key type for consistency with other descriptors
    _phantom: core::marker::PhantomData<Pk>,
}

impl<Pk: MiniscriptKey> Addr<Pk> {
    /// Create a new addr descriptor from an address
    pub fn new(address: Address<NetworkUnchecked>) -> Self {
        Self { address, _phantom: core::marker::PhantomData }
    }

    /// Get the address
    #[inline]
    pub fn address(&self) -> &Address<NetworkUnchecked> { &self.address }

    /// Checks whether the descriptor is safe.
    /// For addr() descriptors, this is always true as they simply wrap an address
    #[inline]
    pub fn sanity_check(&self) -> Result<(), Error> { Ok(()) }

    /// This method returns an error indicating the descriptor cannot be satisfied.
    #[inline]
    pub fn max_weight_to_satisfy(&self) -> Result<Weight, Error> { Err(Error::CouldNotSatisfy) }
}

impl<Pk: MiniscriptKey> Addr<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf { self.address.assume_checked_ref().script_pubkey() }

    /// Obtains the underlying miniscript for this descriptor.
    /// For addr() descriptors, this is the same as the script pubkey.
    pub fn inner_script(&self) -> ScriptBuf { self.script_pubkey() }

    /// Obtains the pre bip-340 signature script code for this descriptor.
    pub fn ecdsa_sighash_script_code(&self) -> ScriptBuf { self.script_pubkey() }
}

impl Addr<DefiniteDescriptorKey> {
    /// Returns a plan if the provided assets are sufficient to produce a non-malleable satisfaction.
    /// For addr() descriptors, satisfaction is never possible.
    pub fn plan_satisfaction<P>(
        &self,
        _provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>>
    where
        P: AssetProvider<DefiniteDescriptorKey>,
    {
        Satisfaction {
            stack: Witness::Unavailable,
            has_sig: false,
            relative_timelock: None,
            absolute_timelock: None,
        }
    }

    /// Returns a plan if the provided assets are sufficient to produce a malleable satisfaction.
    /// For addr() descriptors, satisfaction is never possible.
    pub fn plan_satisfaction_mall<P>(
        &self,
        _provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>>
    where
        P: AssetProvider<DefiniteDescriptorKey>,
    {
        self.plan_satisfaction(_provider)
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Addr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "addr({:?})", self.address) }
}

impl<Pk: MiniscriptKey> fmt::Display for Addr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_descriptor!(f, "addr({})", self.address.assume_checked_ref())
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Addr<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        // addr() descriptors cannot be lifted to a semantic policy as they
        // don't contain information about the spending conditions
        Err(Error::CouldNotSatisfy)
    }
}

impl<Pk: FromStrKey> FromTree for Addr<Pk> {
    fn from_tree(root: &expression::Tree) -> Result<Self, Error> {
        if root.name == "addr" && root.args.len() == 1 {
            // Parse the address string
            let address: Address<NetworkUnchecked> =
                expression::terminal(&root.args[0], |pk| Address::from_str(pk))?;

            Ok(Addr::new(address))
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing wpkh descriptor",
                root.name,
                root.args.len(),
            )))
        }
    }
}

impl<Pk: FromStrKey> core::str::FromStr for Addr<Pk> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Addr<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, _pred: F) -> bool {
        // addr() descriptors don't contain keys
        false
    }
}
