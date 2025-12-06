// fuzz/src/arbitrary.rs
//! Arbitrary implementations for fuzzing secure_gate types

use arbitrary::{Arbitrary, Unstructured};
use secure_gate::{Dynamic, Fixed};

#[cfg(feature = "zeroize")]
use secure_gate::{DynamicNoClone, FixedNoClone};

#[derive(Debug)]
pub struct FuzzFixed32(pub Fixed<[u8; 32]>);

#[derive(Debug)]
pub struct FuzzDynamicVec(pub Dynamic<Vec<u8>>);

#[derive(Debug)]
pub struct FuzzDynamicString(pub Dynamic<String>);

impl<'a> Arbitrary<'a> for FuzzFixed32 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut arr = [0u8; 32];
        u.fill_buffer(&mut arr)?;
        Ok(FuzzFixed32(Fixed::new(arr)))
    }
}

impl<'a> Arbitrary<'a> for FuzzDynamicVec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let vec: Vec<u8> = Arbitrary::arbitrary(u)?;
        Ok(FuzzDynamicVec(Dynamic::new(vec)))
    }
}

impl<'a> Arbitrary<'a> for FuzzDynamicString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s: String = Arbitrary::arbitrary(u)?;
        Ok(FuzzDynamicString(Dynamic::new(s)))
    }
}

#[cfg(feature = "zeroize")]
#[derive(Debug)]
pub struct FuzzFixedZeroizing32(pub FixedNoClone<[u8; 32]>);

#[cfg(feature = "zeroize")]
#[derive(Debug)]
pub struct FuzzDynamicZeroizingVec(pub DynamicNoClone<Vec<u8>>);

#[cfg(feature = "zeroize")]
#[derive(Debug)]
pub struct FuzzDynamicZeroizingString(pub DynamicNoClone<String>);

#[cfg(feature = "zeroize")]
impl<'a> Arbitrary<'a> for FuzzFixedZeroizing32 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut arr = [0u8; 32];
        u.fill_buffer(&mut arr)?;
        Ok(FuzzFixedZeroizing32(FixedNoClone::new(arr)))
    }
}

#[cfg(feature = "zeroize")]
impl<'a> Arbitrary<'a> for FuzzDynamicZeroizingVec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let vec: Vec<u8> = Arbitrary::arbitrary(u)?;
        Ok(FuzzDynamicZeroizingVec(DynamicNoClone::new(Box::new(vec))))
    }
}

#[cfg(feature = "zeroize")]
impl<'a> Arbitrary<'a> for FuzzDynamicZeroizingString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s: String = Arbitrary::arbitrary(u)?;
        Ok(FuzzDynamicZeroizingString(DynamicNoClone::new(Box::new(s))))
    }
}
