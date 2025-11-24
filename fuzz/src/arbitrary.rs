use arbitrary::{Arbitrary, Unstructured};
use secure_gate::{Dynamic, DynamicZeroizing, Fixed, FixedZeroizing}; // ← Updated

#[allow(dead_code)] // ← add this
#[derive(Debug)]
pub struct FuzzFixed32(pub Fixed<[u8; 32]>);

#[allow(dead_code)] // ← add this
#[derive(Debug)]
pub struct FuzzDynamicVec(pub Dynamic<Vec<u8>>);

#[allow(dead_code)] // ← add this
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

// ... (keep existing)

#[allow(dead_code)]
#[derive(Debug)]
pub struct FuzzFixedZeroizing32(pub FixedZeroizing<[u8; 32]>);

#[allow(dead_code)]
#[derive(Debug)]
pub struct FuzzDynamicZeroizingVec(pub DynamicZeroizing<Vec<u8>>);

#[allow(dead_code)]
#[derive(Debug)]
pub struct FuzzDynamicZeroizingString(pub DynamicZeroizing<String>);

impl<'a> Arbitrary<'a> for FuzzFixedZeroizing32 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut arr = [0u8; 32];
        u.fill_buffer(&mut arr)?;
        Ok(FuzzFixedZeroizing32(FixedZeroizing::new(arr)))
    }
}

impl<'a> Arbitrary<'a> for FuzzDynamicZeroizingVec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let vec: Vec<u8> = Arbitrary::arbitrary(u)?;
        Ok(FuzzDynamicZeroizingVec(DynamicZeroizing::new(Box::new(
            vec,
        ))))
    }
}

impl<'a> Arbitrary<'a> for FuzzDynamicZeroizingString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s: String = Arbitrary::arbitrary(u)?;
        Ok(FuzzDynamicZeroizingString(DynamicZeroizing::new(Box::new(
            s,
        ))))
    }
}
