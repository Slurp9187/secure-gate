//! `RevealScoped` shares its method name with `RevealSecret`. Re-exported from the crate
//! root, it would make `use secure_gate::*;` callers fail with `E0034` on every
//! `fixed.with_secret(..)`. These are the three downstream shapes from
//! `docs/design/sealed_memory.md`, checked against the real crate: each must compile.
#![cfg(feature = "sealed")]

mod glob_import {
    use secure_gate::*;

    #[test]
    fn with_secret_resolves_under_a_glob_import() {
        let fixed = Fixed::new([1u8; 4]);
        assert_eq!(fixed.with_secret(|b| b[0]), 1);
        let prekey = Prekey::new();
        let sealed = SealedFixed::seal(Fixed::new([2u8; 4]), &prekey);
        assert_eq!(sealed.with_secret(|b| b[0]), 2);
    }
}

mod single_trait_import {
    use secure_gate::{Fixed, RevealSecret};

    #[test]
    fn with_secret_resolves_with_only_reveal_secret_imported() {
        let fixed = Fixed::new([1u8; 4]);
        assert_eq!(fixed.with_secret(|b| b[0]), 1);
    }
}

mod generic_over_scoped {
    use secure_gate::scoped::RevealScoped;
    use secure_gate::{Fixed, Prekey, SealedFixed};

    fn sum<S: RevealScoped<Inner = [u8; 4]>>(s: &S) -> u32 {
        s.with_secret(|b| b.iter().map(|&x| u32::from(x)).sum())
    }

    #[test]
    fn generic_code_takes_plain_and_sealed() {
        let prekey = Prekey::new();
        assert_eq!(sum(&Fixed::new([1u8; 4])), 4);
        assert_eq!(sum(&SealedFixed::seal(Fixed::new([2u8; 4]), &prekey)), 8);
    }
}
