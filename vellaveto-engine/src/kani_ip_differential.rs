// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — IP privacy classification.
//!
//! `formal/kani/src/ip.rs` states that "each function is a verbatim translation
//! of the production logic — the only difference is the type representation
//! (`[u8; 4]` vs `Ipv4Addr`, `[u16; 8]` vs `Ipv6Addr`)", and carries proofs
//! K26-K32 on top of that claim. Nothing checked it.
//!
//! This is the check. Unlike the path extraction, the two are *not* textually
//! comparable — the representation genuinely differs — so the binding bridges
//! it explicitly: build the `std::net` value from the same octets the extraction
//! is given, and require the classifications to agree.
//!
//! What rides on it: `is_private_ip` is what `block_private` enforces, so a
//! disagreement here means the SSRF and DNS-rebinding proofs describe a
//! classifier that is not the one deciding.

#[cfg(test)]
// Suppressed rather than satisfied, for the reason given in
// `kani_path_differential`: linting the extraction edits the copy the proofs
// run against.
#[allow(
    clippy::manual_range_contains,
    clippy::unusual_byte_groupings,
    dead_code,
    unused_imports
)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_ip_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_ip {
    use super::extracted;
    use crate::ip::is_private_ip;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/ip.rs was not found, so this binding compared nothing"
        );
    }

    /// Every `a.b.c.d` over a first-octet sweep crossed with the second octets
    /// that RFC 1918 and CGNAT branch on.
    ///
    /// The classification depends almost entirely on the first two octets, so
    /// this covers the branch structure exhaustively in the dimension that
    /// matters rather than sampling 2^32.
    #[test]
    fn test_ipv4_classification_matches_production_across_the_branch_structure() {
        let mut checked = 0usize;
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let octets = [a, b, 1, 1];
                let production = is_private_ip(IpAddr::V4(Ipv4Addr::new(a, b, 1, 1)));
                let kani = extracted::is_private_ipv4(octets);
                assert_eq!(
                    production, kani,
                    "PARITY-HAND-2: production and the Kani extraction classify \
                     {a}.{b}.1.1 differently (production private={production}, \
                     extracted private={kani}) — proofs K26-K32 are about a \
                     classifier that is not the one enforcing block_private"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 256 * 256, "enumeration collapsed");
    }

    /// The addresses the kernel's own property table names, plus the boundaries
    /// immediately outside each range — where an off-by-one lives.
    #[test]
    fn test_ipv4_named_properties_and_range_boundaries_agree() {
        const CASES: &[([u8; 4], &str)] = &[
            // K26 loopback
            ([127, 0, 0, 1], "loopback"),
            ([127, 255, 255, 255], "loopback top"),
            ([126, 255, 255, 255], "just below loopback"),
            ([128, 0, 0, 0], "just above loopback"),
            // K27 RFC 1918
            ([10, 0, 0, 0], "10/8 bottom"),
            ([10, 255, 255, 255], "10/8 top"),
            ([9, 255, 255, 255], "below 10/8"),
            ([11, 0, 0, 0], "above 10/8"),
            ([172, 16, 0, 0], "172.16/12 bottom"),
            ([172, 31, 255, 255], "172.16/12 top"),
            ([172, 15, 255, 255], "below 172.16/12"),
            ([172, 32, 0, 0], "above 172.16/12"),
            ([192, 168, 0, 0], "192.168/16 bottom"),
            ([192, 168, 255, 255], "192.168/16 top"),
            ([192, 167, 255, 255], "below 192.168/16"),
            ([192, 169, 0, 0], "above 192.168/16"),
            // K28 CGNAT 100.64/10
            ([100, 64, 0, 0], "CGNAT bottom"),
            ([100, 127, 255, 255], "CGNAT top"),
            ([100, 63, 255, 255], "below CGNAT"),
            ([100, 128, 0, 0], "above CGNAT"),
            // K32 known public
            ([8, 8, 8, 8], "public DNS"),
            ([1, 1, 1, 1], "public DNS"),
            // link-local and unspecified
            ([169, 254, 0, 1], "link-local"),
            ([0, 0, 0, 0], "unspecified"),
            ([255, 255, 255, 255], "broadcast"),
        ];

        for (octets, label) in CASES {
            let [a, b, c, d] = *octets;
            let production = is_private_ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
            let kani = extracted::is_private_ipv4(*octets);
            assert_eq!(
                production, kani,
                "PARITY-HAND-2: disagreement on {a}.{b}.{c}.{d} ({label})"
            );
        }
    }

    /// IPv6, over the transition mechanisms that embed IPv4 — the ones a
    /// classifier is most likely to get wrong, and the ones K29-K31 are about.
    #[test]
    fn test_ipv6_classification_matches_production_on_transition_mechanisms() {
        const CASES: &[([u16; 8], &str)] = &[
            (
                [0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001],
                "IPv4-mapped loopback",
            ),
            ([0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001], "IPv4-mapped 10/8"),
            (
                [0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808],
                "IPv4-mapped 8.8.8.8",
            ),
            (
                [0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0001],
                "IPv4-mapped 192.168.0.1",
            ),
            (
                [0, 0, 0, 0, 0, 0, 0x7f00, 0x0001],
                "IPv4-compatible loopback",
            ),
            ([0, 0, 0, 0, 0, 0, 0x0808, 0x0808], "IPv4-compatible public"),
            ([0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 0], "6to4 over 10/8"),
            ([0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 0], "6to4 over public"),
            ([0x2001, 0, 0, 0, 0, 0, 0xf5ff, 0xfffe], "Teredo"),
            ([0xfc00, 0, 0, 0, 0, 0, 0, 1], "unique local fc00::/7"),
            ([0xfd00, 0, 0, 0, 0, 0, 0, 1], "unique local fd00::/8"),
            ([0xfe80, 0, 0, 0, 0, 0, 0, 1], "link local"),
            ([0xff00, 0, 0, 0, 0, 0, 0, 1], "multicast"),
            ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], "documentation"),
            ([0x0100, 0, 0, 0, 0, 0, 0, 1], "discard"),
            ([0, 0, 0, 0, 0, 0, 0, 1], "loopback ::1"),
            ([0, 0, 0, 0, 0, 0, 0, 0], "unspecified ::"),
            ([0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111], "public"),
        ];

        for (segs, label) in CASES {
            let production = is_private_ip(IpAddr::V6(Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
            )));
            let kani = extracted::is_private_ipv6_segments(*segs);
            assert_eq!(
                production, kani,
                "PARITY-HAND-2: production and the Kani extraction classify the \
                 IPv6 address {label} differently (production private={production}, \
                 extracted private={kani})"
            );
        }
    }

    /// K30: the embedded-IPv4 extraction must recover the same address.
    #[test]
    fn test_embedded_ipv4_extraction_matches_production() {
        for a in [0u8, 1, 8, 10, 100, 127, 169, 172, 192, 255] {
            for b in [0u8, 1, 16, 31, 64, 127, 168, 254, 255] {
                let segs = [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0xffff,
                    (u16::from(a) << 8) | u16::from(b),
                    0x0102,
                ];
                let v6 = Ipv6Addr::new(
                    segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
                );
                let production = crate::ip::extract_embedded_ipv4(&v6).map(|v| v.octets());
                let kani = extracted::extract_embedded_ipv4_from_segments(segs);
                assert_eq!(
                    production, kani,
                    "PARITY-HAND-2 (K30): embedded IPv4 extraction disagrees for {v6}"
                );
            }
        }
    }

    /// The comparison must be able to fail: the sweep has to contain both
    /// private and public addresses, or agreement means nothing.
    #[test]
    fn test_sweep_covers_both_classifications() {
        let mut private = 0usize;
        let mut public = 0usize;
        for a in 0u8..=255 {
            if is_private_ip(IpAddr::V4(Ipv4Addr::new(a, 1, 1, 1))) {
                private += 1;
            } else {
                public += 1;
            }
        }
        assert!(
            private > 0 && public > 0,
            "sweep is one-sided (private {private}, public {public}); it cannot \
             distinguish a classifier that says everything is private"
        );
    }
}
