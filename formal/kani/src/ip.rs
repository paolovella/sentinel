// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! IP address verification extracted from `vellaveto-engine/src/ip.rs`.
//!
//! Functions operate on raw octets/segments instead of `std::net` types
//! to keep the Kani verification tractable. Each function is a verbatim
//! translation of the production logic — the only difference is the type
//! representation (`[u8; 4]` vs `Ipv4Addr`, `[u16; 8]` vs `Ipv6Addr`).
//!
//! That translation is checked behaviourally by
//! `vellaveto-engine/src/kani_ip_differential.rs`, which builds the `std::net`
//! value from the same octets and requires the classifications to agree, over
//! all 65,536 `a.b.1.1` addresses plus the boundary outside each RFC range.
//! Before 2026-08-28 nothing checked it — see PARITY-HAND-2 in
//! formal/ASSUMPTION_REGISTRY.md.
//!
//! Note when editing: the IPv4 classifier appears twice here, in
//! `is_private_ipv4` and again in `is_embedded_ipv4_reserved` (K29 is the
//! property that they agree). A change to one must be made to both.
//!
//! # Verified Properties (K26-K32)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K26 | 127.x.x.x always private (loopback) |
//! | K27 | RFC 1918 ranges always private |
//! | K28 | CGNAT 100.64.0.0/10 always private |
//! | K29 | is_embedded_ipv4_reserved parity with is_private_ipv4 |
//! | K30 | IPv4-mapped extraction correct |
//! | K31 | Teredo XOR inversion round-trip |
//! | K32 | Known public IPs (8.8.8.8, 1.1.1.1) NOT private |
//!
//! # Production Correspondence
//!
//! - `is_private_ipv4` ↔ `vellaveto-engine/src/ip.rs:41-60` (IPv4 branch)
//! - `is_embedded_ipv4_reserved` ↔ `vellaveto-engine/src/ip.rs:115-132`
//! - `extract_embedded_ipv4_from_segments` ↔ `vellaveto-engine/src/ip.rs:145-217`
//! - `is_private_ipv6_segments` ↔ `vellaveto-engine/src/ip.rs:62-77` (IPv6 branch)

/// Check if an IPv4 address (as raw octets) is private/reserved.
///
/// Verbatim from production `is_private_ip` IPv4 branch.
pub fn is_private_ipv4(octets: [u8; 4]) -> bool {
    // 127.0.0.0/8 — loopback
    let is_loopback = octets[0] == 127;
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — RFC 1918
    let is_private = octets[0] == 10
        || (octets[0] == 172 && (octets[1] & 0xF0) == 16)
        || (octets[0] == 192 && octets[1] == 168);
    // 169.254.0.0/16 — link-local
    let is_link_local = octets[0] == 169 && octets[1] == 254;
    // 0.0.0.0
    let is_unspecified = octets == [0, 0, 0, 0];
    // 255.255.255.255
    let is_broadcast = octets == [255, 255, 255, 255];
    // 0.0.0.0/8 (RFC 1122)
    let is_this_network = octets[0] == 0;
    // 100.64.0.0/10 CGNAT (RFC 6598)
    let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 64;
    // 198.18.0.0/15 benchmarking (RFC 2544)
    let is_benchmarking = octets[0] == 198 && (octets[1] & 0xFE) == 18;
    // 192.0.0.0/24 (RFC 6890)
    let is_ietf_protocol = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
    // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
    let is_test_net_1 = octets[0] == 192 && octets[1] == 0 && octets[2] == 2;
    // 198.51.100.0/24 TEST-NET-2
    let is_test_net_2 = octets[0] == 198 && octets[1] == 51 && octets[2] == 100;
    // 203.0.113.0/24 TEST-NET-3
    let is_test_net_3 = octets[0] == 203 && octets[1] == 0 && octets[2] == 113;
    // 192.88.99.0/24 deprecated 6to4 relay (RFC 7526)
    let is_6to4_relay = octets[0] == 192 && octets[1] == 88 && octets[2] == 99;
    // 240.0.0.0/4 Reserved/Class E (RFC 1112)
    let is_class_e = (octets[0] & 0xF0) == 240;

    is_loopback
        || is_private
        || is_link_local
        || is_unspecified
        || is_broadcast
        || is_this_network
        || is_cgnat
        || is_benchmarking
        || is_ietf_protocol
        || is_test_net_1
        || is_test_net_2
        || is_test_net_3
        || is_6to4_relay
        || is_class_e
}

/// Check if an embedded IPv4 address is reserved.
///
/// Verbatim from production `is_embedded_ipv4_reserved`.
/// Must produce identical results to `is_private_ipv4` for all inputs.
pub fn is_embedded_ipv4_reserved(octets: [u8; 4]) -> bool {
    // Identical logic to is_private_ipv4 — production also mirrors these checks.
    let is_loopback = octets[0] == 127;
    let is_private = octets[0] == 10
        || (octets[0] == 172 && (octets[1] & 0xF0) == 16)
        || (octets[0] == 192 && octets[1] == 168);
    let is_link_local = octets[0] == 169 && octets[1] == 254;
    let is_unspecified = octets == [0, 0, 0, 0];
    let is_broadcast = octets == [255, 255, 255, 255];
    let is_this_network = octets[0] == 0;
    let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 64;
    let is_benchmarking = octets[0] == 198 && (octets[1] & 0xFE) == 18;
    let is_ietf_protocol = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
    let is_test_net_1 = octets[0] == 192 && octets[1] == 0 && octets[2] == 2;
    let is_test_net_2 = octets[0] == 198 && octets[1] == 51 && octets[2] == 100;
    let is_test_net_3 = octets[0] == 203 && octets[1] == 0 && octets[2] == 113;
    let is_6to4_relay = octets[0] == 192 && octets[1] == 88 && octets[2] == 99;
    let is_class_e = (octets[0] & 0xF0) == 240;

    is_loopback
        || is_private
        || is_link_local
        || is_unspecified
        || is_broadcast
        || is_this_network
        || is_cgnat
        || is_benchmarking
        || is_ietf_protocol
        || is_test_net_1
        || is_test_net_2
        || is_test_net_3
        || is_6to4_relay
        || is_class_e
}

/// Extract segments 6-7 as IPv4 octets (standard layout for most mechanisms).
fn segments_to_ipv4(seg6: u16, seg7: u16) -> [u8; 4] {
    [
        (seg6 >> 8) as u8,
        (seg6 & 0xff) as u8,
        (seg7 >> 8) as u8,
        (seg7 & 0xff) as u8,
    ]
}

/// Extract embedded IPv4 from IPv6 segments, or None.
///
/// Verbatim logic from production `extract_embedded_ipv4`.
pub fn extract_embedded_ipv4_from_segments(segs: [u16; 8]) -> Option<[u8; 4]> {
    // 1. IPv4-mapped: ::ffff:x.x.x.x
    if segs[0] == 0
        && segs[1] == 0
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0xffff
    {
        return Some(segments_to_ipv4(segs[6], segs[7]));
    }

    // 2. IPv4-compatible: ::x.x.x.x (deprecated but still routable)
    if segs[0] == 0
        && segs[1] == 0
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
        && !(segs[6] == 0 && segs[7] <= 1)
    {
        return Some(segments_to_ipv4(segs[6], segs[7]));
    }

    // 3. 6to4: 2002::/16 — IPv4 in segments 1-2
    if segs[0] == 0x2002 {
        return Some(segments_to_ipv4(segs[1], segs[2]));
    }

    // 4. Teredo: 2001:0000::/32 — IPv4 in segments 6-7, XORed
    if segs[0] == 0x2001 && segs[1] == 0 {
        return Some([
            ((segs[6] >> 8) ^ 0xff) as u8,
            ((segs[6] & 0xff) ^ 0xff) as u8,
            ((segs[7] >> 8) ^ 0xff) as u8,
            ((segs[7] & 0xff) ^ 0xff) as u8,
        ]);
    }

    // 5. NAT64 well-known: 64:ff9b::/96 — IPv4 in segments 6-7
    if segs[0] == 0x0064
        && segs[1] == 0xff9b
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
    {
        return Some(segments_to_ipv4(segs[6], segs[7]));
    }

    // 6. NAT64 local-use: 64:ff9b:0001::/48 — IPv4 in segments 6-7
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
        return Some(segments_to_ipv4(segs[6], segs[7]));
    }

    None
}

/// Check if IPv6 segments represent a private/reserved address.
///
/// Verbatim from production `is_private_ip` IPv6 branch.
pub fn is_private_ipv6_segments(segs: [u16; 8]) -> bool {
    // ::1 — loopback
    let is_loopback = segs[0] == 0
        && segs[1] == 0
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
        && segs[6] == 0
        && segs[7] == 1;
    // :: — unspecified
    let is_unspecified = segs[0] == 0
        && segs[1] == 0
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
        && segs[6] == 0
        && segs[7] == 0;
    // fc00::/7 — ULA
    let is_ula = (segs[0] & 0xfe00) == 0xfc00;
    // fe80::/10 — link-local
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
    // ff00::/8 — multicast
    let is_multicast = (segs[0] & 0xff00) == 0xff00;
    // 2001:db8::/32 — documentation
    let is_documentation = segs[0] == 0x2001 && segs[1] == 0x0db8;
    // 100::/64 — discard-only
    let is_discard = segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0;

    // Transition mechanisms with embedded IPv4
    let embedded_private = match extract_embedded_ipv4_from_segments(segs) {
        Some(v4) => is_embedded_ipv4_reserved(v4),
        None => false,
    };

    is_loopback
        || is_unspecified
        || is_ula
        || is_link_local
        || is_multicast
        || is_documentation
        || is_discard
        || embedded_private
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parity_loopback() {
        assert!(is_private_ipv4([127, 0, 0, 1]));
        assert!(is_private_ipv4([127, 255, 255, 255]));
    }

    #[test]
    fn test_parity_rfc1918() {
        assert!(is_private_ipv4([10, 0, 0, 1]));
        assert!(is_private_ipv4([172, 16, 0, 1]));
        assert!(is_private_ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn test_parity_cgnat() {
        assert!(is_private_ipv4([100, 64, 0, 1]));
        assert!(is_private_ipv4([100, 127, 255, 255]));
        // Just outside CGNAT range
        assert!(!is_private_ipv4([100, 128, 0, 0]));
    }

    #[test]
    fn test_parity_public() {
        assert!(!is_private_ipv4([8, 8, 8, 8]));
        assert!(!is_private_ipv4([1, 1, 1, 1]));
        assert!(!is_private_ipv4([93, 184, 216, 34])); // example.com
    }

    #[test]
    fn test_embedded_ipv4_parity() {
        // Must agree with is_private_ipv4 for all tested addresses
        for octets in [
            [127, 0, 0, 1],
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            [100, 64, 0, 1],
            [8, 8, 8, 8],
            [1, 1, 1, 1],
            [172, 16, 0, 1],
        ] {
            assert_eq!(
                is_private_ipv4(octets),
                is_embedded_ipv4_reserved(octets),
                "Parity mismatch for {:?}",
                octets
            );
        }
    }

    #[test]
    fn test_extract_mapped() {
        // ::ffff:192.168.1.1
        let segs = [0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101];
        assert_eq!(
            extract_embedded_ipv4_from_segments(segs),
            Some([192, 168, 1, 1])
        );
    }

    #[test]
    fn test_extract_teredo_xor() {
        // Teredo XOR: 192.168.1.1 → XOR'd = 0x3f57, 0xfefe
        let segs = [0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3f57, 0xfefe];
        let v4 = extract_embedded_ipv4_from_segments(segs);
        assert_eq!(v4, Some([192, 168, 1, 1]));
    }

    #[test]
    fn test_extract_6to4() {
        // 2002:c0a8:0101::1 → embedded 192.168.1.1
        let segs = [0x2002, 0xc0a8, 0x0101, 0, 0, 0, 0, 1];
        assert_eq!(
            extract_embedded_ipv4_from_segments(segs),
            Some([192, 168, 1, 1])
        );
    }

    #[test]
    fn test_extract_nat64() {
        // 64:ff9b::c0a8:0101 → embedded 192.168.1.1
        let segs = [0x0064, 0xff9b, 0, 0, 0, 0, 0xc0a8, 0x0101];
        assert_eq!(
            extract_embedded_ipv4_from_segments(segs),
            Some([192, 168, 1, 1])
        );
    }

    #[test]
    fn test_extract_nat64_local() {
        // 64:ff9b:1::c0a8:0101 → embedded 192.168.1.1
        let segs = [0x0064, 0xff9b, 0x0001, 0, 0, 0, 0xc0a8, 0x0101];
        assert_eq!(
            extract_embedded_ipv4_from_segments(segs),
            Some([192, 168, 1, 1])
        );
    }

    #[test]
    fn test_no_embedded() {
        // 2001:4860:4860::8888 — pure IPv6, no embedded IPv4
        let segs = [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888];
        assert_eq!(extract_embedded_ipv4_from_segments(segs), None);
    }

    #[test]
    fn test_ipv6_private_loopback() {
        // ::1
        let segs = [0, 0, 0, 0, 0, 0, 0, 1];
        assert!(is_private_ipv6_segments(segs));
    }

    #[test]
    fn test_ipv6_private_ula() {
        // fc00::1
        let segs = [0xfc00, 0, 0, 0, 0, 0, 0, 1];
        assert!(is_private_ipv6_segments(segs));
        // fd00::1
        let segs = [0xfd00, 0, 0, 0, 0, 0, 0, 1];
        assert!(is_private_ipv6_segments(segs));
    }

    #[test]
    fn test_ipv6_public() {
        // 2001:4860:4860::8888 (Google DNS)
        let segs = [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888];
        assert!(!is_private_ipv6_segments(segs));
    }
}
