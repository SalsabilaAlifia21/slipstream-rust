mod base32;
mod codec;
mod dots;
mod name;
mod types;
mod wire;

pub use base32::{decode as base32_decode, encode as base32_encode, Base32Error};
pub use codec::{
    decode_query, decode_query_with_domains, decode_response, encode_query, encode_response,
    is_response,
};
pub use dots::{dotify, undotify};
pub use types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Question, Rcode, ResponseParams,
    CLASS_IN, EDNS_UDP_PAYLOAD, MAX_UPSTREAM_PAYLOAD_LEN, RR_A, RR_NULL, RR_OPT, RR_TXT,
};

pub fn build_qname(payload: &[u8], domain: &str) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let max_payload = qname_payload_len_for_domain(domain)?;
    if payload.len() > max_payload {
        return Err(DnsError::new("payload too large for domain"));
    }
    let base32 = base32_encode(payload);
    let dotted = dotify(&base32);
    Ok(format!("{}.{}.", dotted, domain))
}

/// Build a QNAME that carries only a short nonce (derived from the DNS ID)
/// for cache-busting.  The upstream payload is carried in a NULL additional
/// record instead of in the QNAME.
pub fn build_nonce_qname(dns_id: u16, domain: &str) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let nonce_bytes = dns_id.to_be_bytes();
    let nonce = base32_encode(&nonce_bytes);
    Ok(format!("{}.{}.", nonce, domain))
}

/// Maximum upstream payload length.  With the NULL additional record path the
/// payload is no longer limited by QNAME encoding; it is capped at
/// [`MAX_UPSTREAM_PAYLOAD_LEN`] (1000 bytes).
pub fn max_payload_len_for_domain(domain: &str) -> Result<usize, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if domain.len() > name::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("domain too long"));
    }
    Ok(types::MAX_UPSTREAM_PAYLOAD_LEN)
}

/// Maximum payload that can be encoded in a QNAME subdomain (legacy path).
pub fn qname_payload_len_for_domain(domain: &str) -> Result<usize, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if domain.len() > name::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("domain too long"));
    }
    let max_name_len = name::MAX_DNS_NAME_LEN;
    let max_dotted_len = max_name_len.saturating_sub(domain.len() + 1);
    if max_dotted_len == 0 {
        return Ok(0);
    }
    let mut max_base32_len = 0usize;
    for len in 1..=max_dotted_len {
        let dots = (len - 1) / 57;
        if len + dots > max_dotted_len {
            break;
        }
        max_base32_len = len;
    }

    let mut max_payload = (max_base32_len * 5) / 8;
    while max_payload > 0 && base32_len(max_payload) > max_base32_len {
        max_payload -= 1;
    }
    Ok(max_payload)
}

fn base32_len(payload_len: usize) -> usize {
    if payload_len == 0 {
        return 0;
    }
    (payload_len * 8).div_ceil(5)
}

#[cfg(test)]
mod tests {
    use super::{build_qname, max_payload_len_for_domain, qname_payload_len_for_domain};

    #[test]
    fn build_qname_rejects_payload_overflow() {
        let domain = "test.com";
        let max_payload = qname_payload_len_for_domain(domain).expect("max payload");
        let payload = vec![0u8; max_payload + 1];
        assert!(build_qname(&payload, domain).is_err());
    }

    #[test]
    fn build_qname_rejects_long_domain() {
        let domain = format!("{}.com", "a".repeat(260));
        let payload = vec![0u8; 1];
        assert!(build_qname(&payload, &domain).is_err());
    }

    #[test]
    fn max_payload_len_returns_upstream_limit() {
        let max = max_payload_len_for_domain("example.com").expect("max payload");
        assert_eq!(max, 1000);
    }
}
