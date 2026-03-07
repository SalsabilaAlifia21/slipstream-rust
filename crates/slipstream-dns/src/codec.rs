use crate::base32;
use crate::dots;

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, ResponseParams, EDNS_UDP_PAYLOAD,
    RR_NULL, RR_OPT,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, parse_rr, read_u16, read_u32,
    write_u16, write_u32,
};

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain])
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
) -> Result<DecodedQuery, DecodeQueryError> {
    let header = match parse_header(packet) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let (question, question_end) = match parse_question(packet, header.offset) {
        Ok(result) => result,
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    if question.qtype != RR_NULL {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    // Check additional section for a NULL record carrying upstream payload.
    let additional_payload = scan_additional_null(packet, question_end, header.arcount);

    if let Some(payload) = additional_payload {
        // Upstream data is carried in the NULL additional record.
        // The QNAME subdomain must still be present (for cache-busting) but
        // its content is not decoded as payload data.
        let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
            Ok(sub) => sub,
            Err(rcode) => {
                return Err(DecodeQueryError::Reply {
                    id: header.id,
                    rd,
                    cd,
                    question: Some(question),
                    rcode,
                });
            }
        };
        if subdomain_raw.is_empty() {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode: Rcode::NameError,
            });
        }
        return Ok(DecodedQuery {
            id: header.id,
            rd,
            cd,
            question,
            payload,
        });
    }

    // Legacy path: upstream data is encoded in the QNAME subdomain.
    let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(rcode) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode,
            })
        }
    };

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let payload = match base32::decode(&undotted) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode: Rcode::ServerFailure,
            })
        }
    };

    Ok(DecodedQuery {
        id: header.id,
        rd,
        cd,
        question,
        payload,
    })
}

pub fn encode_query(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    let payload_data = params.payload.filter(|p| !p.is_empty());
    if let Some(data) = payload_data {
        if data.len() > params.max_payload_len {
            return Err(DnsError::new("query payload too long"));
        }
    }

    let arcount: u16 = if payload_data.is_some() { 2 } else { 1 };

    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, arcount);

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    if let Some(data) = payload_data {
        encode_null_record(&mut out, data)?;
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn encode_response(params: &ResponseParams<'_>) -> Result<Vec<u8>, DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let mut ancount = 0u16;
    if payload_len > 0 && rcode == Rcode::Ok {
        ancount = 1;
    } else if params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    let mut out = Vec::with_capacity(256);
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, ancount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(&params.question.name, &mut out)?;
    write_u16(&mut out, params.question.qtype);
    write_u16(&mut out, params.question.qclass);

    if ancount == 1 {
        out.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut out, params.question.qtype);
        write_u16(&mut out, params.question.qclass);
        write_u32(&mut out, 60);
        if payload_len > params.max_payload_len {
            return Err(DnsError::new("payload too long"));
        }
        write_u16(&mut out, payload_len as u16);
        if let Some(payload) = params.payload {
            out.extend_from_slice(payload);
        }
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn decode_response(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount != 1 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let (_, new_offset) = parse_name(packet, offset).ok()?;
    offset = new_offset;
    if offset + 10 > packet.len() {
        return None;
    }
    let qtype = read_u16(packet, offset)?;
    if qtype != RR_NULL {
        return None;
    }
    offset += 2;
    let _qclass = read_u16(packet, offset)?;
    offset += 2;
    let _ttl = read_u32(packet, offset)?;
    offset += 4;
    let rdlen = read_u16(packet, offset)? as usize;
    offset += 2;
    if rdlen == 0 || offset + rdlen > packet.len() {
        return None;
    }
    let out = packet[offset..offset + rdlen].to_vec();
    if out.is_empty() {
        return None;
    }
    Some(out)
}

pub fn is_response(packet: &[u8]) -> bool {
    parse_header(packet)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    write_u16(out, 0);
    Ok(())
}

fn encode_null_record(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), DnsError> {
    use crate::types::CLASS_IN;
    out.push(0); // root name
    write_u16(out, RR_NULL);
    write_u16(out, CLASS_IN);
    write_u32(out, 0); // TTL
    write_u16(out, payload.len() as u16);
    out.extend_from_slice(payload);
    Ok(())
}

/// Scan the additional section of a query for a NULL record and return its
/// RDATA as the upstream payload.  Returns `None` when no NULL record is found
/// (which means the caller should fall back to QNAME-based decoding).
fn scan_additional_null(packet: &[u8], mut offset: usize, arcount: u16) -> Option<Vec<u8>> {
    for _ in 0..arcount {
        let (rr_type, rdata, next) = parse_rr(packet, offset)?;
        // Safety: ensure the parser is making forward progress to
        // prevent infinite loops on malformed packets.
        if next <= offset {
            return None;
        }
        // Ignore empty NULL records so we fall back to QNAME-based decoding
        // when a zero-length record is present (e.g. malformed query).
        if rr_type == RR_NULL && !rdata.is_empty() {
            return Some(rdata.to_vec());
        }
        offset = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{decode_query, encode_query, encode_response};
    use crate::types::{
        QueryParams, Question, ResponseParams, CLASS_IN, DEFAULT_PAYLOAD_LIMIT, RR_NULL,
    };

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_NULL,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; DEFAULT_PAYLOAD_LIMIT + 1];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        assert!(encode_response(&params).is_err());
    }

    #[test]
    fn encode_response_accepts_max_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_NULL,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; DEFAULT_PAYLOAD_LIMIT];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        assert!(encode_response(&params).is_ok());
    }

    #[test]
    fn encode_query_with_null_payload_roundtrips() {
        let domain = "test.com";
        let payload = vec![0xABu8; 500];
        let qname = format!("AA.{}.", domain);
        let params = QueryParams {
            id: 0x1234,
            qname: &qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: Some(&payload),
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        let packet = encode_query(&params).expect("encode");
        let decoded = decode_query(&packet, domain).expect("decode");
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.id, 0x1234);
    }

    #[test]
    fn encode_query_with_max_null_payload() {
        let domain = "test.com";
        let payload = vec![0xFFu8; DEFAULT_PAYLOAD_LIMIT];
        let qname = format!("BB.{}.", domain);
        let params = QueryParams {
            id: 0x5678,
            qname: &qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: Some(&payload),
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        let packet = encode_query(&params).expect("encode");
        let decoded = decode_query(&packet, domain).expect("decode");
        assert_eq!(decoded.payload.len(), DEFAULT_PAYLOAD_LIMIT);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn encode_query_rejects_oversized_null_payload() {
        let domain = "test.com";
        let payload = vec![0u8; DEFAULT_PAYLOAD_LIMIT + 1];
        let qname = format!("CC.{}.", domain);
        let params = QueryParams {
            id: 0x0001,
            qname: &qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: Some(&payload),
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        assert!(encode_query(&params).is_err());
    }

    #[test]
    fn encode_query_without_payload_is_backward_compatible() {
        // When payload is None, ARCOUNT should be 1 (OPT only).
        let qname = "AA.test.com.";
        let params = QueryParams {
            id: 0x0001,
            qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: None,
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        let packet = encode_query(&params).expect("encode");
        // ARCOUNT at offset 10-11 should be 1
        assert_eq!(packet[10], 0x00);
        assert_eq!(packet[11], 0x01);
    }

    #[test]
    fn encode_query_with_payload_has_arcount_two() {
        let payload = vec![0xAB; 10];
        let qname = "AA.test.com.";
        let params = QueryParams {
            id: 0x0001,
            qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: Some(&payload),
            max_payload_len: DEFAULT_PAYLOAD_LIMIT,
        };
        let packet = encode_query(&params).expect("encode");
        // ARCOUNT at offset 10-11 should be 2
        assert_eq!(packet[10], 0x00);
        assert_eq!(packet[11], 0x02);
    }

    #[test]
    fn encode_query_respects_custom_payload_limit() {
        let domain = "test.com";
        let payload = vec![0xABu8; 500];
        let qname = format!("AA.{}.", domain);

        // Should succeed with limit of 500
        let params = QueryParams {
            id: 0x1234,
            qname: &qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: Some(&payload),
            max_payload_len: 500,
        };
        assert!(encode_query(&params).is_ok());

        // Should fail with limit of 499
        let params = QueryParams {
            id: 0x1234,
            qname: &qname,
            qtype: RR_NULL,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
            payload: Some(&payload),
            max_payload_len: 499,
        };
        assert!(encode_query(&params).is_err());
    }

    #[test]
    fn encode_response_respects_custom_payload_limit() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_NULL,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; 500];

        // Should succeed with limit of 500
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
            max_payload_len: 500,
        };
        assert!(encode_response(&params).is_ok());

        // Should fail with limit of 499
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
            max_payload_len: 499,
        };
        assert!(encode_response(&params).is_err());
    }
}
