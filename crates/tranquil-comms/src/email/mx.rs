use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use hickory_resolver::proto::op::ResponseCode;
use rand::seq::SliceRandom;

use super::types::{EmailDomain, MxHost, MxPriority, MxRecord};
use crate::sender::SendError;

pub async fn resolve(
    resolver: &TokioAsyncResolver,
    domain: &EmailDomain,
) -> Result<Vec<MxRecord>, SendError> {
    match resolver.mx_lookup(domain.as_str()).await {
        Ok(lookup) => interpret_lookup(
            lookup
                .iter()
                .map(|mx| (mx.preference(), mx.exchange().clone())),
            domain,
        ),
        Err(e) => classify_lookup_error(e, domain),
    }
}

fn interpret_lookup(
    items: impl IntoIterator<Item = (u16, hickory_resolver::Name)>,
    domain: &EmailDomain,
) -> Result<Vec<MxRecord>, SendError> {
    let entries: Vec<_> = items.into_iter().collect();
    match entries.iter().any(|(_, name)| name.is_root()) {
        true => Err(SendError::DnsPermanent(format!(
            "null MX record at {}: domain refuses mail",
            domain.as_str()
        ))),
        false => {
            let records: Vec<MxRecord> = entries
                .into_iter()
                .filter_map(|(prio, name)| {
                    MxHost::parse(&name.to_utf8()).ok().map(|host| MxRecord {
                        priority: MxPriority::new(prio),
                        host,
                    })
                })
                .collect();
            match records.is_empty() {
                true => implicit_mx(domain),
                false => Ok(prioritize(records)),
            }
        }
    }
}

fn prioritize(mut records: Vec<MxRecord>) -> Vec<MxRecord> {
    records.shuffle(&mut rand::thread_rng());
    records.sort_by_key(|r| r.priority);
    records
}

fn classify_lookup_error(
    e: ResolveError,
    domain: &EmailDomain,
) -> Result<Vec<MxRecord>, SendError> {
    match e.kind() {
        ResolveErrorKind::NoRecordsFound { response_code, .. } => match *response_code {
            ResponseCode::NoError => implicit_mx(domain),
            ResponseCode::NXDomain => Err(SendError::DnsPermanent(format!(
                "domain {} does not exist",
                domain.as_str()
            ))),
            other => Err(SendError::DnsTransient(format!(
                "MX lookup for {} failed with {other}",
                domain.as_str()
            ))),
        },
        _ => Err(SendError::DnsTransient(e.to_string())),
    }
}

fn implicit_mx(domain: &EmailDomain) -> Result<Vec<MxRecord>, SendError> {
    MxHost::parse(domain.as_str())
        .map(|host| {
            vec![MxRecord {
                priority: MxPriority::new(0),
                host,
            }]
        })
        .map_err(|e| SendError::DnsPermanent(format!("invalid recipient domain: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(prio: u16, host: &str) -> MxRecord {
        MxRecord {
            priority: MxPriority::new(prio),
            host: MxHost::parse(host).unwrap(),
        }
    }

    #[test]
    fn prioritize_sorts_by_priority_ascending() {
        let result = prioritize(vec![
            record(20, "mx2.nel.pet"),
            record(10, "mx1.nel.pet"),
            record(10, "mx1b.nel.pet"),
        ]);
        assert_eq!(result[0].priority.as_u16(), 10);
        assert_eq!(result[1].priority.as_u16(), 10);
        assert_eq!(result[2].priority.as_u16(), 20);
    }

    #[test]
    fn prioritize_randomizes_equal_priority_order() {
        let attempts: Vec<Vec<String>> = (0..200)
            .map(|_| {
                prioritize(vec![
                    record(10, "a.nel.pet"),
                    record(10, "b.nel.pet"),
                    record(10, "c.nel.pet"),
                    record(10, "d.nel.pet"),
                ])
                .into_iter()
                .map(|r| r.host.as_str().to_string())
                .collect()
            })
            .collect();
        let distinct: std::collections::HashSet<_> = attempts.iter().cloned().collect();
        assert!(
            distinct.len() > 1,
            "equal-priority MX order should vary across calls; got only {}",
            distinct.len()
        );
    }

    #[test]
    fn implicit_mx_uses_domain_as_host() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let result = implicit_mx(&d).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].priority.as_u16(), 0);
        assert_eq!(result[0].host.as_str(), "nel.pet");
    }

    #[test]
    fn no_error_response_yields_implicit_mx() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let err = ResolveError::from(ResolveErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::default()),
            soa: None,
            negative_ttl: None,
            response_code: ResponseCode::NoError,
            trusted: false,
        });
        let result = classify_lookup_error(err, &d).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host.as_str(), "nel.pet");
    }

    #[test]
    fn nxdomain_response_is_permanent() {
        let d = EmailDomain::parse("does-not-exist.invalid").unwrap();
        let err = ResolveError::from(ResolveErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::default()),
            soa: None,
            negative_ttl: None,
            response_code: ResponseCode::NXDomain,
            trusted: true,
        });
        match classify_lookup_error(err, &d) {
            Err(SendError::DnsPermanent(_)) => {}
            other => panic!("expected DnsPermanent, got {other:?}"),
        }
    }

    #[test]
    fn servfail_response_is_transient() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let err = ResolveError::from(ResolveErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::default()),
            soa: None,
            negative_ttl: None,
            response_code: ResponseCode::ServFail,
            trusted: false,
        });
        match classify_lookup_error(err, &d) {
            Err(SendError::DnsTransient(_)) => {}
            other => panic!("expected DnsTransient, got {other:?}"),
        }
    }

    #[test]
    fn timeout_is_transient() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let err = ResolveError::from(ResolveErrorKind::Timeout);
        match classify_lookup_error(err, &d) {
            Err(SendError::DnsTransient(_)) => {}
            other => panic!("expected DnsTransient, got {other:?}"),
        }
    }

    #[test]
    fn message_variant_is_transient() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let err = ResolveError::from(ResolveErrorKind::Message("transient resolver glitch"));
        match classify_lookup_error(err, &d) {
            Err(SendError::DnsTransient(_)) => {}
            other => panic!("expected DnsTransient default, got {other:?}"),
        }
    }

    #[test]
    fn null_mx_is_permanent() {
        let d = EmailDomain::parse("nomail.nel.pet").unwrap();
        let result = interpret_lookup(vec![(0, hickory_resolver::Name::root())], &d);
        match result {
            Err(SendError::DnsPermanent(msg)) => {
                assert!(msg.contains("null MX"), "msg: {msg}")
            }
            other => panic!("expected DnsPermanent, got {other:?}"),
        }
    }

    #[test]
    fn null_mx_alongside_real_records_still_permanent() {
        let d = EmailDomain::parse("mixed.nel.pet").unwrap();
        let real = hickory_resolver::Name::from_ascii("mx1.nel.pet.").unwrap();
        let result = interpret_lookup(vec![(10, real), (0, hickory_resolver::Name::root())], &d);
        assert!(matches!(result, Err(SendError::DnsPermanent(_))));
    }

    #[test]
    fn empty_lookup_uses_implicit_mx() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let result = interpret_lookup(Vec::<(u16, hickory_resolver::Name)>::new(), &d).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host.as_str(), "nel.pet");
    }

    #[test]
    fn valid_records_pass_through_with_priority_sort() {
        let d = EmailDomain::parse("nel.pet").unwrap();
        let mx1 = hickory_resolver::Name::from_ascii("mx1.nel.pet.").unwrap();
        let mx2 = hickory_resolver::Name::from_ascii("mx2.nel.pet.").unwrap();
        let result = interpret_lookup(vec![(20, mx2), (10, mx1)], &d).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].priority.as_u16(), 10);
        assert_eq!(result[0].host.as_str(), "mx1.nel.pet");
        assert_eq!(result[1].priority.as_u16(), 20);
    }
}
