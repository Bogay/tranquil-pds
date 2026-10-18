# Changelog

## 0.7.0

### Breaking changes

- Tranquil no longer uses the AWS crates for S3 support, instead using a pure S3 crate. This means you must pass `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` on start up to use S3 - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
- `subscribeRepos` is now rate limited, allowing 1 request per minute per IP, with a burst of 5 - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
- Tranquil now enforces a maximum record size of 1MB for the CBOR record. Additionally, a batch of records where the total bytes of the combined commit event surpass 2MB is also rejected. - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)

### Features and noteworthy implementation changes

- Tranquil now produces container images automatically from main, tagging each revision. There's also a `main` tag for those who wish to live dangerously - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
- There's an alpine linux installation guide! - koi.rip (did:plc:b26ewgkrnx3yvsp2cdao3ntu)
- We have CI workflows for test+lint, and tests and compilation is much faster - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
- Support for scrypt passwords is in - oyster.cafe (did:plc:3fwecdnvtcscjnrx2p4n7alz) and scanash.com (did:plc:3i6uzuatdyk7rwfkrybynf5j)
- We now have a "light" LLM policy - oyster.cafe (did:plc:3fwecdnvtcscjnrx2p4n7alz)
- Add notification templates capability for customizing notifications with examples - oyster.cafe (did:plc:3fwecdnvtcscjnrx2p4n7alz) and straiforos.tngl.sh (did:plc:bomby4msfvfsco4rno2yfpg7)

### Bug fixes

- Actually pass the scope's aud with the service fragment - lou.gg (did:plc:w64dlsa4zwjv2wljlvmymldc)
- Handle wildcard + aud in OAuth scopes - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
- During migration, log in to the new PDS by DID and not email - okami.mom (did:plc:3rwz3xfw2crswgifqgc3g7zh)
- A whole series of auth fixes - quilling.dev (did:plc:jrtgsidnmxaen4offglr5lsh)
- Don't ask for a verification code if the account has no email - steffo.eu (did:plc:6l7xbgjswn2oauofpz3xagvg)
- Fix case where iOS client cookies are stripped during OAuth redirect - natalie.sh (did:plc:k644h4rq5bjfzcetgsa6tuby)
- Stop showing clear text password after revoking - hayden.moe (did:plc:puvaym5ytsvejx3rwjrnxhvb)
- Stop buffering streaming blob uploads - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
- Correctly abort multipart uploads on error, prevent leaving incomplete parts in bucket - jola.dev (did:plc:bvraa6gajy4tfr3eh2sisdkr)
