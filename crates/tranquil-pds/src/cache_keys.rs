pub fn session_key(did: &str, jti: &str) -> String {
    format!("auth:session:{}:{}", did, jti)
}

pub fn signing_key_key(did: &str) -> String {
    format!("auth:key:{}", did)
}

pub fn user_status_key(did: &str) -> String {
    format!("auth:status:{}", did)
}

pub fn handle_key(handle: &str) -> String {
    format!("handle:{}", handle)
}

pub fn reauth_key(did: &str) -> String {
    format!("reauth:{}", did)
}

pub fn plc_doc_key(did: &str) -> String {
    format!("plc:doc:{}", did)
}

pub fn plc_data_key(did: &str) -> String {
    format!("plc:data:{}", did)
}

pub fn email_update_key(did: &str) -> String {
    format!("email_update:{}", did)
}

pub fn scope_ref_key(cid: &str) -> String {
    format!("scope_ref:{}", cid)
}

pub fn auto_verify_sent_key(did: &str) -> String {
    format!("auto_verify_sent:{}", did)
}
