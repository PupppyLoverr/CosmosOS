//! Kernel keyring — real key objects behind SYS_ADD_KEY / SYS_REQUEST_KEY /
//! SYS_KEYCTL. Each key carries owner uid + session id, a type ("user" only),
//! a free-form description, and a payload <= 4KiB. Permissions follow the
//! simple rule Linux applies to the session keyring: only the owner's uid
//! may read/revoke/unlink it.
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub struct Key {
    pub serial: u32,
    pub uid: u32,
    pub sid: u32,
    pub typ: String,
    pub desc: String,
    pub payload: Vec<u8>,
    pub revoked: bool,
}

static KEYS: Mutex<Vec<Key>> = Mutex::new(Vec::new());
static NEXT: Mutex<u32> = Mutex::new(1);

/// add_key(type, desc, payload) -> serial | negative errno.
pub fn add(typ: &str, desc: &str, payload: &[u8]) -> i64 {
    if typ != "user" {
        return -95; // EOPNOTSUPP: no asymmetric/crypto facilities
    }
    if desc.is_empty() || desc.len() > 64 {
        return -22;
    }
    if payload.len() > 4096 {
        return -34;
    }
    let (uid, _) = crate::task::eff_cred();
    let sid = crate::task::cur_sid();
    let mut nx = NEXT.lock();
    let serial = *nx;
    *nx += 1;
    let mut g = KEYS.lock();
    if g.len() >= 256 {
        return -28;
    }
    // same-desc keys replace, like the session keyring
    if let Some(k) = g.iter_mut().find(|k| {
        k.sid == sid && k.typ == typ && k.desc == desc && !k.revoked && k.uid == uid
    }) {
        k.payload.clear();
        k.payload.extend_from_slice(payload);
        return k.serial as i64;
    }
    g.push(Key {
        serial,
        uid,
        sid,
        typ: String::from(typ),
        desc: String::from(desc),
        payload: payload.to_vec(),
        revoked: false,
    });
    serial as i64
}

/// request_key(desc) -> serial | -126 ENOKEY. Searches the caller's
/// session ring, owner-uid keys only (permission-real).
pub fn request(desc: &str) -> i64 {
    let (uid, _) = crate::task::eff_cred();
    let sid = crate::task::cur_sid();
    let g = KEYS.lock();
    g.iter()
        .find(|k| k.sid == sid && k.desc == desc && !k.revoked && k.uid == uid)
        .map(|k| k.serial as i64)
        .unwrap_or(-126)
}

fn with_key<F: FnOnce(&mut Key) -> i64>(serial: u32, f: F) -> i64 {
    let (uid, _) = crate::task::eff_cred();
    let mut g = KEYS.lock();
    let Some(k) = g.iter_mut().find(|k| k.serial == serial) else {
        return -126;
    };
    if k.uid != uid {
        return -13; // EACCES: not the owner
    }
    f(k)
}

/// KEYCTL_READ(serial) -> payload copy | negative.
pub fn read(serial: u32) -> Result<Vec<u8>, i64> {
    let mut out = None;
    let r = with_key(serial, |k| {
        if k.revoked {
            return -128; // EKEYREVOKED
        }
        out = Some(k.payload.clone());
        0
    });
    if r < 0 {
        return Err(r);
    }
    Ok(out.unwrap_or_default())
}

/// KEYCTL_REVOKE(serial) -> 0 | negative. Permanent: requests and reads
/// start failing.
pub fn revoke(serial: u32) -> i64 {
    with_key(serial, |k| {
        k.revoked = true;
        0
    })
}

/// KEYCTL_UNLINK(serial) -> 0 | -126.
pub fn unlink(serial: u32) -> i64 {
    let (uid, _) = crate::task::eff_cred();
    let mut g = KEYS.lock();
    let Some(i) = g.iter().position(|k| k.serial == serial) else {
        return -126;
    };
    if g[i].uid != uid {
        return -13;
    }
    g.remove(i);
    0
}

/// KEYCTL_SEARCH(desc) -> serial | -126. Same lookup as request_key.
pub fn search(desc: &str) -> i64 {
    request(desc)
}
