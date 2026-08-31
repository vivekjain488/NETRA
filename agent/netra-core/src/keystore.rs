//! Local protection of the device private key.
//!
//! # Development vs hardware-backed identity (spec §11)
//!
//! - **Software** — the key is stored in a file readable only by the account
//!   the agent runs as. This is the *development* device identity. It protects
//!   against another user on the machine; it does not protect against an
//!   attacker who already has the agent's own privileges.
//! - **Windows DPAPI** — the key is additionally encrypted with a key derived
//!   from the machine, so a copied file is useless on another host.
//! - **TPM / Windows certificate store** — not implemented. The trait exists so
//!   these can be added without changing any caller.
//!
//! The distinction is reported to the backend as `key_protection` and is a
//! genuine input to device trust, so a software-backed key is never presented
//! as equivalent to a hardware-backed one.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// Errors produced while storing or loading key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("key store i/o failed: {0}")]
    Io(#[from] io::Error),
    #[error("stored key is corrupt: {0}")]
    Corrupt(String),
    #[error("platform key protection failed: {0}")]
    Platform(String),
}

/// How the private key is protected at rest. The value is reported to the
/// backend verbatim as `key_protection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Software,
    WindowsDpapi,
}

impl Protection {
    /// The value the enrollment API expects.
    ///
    /// DPAPI reports as `windows-cert-store` because that is the vocabulary
    /// the backend schema defines for platform-protected keys; it is not a
    /// claim that the certificate store itself is in use.
    pub fn as_api_value(self) -> &'static str {
        match self {
            Protection::Software => "software",
            Protection::WindowsDpapi => "windows-cert-store",
        }
    }
}

/// Local storage for the device private key.
pub trait KeyStore {
    /// Persists secret key bytes, replacing anything already stored.
    fn store(&self, secret: &[u8]) -> Result<(), KeyStoreError>;
    /// Loads the stored secret, or `None` if the device is not yet enrolled.
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
    /// Removes the stored key.
    fn clear(&self) -> Result<(), KeyStoreError>;
    /// How this store protects the key at rest.
    fn protection(&self) -> Protection;
}

/// Returns the platform key store for this build.
pub fn default_key_store(state_dir: PathBuf) -> Box<dyn KeyStore> {
    #[cfg(windows)]
    {
        Box::new(windows_dpapi::DpapiKeyStore::new(state_dir))
    }
    #[cfg(not(windows))]
    {
        Box::new(FileKeyStore::new(state_dir))
    }
}

/// A key stored as a file readable only by the agent's own account.
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// Creates a store rooted at the given state directory.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("device.key")
    }
}

impl KeyStore for FileKeyStore {
    fn store(&self, secret: &[u8]) -> Result<(), KeyStoreError> {
        write_private_file(&self.dir, &self.key_path(), secret)
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        read_optional(&self.key_path())
    }

    fn clear(&self) -> Result<(), KeyStoreError> {
        remove_if_present(&self.key_path())
    }

    fn protection(&self) -> Protection {
        Protection::Software
    }
}

/// Writes a file containing key material with owner-only permissions.
///
/// The permissions are set at creation rather than afterwards: creating a
/// world-readable file and narrowing it later leaves a window in which the key
/// is exposed.
fn write_private_file(dir: &Path, path: &Path, contents: &[u8]) -> Result<(), KeyStoreError> {
    fs::create_dir_all(dir)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        // On Windows the file inherits the ACL of the state directory, which
        // lives under the agent account's local application data. DPAPI, not
        // file permissions, is what protects the contents there.
        fs::write(path, contents)?;
    }

    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(KeyStoreError::Io(err)),
    }
}

fn remove_if_present(path: &Path) -> Result<(), KeyStoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(KeyStoreError::Io(err)),
    }
}

/// Windows key protection using DPAPI.
///
/// **UNTESTED.** This compiles only under `cfg(windows)` and has not been run
/// on Windows hardware. Do not describe it as working until it has been.
///
/// `CryptProtectData` is called with `CRYPTPROTECT_LOCAL_MACHINE` unset, so the
/// ciphertext is bound to the user account the agent runs as: a copy of the
/// file is useless both on another machine and under another account.
#[cfg(windows)]
mod windows_dpapi {
    use super::*;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    pub struct DpapiKeyStore {
        dir: PathBuf,
    }

    impl DpapiKeyStore {
        pub fn new(dir: PathBuf) -> Self {
            Self { dir }
        }

        fn key_path(&self) -> PathBuf {
            self.dir.join("device.key.dpapi")
        }
    }

    impl KeyStore for DpapiKeyStore {
        fn store(&self, secret: &[u8]) -> Result<(), KeyStoreError> {
            let protected = protect(secret)?;
            write_private_file(&self.dir, &self.key_path(), &protected)
        }

        fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
            match read_optional(&self.key_path())? {
                None => Ok(None),
                Some(protected) => Ok(Some(unprotect(&protected)?)),
            }
        }

        fn clear(&self) -> Result<(), KeyStoreError> {
            remove_if_present(&self.key_path())
        }

        fn protection(&self) -> Protection {
            Protection::WindowsDpapi
        }
    }

    /// Copies a DPAPI output blob into owned memory and frees the OS buffer.
    ///
    /// # Safety
    /// `blob` must be an output blob populated by DPAPI, whose `pbData` was
    /// allocated by the OS and has not yet been freed.
    unsafe fn take_blob(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize);
        let owned = slice.to_vec();
        let _ = LocalFree(HLOCAL(blob.pbData as *mut _));
        owned
    }

    fn protect(plaintext: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: `input` points at a live slice for the duration of the call,
        // and `output` is populated by the OS and freed by `take_blob`.
        unsafe {
            CryptProtectData(&input, None, None, None, None, 0, &mut output)
                .map_err(|e| KeyStoreError::Platform(format!("CryptProtectData: {e}")))?;
            Ok(take_blob(output))
        }
    }

    fn unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: as above.
        unsafe {
            CryptUnprotectData(&input, None, None, None, None, 0, &mut output).map_err(|e| {
                KeyStoreError::Corrupt(format!(
                    "CryptUnprotectData failed; the key may belong to another account or machine: {e}"
                ))
            })?;
            Ok(Zeroizing::new(take_blob(output)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netra-keystore-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn stores_and_loads_a_key() {
        let dir = temp_dir("roundtrip");
        let store = FileKeyStore::new(dir.clone());
        let secret = [7u8; 32];

        assert!(store.load().expect("load before store").is_none());
        store.store(&secret).expect("store");

        let loaded = store.load().expect("load").expect("key is present");
        assert_eq!(loaded.as_slice(), &secret);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_key_is_not_an_error() {
        // A fresh install has no key; that is the normal pre-enrollment state,
        // not a failure.
        let dir = temp_dir("absent");
        assert!(FileKeyStore::new(dir).load().expect("load").is_none());
    }

    #[test]
    fn clear_removes_the_key_and_is_idempotent() {
        let dir = temp_dir("clear");
        let store = FileKeyStore::new(dir.clone());
        store.store(&[1u8; 32]).expect("store");

        store.clear().expect("clear");
        assert!(store.load().expect("load").is_none());
        store.clear().expect("clearing twice is not an error");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrites_an_existing_key() {
        let dir = temp_dir("overwrite");
        let store = FileKeyStore::new(dir.clone());

        store.store(&[1u8; 32]).expect("first store");
        store.store(&[2u8; 32]).expect("second store");

        let loaded = store.load().expect("load").expect("present");
        assert_eq!(loaded.as_slice(), &[2u8; 32]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("perms");
        let store = FileKeyStore::new(dir.clone());
        store.store(&[3u8; 32]).expect("store");

        let mode = fs::metadata(dir.join("device.key"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key file mode is {mode:o}, want 600");

        let dir_mode = fs::metadata(&dir).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "state directory mode is {dir_mode:o}, want 700");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn protection_reports_the_api_value() {
        assert_eq!(Protection::Software.as_api_value(), "software");
        assert_eq!(Protection::WindowsDpapi.as_api_value(), "windows-cert-store");
    }
}
