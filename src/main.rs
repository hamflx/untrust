use std::{
    ffi::{c_void, CString},
    slice::from_raw_parts,
};

use picky::x509::pkcs7::ctl::{http_fetch::CtlHttpFetch, CertificateTrustList};
use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertDeleteCertificateFromStore,
    CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertGetNameStringA,
    CertOpenStore, CertSaveStore, CryptHashCertificate, ALG_CLASS_HASH, ALG_SID_SHA1, CERT_CONTEXT,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
    CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_MEMORY,
    CERT_STORE_PROV_SYSTEM_A, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_FILENAME_A, HCERTSTORE,
    HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

const CERT_SYSTEM_STORE_CURRENT_USER: CERT_OPEN_STORE_FLAGS = CERT_OPEN_STORE_FLAGS(0x00010000);
const CERT_SYSTEM_STORE_LOCAL_MACHINE: CERT_OPEN_STORE_FLAGS = CERT_OPEN_STORE_FLAGS(0x00020000);

fn to_hex_string(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for ch in bytes {
        hex.push_str(&format!("{:02X}", *ch));
    }
    hex
}

fn main() {
    let mut trusted_certs_hash = Vec::new();
    let ctl = CertificateTrustList::fetch().unwrap();
    let ctl_cert_list = ctl.ctl_entries().unwrap();
    trusted_certs_hash.reserve(ctl_cert_list.len());
    for entry in ctl_cert_list {
        trusted_certs_hash.push(entry.cert_fingerprint.to_vec());
    }

    let stores = [
        (
            CertStore::from_user_root(),
            CertStore::from_memory(),
            "user",
        ),
        (
            CertStore::from_local_machine_root(),
            CertStore::from_memory(),
            "local_machine",
        ),
    ];
    for (store, backup_store, _) in stores.iter() {
        println!("==> enumerating: {}", store.name());

        for cert in store.list_certs() {
            let encoded_cert = cert.encoded_cert();
            let hash = cert.hash().unwrap();
            if !trusted_certs_hash.contains(&hash) {
                let cert_name = cert.name().unwrap();

                println!(
                    "    cert: {}, fingerprint: {}",
                    cert_name,
                    to_hex_string(&hash)
                );

                if !backup_store.add_cert(encoded_cert) {
                    panic!(
                        "Failed to add cert to store: {:?}",
                        std::io::Error::last_os_error()
                    );
                }

                if cert.duplicate().delete() {
                    eprintln!(
                        "        Failed to delete cert from store: {:?}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }

    stores[0].1.save(stores[0].2);
    stores[1].1.save(stores[1].2);
}

struct CertStore(HCERTSTORE, String);

impl CertStore {
    fn name(&self) -> &str {
        self.1.as_str()
    }

    fn from_memory() -> Self {
        Self(
            unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_MEMORY,
                    CERT_QUERY_ENCODING_TYPE::default(),
                    HCRYPTPROV_LEGACY::default(),
                    CERT_OPEN_STORE_FLAGS::default(),
                    None,
                )
                .unwrap()
            },
            "MEM".into(),
        )
    }

    fn from_system(flags: CERT_OPEN_STORE_FLAGS, name: String) -> Self {
        Self(
            unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_A,
                    CERT_QUERY_ENCODING_TYPE::default(),
                    HCRYPTPROV_LEGACY::default(),
                    flags,
                    Some(b"Root\0".as_ptr() as *const c_void),
                )
                .unwrap()
            },
            name,
        )
    }

    fn from_local_machine_root() -> Self {
        Self::from_system(
            CERT_OPEN_STORE_FLAGS(
                CERT_SYSTEM_STORE_LOCAL_MACHINE.0 | CERT_STORE_OPEN_EXISTING_FLAG.0,
            ),
            "LocalMachine/Root".into(),
        )
    }

    fn from_user_root() -> Self {
        Self::from_system(
            CERT_OPEN_STORE_FLAGS(
                CERT_SYSTEM_STORE_CURRENT_USER.0 | CERT_STORE_OPEN_EXISTING_FLAG.0,
            ),
            "User/Root".into(),
        )
    }

    fn list_certs(&self) -> CertsIter {
        CertsIter(self, None)
    }

    fn add_cert(&self, encoded_cert: &[u8]) -> bool {
        unsafe {
            CertAddEncodedCertificateToStore(
                self.0,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                encoded_cert,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
        }
        .as_bool()
    }

    fn save(&self, path: &str) {
        let path = if path.to_lowercase().ends_with(".p7b") {
            path.into()
        } else {
            String::from(path) + ".p7b"
        };
        let path = CString::new(path).unwrap();
        unsafe {
            CertSaveStore(
                self.0,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                CERT_STORE_SAVE_AS_PKCS7,
                CERT_STORE_SAVE_TO_FILENAME_A,
                path.as_ptr() as *const c_void as *mut c_void,
                0,
            );
        }
    }
}

struct CertsIter<'a>(&'a CertStore, Option<*const CERT_CONTEXT>);

impl<'a> Iterator for CertsIter<'a> {
    type Item = Certificate;

    fn next(&mut self) -> Option<Self::Item> {
        let next_item = unsafe { CertEnumCertificatesInStore(self.0 .0, self.1) };
        self.1 = if next_item.is_null() {
            None
        } else {
            Some(next_item)
        };
        self.1.map(Certificate)
    }
}

struct Certificate(*const CERT_CONTEXT);

impl Certificate {
    fn name(&self) -> Result<String, &'static str> {
        let mut cert_name = [0; 4096];
        let bytes = unsafe {
            CertGetNameStringA(
                self.0,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut cert_name),
            )
        };
        if bytes == 0 {
            return Err("CertGetNameStringA error");
        }
        let mut cert_name: Vec<_> = cert_name.into();
        cert_name.truncate(bytes as _);
        Ok(CString::from_vec_with_nul(cert_name)
            .unwrap()
            .to_str()
            .unwrap()
            .into())
    }

    fn encoded_cert(&self) -> &[u8] {
        unsafe { from_raw_parts((*self.0).pbCertEncoded, (*self.0).cbCertEncoded as _) }
    }

    fn hash(&self) -> Result<Vec<u8>, &'static str> {
        let encoded_cert = self.encoded_cert();
        let mut hash_size = 0;
        if !unsafe {
            CryptHashCertificate(
                HCRYPTPROV_LEGACY::default(),
                ALG_CLASS_HASH | ALG_SID_SHA1,
                0,
                encoded_cert,
                None,
                &mut hash_size,
            )
        }
        .as_bool()
        {
            return Err("hash error");
        }
        let mut buf = vec![0; hash_size as _];
        if !unsafe {
            CryptHashCertificate(
                HCRYPTPROV_LEGACY::default(),
                ALG_CLASS_HASH | ALG_SID_SHA1,
                0,
                encoded_cert,
                Some(buf.as_mut_ptr()),
                &mut hash_size,
            )
        }
        .as_bool()
        {
            return Err("hash error");
        }
        Ok(buf)
    }

    fn delete(self) -> bool {
        unsafe { CertDeleteCertificateFromStore(self.0) }.as_bool()
    }

    fn duplicate(&self) -> Self {
        let ptr = unsafe { CertDuplicateCertificateContext(Some(self.0)) };
        if ptr.is_null() {
            panic!("dup error");
        }
        Self(ptr)
    }
}
