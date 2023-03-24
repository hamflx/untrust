use std::{
    ffi::{c_void, CString},
    slice::from_raw_parts,
};

use chrono::Local;
use clap::{Parser, Subcommand};
use picky::x509::pkcs7::ctl::{http_fetch::CtlHttpFetch, CertificateTrustList};
use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
    CertDuplicateCertificateContext, CertEnumCertificatesInStore,
    CertGetCertificateContextProperty, CertGetNameStringA, CertOpenStore, CertSaveStore,
    CryptHashCertificate, ALG_CLASS_HASH, ALG_SID_SHA1, CERT_CONTEXT, CERT_NAME_ISSUER_FLAG,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
    CERT_SIGN_HASH_CNG_ALG_PROP_ID, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_A, CERT_STORE_SAVE_AS_PKCS7,
    CERT_STORE_SAVE_TO_FILENAME_A, HCERTSTORE, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};

const CERT_SYSTEM_STORE_CURRENT_USER: CERT_OPEN_STORE_FLAGS = CERT_OPEN_STORE_FLAGS(0x00010000);
const CERT_SYSTEM_STORE_LOCAL_MACHINE: CERT_OPEN_STORE_FLAGS = CERT_OPEN_STORE_FLAGS(0x00020000);

fn to_hex_string(bytes: &[u8], join_space: bool) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    match (join_space, bytes) {
        (true, [rest @ .., last]) => {
            for ch in rest {
                hex.push_str(&format!("{:02X} ", *ch));
            }
            hex.push_str(&format!("{:02X}", *last));
        }
        _ => {
            for ch in &bytes[..bytes.len() - 1] {
                hex.push_str(&format!("{:02X}", *ch));
            }
        }
    }
    hex
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: UntrustCommand,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum UntrustCommand {
    Clean,
    Check,
    Dump,
}

fn main() {
    let delete = Args::parse().command == UntrustCommand::Clean;
    let dump = Args::parse().command == UntrustCommand::Dump;

    let mut trusted_certs_hash = Vec::new();
    let ctl = CertificateTrustList::fetch().unwrap();
    let ctl_cert_list = ctl.ctl_entries().unwrap();
    trusted_certs_hash.reserve(ctl_cert_list.len());
    for entry in ctl_cert_list {
        trusted_certs_hash.push(entry.cert_fingerprint.to_vec());
    }

    let stores = [
        (CertStore::from_user_root().unwrap(), "backup-user"),
        (
            CertStore::from_local_machine_root().unwrap(),
            "backup-local_machine",
        ),
    ];
    for (store, path) in stores.iter() {
        println!("{}:", store.name());
        let mut has_changes = false;
        let backup_store = CertStore::from_memory().unwrap();

        for cert in store.list_certs() {
            let encoded_cert = cert.encoded_cert();
            let Ok(hash) = cert.hash() else {
                eprintln!("Failed to get cert hash");
                continue;
            };
            if !trusted_certs_hash.contains(&hash) {
                let cert_name = cert.name().unwrap_or_else(|err| format!("Err({})", err));
                let cert_issuer = cert.issuer().unwrap_or_else(|err| format!("Err({})", err));
                let serial_number = cert.serial_number().unwrap_or_default();
                let algorithm = cert.algorithm().unwrap_or_default();

                println!("    {}", cert_name);
                println!("        Cert Issuer:   {}", cert_issuer);
                println!(
                    "        Serial Number: {}",
                    to_hex_string(serial_number, true)
                );
                println!("        Thumbprint:    {}", to_hex_string(&hash, false));
                println!("        Algorithm:     {}", algorithm);

                if delete || dump {
                    if let Err(err) = backup_store.add_cert(encoded_cert) {
                        eprintln!("Failed to add cert to backup store: {}", err);
                        continue;
                    }
                    has_changes = true;
                }
                if delete {
                    if let Err(err) = cert.duplicate().delete() {
                        eprintln!("Failed to delete cert from store: {}", err);
                    }
                }
            }
        }

        if has_changes {
            let full_path = format!("{}-{}", path, Local::now().format("%Y%m%d%H%M%S"));
            backup_store.save(&full_path);
        }
    }
}

struct CertStore(HCERTSTORE, String);

impl CertStore {
    fn name(&self) -> &str {
        self.1.as_str()
    }

    fn from_memory() -> Result<Self, std::io::Error> {
        Ok(Self(
            unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_MEMORY,
                    CERT_QUERY_ENCODING_TYPE::default(),
                    HCRYPTPROV_LEGACY::default(),
                    CERT_OPEN_STORE_FLAGS::default(),
                    None,
                )?
            },
            "MEM".into(),
        ))
    }

    fn from_system(
        flags: CERT_OPEN_STORE_FLAGS,
        store: &[u8],
        name: String,
    ) -> Result<Self, std::io::Error> {
        Ok(Self(
            unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_A,
                    CERT_QUERY_ENCODING_TYPE::default(),
                    HCRYPTPROV_LEGACY::default(),
                    flags,
                    Some(store.as_ptr() as *const c_void),
                )?
            },
            name,
        ))
    }

    fn from_local_machine_root() -> Result<Self, std::io::Error> {
        Self::from_system(
            CERT_OPEN_STORE_FLAGS(
                CERT_SYSTEM_STORE_LOCAL_MACHINE.0 | CERT_STORE_OPEN_EXISTING_FLAG.0,
            ),
            b"Root\0",
            "LocalMachine/Root".into(),
        )
    }

    fn from_user_root() -> Result<Self, std::io::Error> {
        Self::from_system(
            CERT_OPEN_STORE_FLAGS(
                CERT_SYSTEM_STORE_CURRENT_USER.0 | CERT_STORE_OPEN_EXISTING_FLAG.0,
            ),
            b"Root\0",
            "User/Root".into(),
        )
    }

    fn list_certs(&self) -> CertsIter {
        CertsIter(self, None)
    }

    fn add_cert(&self, encoded_cert: &[u8]) -> Result<(), std::io::Error> {
        match unsafe {
            CertAddEncodedCertificateToStore(
                self.0,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                encoded_cert,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
        }
        .as_bool()
        {
            true => Ok(()),
            false => Err(std::io::Error::last_os_error()),
        }
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

impl Drop for CertStore {
    fn drop(&mut self) {
        debug_assert!(unsafe { CertCloseStore(self.0, 0) }.as_bool());
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
        self.get_name_string(0)
    }

    fn issuer(&self) -> Result<String, &'static str> {
        self.get_name_string(CERT_NAME_ISSUER_FLAG)
    }

    fn algorithm(&self) -> Result<String, String> {
        let mut buffer_size = 0;
        if !unsafe {
            CertGetCertificateContextProperty(
                self.0,
                CERT_SIGN_HASH_CNG_ALG_PROP_ID,
                None,
                &mut buffer_size,
            )
        }
        .as_bool()
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut buffer = vec![0u16; (buffer_size / 2) as usize];
        if !unsafe {
            CertGetCertificateContextProperty(
                self.0,
                CERT_SIGN_HASH_CNG_ALG_PROP_ID,
                Some(buffer.as_mut_ptr() as *mut c_void),
                &mut buffer_size,
            )
        }
        .as_bool()
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        String::from_utf16(&buffer).map_err(|err| format!("String::from_utf8 error: {}", err))
    }

    fn get_name_string(&self, flags: u32) -> Result<String, &'static str> {
        let mut cert_name = [0; 4096];
        let bytes = unsafe {
            CertGetNameStringA(
                self.0,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
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
            .map_err(|_| "CString::from_vec_with_nul error")?
            .to_str()
            .map_err(|_| "CString::to_str error")?
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

    fn delete(self) -> Result<(), std::io::Error> {
        match unsafe { CertDeleteCertificateFromStore(self.0) }.as_bool() {
            true => Ok(()),
            false => Err(std::io::Error::last_os_error()),
        }
    }

    fn serial_number(&self) -> Result<&[u8], &'static str> {
        let serial_number = unsafe {
            (*self.0)
                .pCertInfo
                .as_ref()
                .ok_or("no cert info")?
                .SerialNumber
        };
        Ok(unsafe { from_raw_parts(serial_number.pbData, serial_number.cbData as _) })
    }

    fn duplicate(&self) -> Self {
        let ptr = unsafe { CertDuplicateCertificateContext(Some(self.0)) };
        if ptr.is_null() {
            panic!("dup error");
        }
        Self(ptr)
    }
}
