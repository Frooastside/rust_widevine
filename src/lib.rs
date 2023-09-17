pub mod error;
pub mod license_protocol;

use crate::{
    error::Error,
    license_protocol::{
        license_request::{
            content_identification::{ContentIdVariant, WidevinePsshData},
            ContentIdentification, RequestType,
        },
        signed_message::MessageType,
        ClientIdentification, DrmCertificate, EncryptedClientIdentification, License,
        LicenseRequest, LicenseType, ProtocolVersion,
    },
};
use license_protocol::{SignedDrmCertificate, SignedMessage};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier},
    symm::{decrypt, Cipher},
};
use prost::Message;
use rand::{random, Rng};
use std::time::{SystemTime, UNIX_EPOCH};

pub const WIDEVINE_SYSTEM_ID: [u8; 16] = [
    0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, 0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED,
];

//noinspection SpellCheckingInspection
/// From Signed Root DRM Certificate (CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA==)
pub const WIDEVINE_ROOT_PUBLIC_KEY: [u8; 398] = [
    0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 0x01, 0x81, 0x00, 0xB4, 0xFE, 0x39, 0xC3, 0x65, 0x90, 0x03,
    0xDB, 0x3C, 0x11, 0x97, 0x09, 0xE8, 0x68, 0xCD, 0xF2, 0xC3, 0x5E, 0x9B, 0xF2, 0xE7, 0x4D, 0x23,
    0xB1, 0x10, 0xDB, 0x87, 0x65, 0xDF, 0xDC, 0xFB, 0x9F, 0x35, 0xA0, 0x57, 0x03, 0x53, 0x4C, 0xF6,
    0x6D, 0x35, 0x7D, 0xA6, 0x78, 0xDB, 0xB3, 0x36, 0xD2, 0x3F, 0x9C, 0x40, 0xA9, 0x95, 0x26, 0x72,
    0x7F, 0xB8, 0xBE, 0x66, 0xDF, 0xC5, 0x21, 0x98, 0x78, 0x15, 0x16, 0x68, 0x5D, 0x2F, 0x46, 0x0E,
    0x43, 0xCB, 0x8A, 0x84, 0x39, 0xAB, 0xFB, 0xB0, 0x35, 0x80, 0x22, 0xBE, 0x34, 0x23, 0x8B, 0xAB,
    0x53, 0x5B, 0x72, 0xEC, 0x4B, 0xB5, 0x48, 0x69, 0x53, 0x3E, 0x47, 0x5F, 0xFD, 0x09, 0xFD, 0xA7,
    0x76, 0x13, 0x8F, 0x0F, 0x92, 0xD6, 0x4C, 0xDF, 0xAE, 0x76, 0xA9, 0xBA, 0xD9, 0x22, 0x10, 0xA9,
    0x9D, 0x71, 0x45, 0xD6, 0xD7, 0xE1, 0x19, 0x25, 0x85, 0x9C, 0x53, 0x9A, 0x97, 0xEB, 0x84, 0xD7,
    0xCC, 0xA8, 0x88, 0x82, 0x20, 0x70, 0x26, 0x20, 0xFD, 0x7E, 0x40, 0x50, 0x27, 0xE2, 0x25, 0x93,
    0x6F, 0xBC, 0x3E, 0x72, 0xA0, 0xFA, 0xC1, 0xBD, 0x29, 0xB4, 0x4D, 0x82, 0x5C, 0xC1, 0xB4, 0xCB,
    0x9C, 0x72, 0x7E, 0xB0, 0xE9, 0x8A, 0x17, 0x3E, 0x19, 0x63, 0xFC, 0xFD, 0x82, 0x48, 0x2B, 0xB7,
    0xB2, 0x33, 0xB9, 0x7D, 0xEC, 0x4B, 0xBA, 0x89, 0x1F, 0x27, 0xB8, 0x9B, 0x88, 0x48, 0x84, 0xAA,
    0x18, 0x92, 0x0E, 0x65, 0xF5, 0xC8, 0x6C, 0x11, 0xFF, 0x6B, 0x36, 0xE4, 0x74, 0x34, 0xCA, 0x8C,
    0x33, 0xB1, 0xF9, 0xB8, 0x8E, 0xB4, 0xE6, 0x12, 0xE0, 0x02, 0x98, 0x79, 0x52, 0x5E, 0x45, 0x33,
    0xFF, 0x11, 0xDC, 0xEB, 0xC3, 0x53, 0xBA, 0x7C, 0x60, 0x1A, 0x11, 0x3D, 0x00, 0xFB, 0xD2, 0xB7,
    0xAA, 0x30, 0xFA, 0x4F, 0x5E, 0x48, 0x77, 0x5B, 0x17, 0xDC, 0x75, 0xEF, 0x6F, 0xD2, 0x19, 0x6D,
    0xDC, 0xBE, 0x7F, 0xB0, 0x78, 0x8F, 0xDC, 0x82, 0x60, 0x4C, 0xBF, 0xE4, 0x29, 0x06, 0x5E, 0x69,
    0x8C, 0x39, 0x13, 0xAD, 0x14, 0x25, 0xED, 0x19, 0xB2, 0xF2, 0x9F, 0x01, 0x82, 0x0D, 0x56, 0x44,
    0x88, 0xC8, 0x35, 0xEC, 0x1F, 0x11, 0xB3, 0x24, 0xE0, 0x59, 0x0D, 0x37, 0xE4, 0x47, 0x3C, 0xEA,
    0x4B, 0x7F, 0x97, 0x31, 0x1C, 0x81, 0x7C, 0x94, 0x8A, 0x4C, 0x7D, 0x68, 0x15, 0x84, 0xFF, 0xA5,
    0x08, 0xFD, 0x18, 0xE7, 0xE7, 0x2B, 0xE4, 0x47, 0x27, 0x12, 0x11, 0xB8, 0x23, 0xEC, 0x58, 0x93,
    0x3C, 0xAC, 0x12, 0xD2, 0x88, 0x6D, 0x41, 0x3D, 0xC5, 0xFE, 0x1C, 0xDC, 0xB9, 0xF8, 0xD4, 0x51,
    0x3E, 0x07, 0xE5, 0x03, 0x6F, 0xA7, 0x12, 0xE8, 0x12, 0xF7, 0xB5, 0xCE, 0xA6, 0x96, 0x55, 0x3F,
    0x78, 0xB4, 0x64, 0x82, 0x50, 0xD2, 0x33, 0x5F, 0x91, 0x02, 0x03, 0x01, 0x00, 0x01,
];

pub const SERVICE_CERTIFICATE_CHALLENGE: [u8; 2] = [0x08, 0x04];

pub const COMMON_SERVICE_CERTIFICATE: [u8; 716] = [
    0x08, 0x05, 0x12, 0xC7, 0x05, 0x0A, 0xC1, 0x02, 0x08, 0x03, 0x12, 0x10, 0x17, 0x05, 0xB9, 0x17,
    0xCC, 0x12, 0x04, 0x86, 0x8B, 0x06, 0x33, 0x3A, 0x2F, 0x77, 0x2A, 0x8C, 0x18, 0x82, 0xB4, 0x82,
    0x92, 0x05, 0x22, 0x8E, 0x02, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0x99, 0xED,
    0x5B, 0x3B, 0x32, 0x7D, 0xAB, 0x5E, 0x24, 0xEF, 0xC3, 0xB6, 0x2A, 0x95, 0xB5, 0x98, 0x52, 0x0A,
    0xD5, 0xBC, 0xCB, 0x37, 0x50, 0x3E, 0x06, 0x45, 0xB8, 0x14, 0xD8, 0x76, 0xB8, 0xDF, 0x40, 0x51,
    0x04, 0x41, 0xAD, 0x8C, 0xE3, 0xAD, 0xB1, 0x1B, 0xB8, 0x8C, 0x4E, 0x72, 0x5A, 0x5E, 0x4A, 0x9E,
    0x07, 0x95, 0x29, 0x1D, 0x58, 0x58, 0x40, 0x23, 0xA7, 0xE1, 0xAF, 0x0E, 0x38, 0xA9, 0x12, 0x79,
    0x39, 0x30, 0x08, 0x61, 0x0B, 0x6F, 0x15, 0x8C, 0x87, 0x8C, 0x7E, 0x21, 0xBF, 0xFB, 0xFE, 0xEA,
    0x77, 0xE1, 0x01, 0x9E, 0x1E, 0x57, 0x81, 0xE8, 0xA4, 0x5F, 0x46, 0x26, 0x3D, 0x14, 0xE6, 0x0E,
    0x80, 0x58, 0xA8, 0x60, 0x7A, 0xDC, 0xE0, 0x4F, 0xAC, 0x84, 0x57, 0xB1, 0x37, 0xA8, 0xD6, 0x7C,
    0xCD, 0xEB, 0x33, 0x70, 0x5D, 0x98, 0x3A, 0x21, 0xFB, 0x4E, 0xEC, 0xBD, 0x4A, 0x10, 0xCA, 0x47,
    0x49, 0x0C, 0xA4, 0x7E, 0xAA, 0x5D, 0x43, 0x82, 0x18, 0xDD, 0xBA, 0xF1, 0xCA, 0xDE, 0x33, 0x92,
    0xF1, 0x3D, 0x6F, 0xFB, 0x64, 0x42, 0xFD, 0x31, 0xE1, 0xBF, 0x40, 0xB0, 0xC6, 0x04, 0xD1, 0xC4,
    0xBA, 0x4C, 0x95, 0x20, 0xA4, 0xBF, 0x97, 0xEE, 0xBD, 0x60, 0x92, 0x9A, 0xFC, 0xEE, 0xF5, 0x5B,
    0xBA, 0xF5, 0x64, 0xE2, 0xD0, 0xE7, 0x6C, 0xD7, 0xC5, 0x5C, 0x73, 0xA0, 0x82, 0xB9, 0x96, 0x12,
    0x0B, 0x83, 0x59, 0xED, 0xCE, 0x24, 0x70, 0x70, 0x82, 0x68, 0x0D, 0x6F, 0x67, 0xC6, 0xD8, 0x2C,
    0x4A, 0xC5, 0xF3, 0x13, 0x44, 0x90, 0xA7, 0x4E, 0xEC, 0x37, 0xAF, 0x4B, 0x2F, 0x01, 0x0C, 0x59,
    0xE8, 0x28, 0x43, 0xE2, 0x58, 0x2F, 0x0B, 0x6B, 0x9F, 0x5D, 0xB0, 0xFC, 0x5E, 0x6E, 0xDF, 0x64,
    0xFB, 0xD3, 0x08, 0xB4, 0x71, 0x1B, 0xCF, 0x12, 0x50, 0x01, 0x9C, 0x9F, 0x5A, 0x09, 0x02, 0x03,
    0x01, 0x00, 0x01, 0x3A, 0x14, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x2E, 0x77, 0x69, 0x64,
    0x65, 0x76, 0x69, 0x6E, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x12, 0x80, 0x03, 0xAE, 0x34, 0x73, 0x14,
    0xB5, 0xA8, 0x35, 0x29, 0x7F, 0x27, 0x13, 0x88, 0xFB, 0x7B, 0xB8, 0xCB, 0x52, 0x77, 0xD2, 0x49,
    0x82, 0x3C, 0xDD, 0xD1, 0xDA, 0x30, 0xB9, 0x33, 0x39, 0x51, 0x1E, 0xB3, 0xCC, 0xBD, 0xEA, 0x04,
    0xB9, 0x44, 0xB9, 0x27, 0xC1, 0x21, 0x34, 0x6E, 0xFD, 0xBD, 0xEA, 0xC9, 0xD4, 0x13, 0x91, 0x7E,
    0x6E, 0xC1, 0x76, 0xA1, 0x04, 0x38, 0x46, 0x0A, 0x50, 0x3B, 0xC1, 0x95, 0x2B, 0x9B, 0xA4, 0xE4,
    0xCE, 0x0F, 0xC4, 0xBF, 0xC2, 0x0A, 0x98, 0x08, 0xAA, 0xAF, 0x4B, 0xFC, 0xD1, 0x9C, 0x1D, 0xCF,
    0xCD, 0xF5, 0x74, 0xCC, 0xAC, 0x28, 0xD1, 0xB4, 0x10, 0x41, 0x6C, 0xF9, 0xDE, 0x88, 0x04, 0x30,
    0x1C, 0xBD, 0xB3, 0x34, 0xCA, 0xFC, 0xD0, 0xD4, 0x09, 0x78, 0x42, 0x3A, 0x64, 0x2E, 0x54, 0x61,
    0x3D, 0xF0, 0xAF, 0xCF, 0x96, 0xCA, 0x4A, 0x92, 0x49, 0xD8, 0x55, 0xE4, 0x2B, 0x3A, 0x70, 0x3E,
    0xF1, 0x76, 0x7F, 0x6A, 0x9B, 0xD3, 0x6D, 0x6B, 0xF8, 0x2B, 0xE7, 0x6B, 0xBF, 0x0C, 0xBA, 0x4F,
    0xDE, 0x59, 0xD2, 0xAB, 0xCC, 0x76, 0xFE, 0xB6, 0x42, 0x47, 0xB8, 0x5C, 0x43, 0x1F, 0xBC, 0xA5,
    0x22, 0x66, 0xB6, 0x19, 0xFC, 0x36, 0x97, 0x95, 0x43, 0xFC, 0xA9, 0xCB, 0xBD, 0xBB, 0xFA, 0xFA,
    0x0E, 0x1A, 0x55, 0xE7, 0x55, 0xA3, 0xC7, 0xBC, 0xE6, 0x55, 0xF9, 0x64, 0x6F, 0x58, 0x2A, 0xB9,
    0xCF, 0x70, 0xAA, 0x08, 0xB9, 0x79, 0xF8, 0x67, 0xF6, 0x3A, 0x0B, 0x2B, 0x7F, 0xDB, 0x36, 0x2C,
    0x5B, 0xC4, 0xEC, 0xD5, 0x55, 0xD8, 0x5B, 0xCA, 0xA9, 0xC5, 0x93, 0xC3, 0x83, 0xC8, 0x57, 0xD4,
    0x9D, 0xAA, 0xB7, 0x7E, 0x40, 0xB7, 0x85, 0x1D, 0xDF, 0xD2, 0x49, 0x98, 0x80, 0x8E, 0x35, 0xB2,
    0x58, 0xE7, 0x5D, 0x78, 0xEA, 0xC0, 0xCA, 0x16, 0xF7, 0x04, 0x73, 0x04, 0xC2, 0x0D, 0x93, 0xED,
    0xE4, 0xE8, 0xFF, 0x1C, 0x6F, 0x17, 0xE6, 0x24, 0x3E, 0x3F, 0x3D, 0xA8, 0xFC, 0x17, 0x09, 0x87,
    0x0E, 0xC4, 0x5F, 0xBA, 0x82, 0x3A, 0x26, 0x3F, 0x0C, 0xEF, 0xA1, 0xF7, 0x09, 0x3B, 0x19, 0x09,
    0x92, 0x83, 0x26, 0x33, 0x37, 0x05, 0x04, 0x3A, 0x29, 0xBD, 0xA6, 0xF9, 0xB4, 0x34, 0x2C, 0xC8,
    0xDF, 0x54, 0x3C, 0xB1, 0xA1, 0x18, 0x2F, 0x7C, 0x5F, 0xFF, 0x33, 0xF1, 0x04, 0x90, 0xFA, 0xCA,
    0x5B, 0x25, 0x36, 0x0B, 0x76, 0x01, 0x5E, 0x9C, 0x5A, 0x06, 0xAB, 0x8E, 0xE0, 0x2F, 0x00, 0xD2,
    0xE8, 0xD5, 0x98, 0x61, 0x04, 0xAA, 0xCC, 0x4D, 0xD4, 0x75, 0xFD, 0x96, 0xEE, 0x9C, 0xE4, 0xE3,
    0x26, 0xF2, 0x1B, 0x83, 0xC7, 0x05, 0x85, 0x77, 0xB3, 0x87, 0x32, 0xCD, 0xDA, 0xBC, 0x6A, 0x6B,
    0xED, 0x13, 0xFB, 0x0D, 0x49, 0xD3, 0x8A, 0x45, 0xEB, 0x87, 0xA5, 0xF4,
];

pub struct LicenseDecryptionModule {
    private_key: Rsa<Private>,
    private_key_pkey: PKey<Private>,
    identification_blob: Vec<u8>,
    _vmp_blob: Option<Vec<u8>>,
}

impl LicenseDecryptionModule {
    pub fn new(
        private_key: &Vec<u8>,
        identification_blob: Vec<u8>,
        vmp_blob: Option<Vec<u8>>,
    ) -> LicenseDecryptionModule {
        let private_key: Rsa<Private> = Rsa::private_key_from_pem(private_key).unwrap();
        let pkey: PKey<Private> = PKey::from_rsa(private_key.clone()).unwrap();
        return LicenseDecryptionModule {
            identification_blob,
            private_key,
            private_key_pkey: pkey,
            _vmp_blob: vmp_blob,
        };
    }
}

pub struct KeyContainer {
    pub kid: String,
    pub key: String,
}

pub struct Session {
    pub session_id: Vec<u8>,
    signed_service_certificate: Option<SignedDrmCertificate>,
    raw_license_request: Option<Vec<u8>>,
}

impl Session {
    pub fn new() -> Session {
        return Session {
            session_id: generate_session_token(),
            signed_service_certificate: None,
            raw_license_request: None,
        };
    }

    pub fn set_default_service_certificate(&mut self) -> error::Result<()> {
        return self.set_service_certificate(COMMON_SERVICE_CERTIFICATE.to_vec());
    }

    pub fn set_service_certificate_from_message(
        &mut self,
        signed_message: Vec<u8>,
    ) -> error::Result<()> {
        let signed_message: SignedMessage = SignedMessage::decode(&*signed_message).unwrap();
        return self.set_service_certificate(signed_message.msg().to_vec());
    }

    pub fn set_service_certificate(
        &mut self,
        raw_service_certificate: Vec<u8>,
    ) -> error::Result<()> {
        let signed_service_certificate =
            match SignedDrmCertificate::decode(&*raw_service_certificate) {
                Ok(signed_service_certificate) => signed_service_certificate,
                Err(_error) => {
                    return Err(Error::Input {
                        message: "Provided data is not a signed service certificate.".to_string(),
                    })
                }
            };
        let verified = match verify_service_certificate(&signed_service_certificate) {
            Ok(verified) => verified,
            Err(error) => {
                return Err(Error::OpenSSL {
                    message: "An error occurred while verifying the service certificate"
                        .to_string(),
                    stack: error,
                })
            }
        };
        if !verified {
            return Err(Error::Input {
                message: "".to_string(),
            });
        }
        self.signed_service_certificate = Some(signed_service_certificate);
        return Ok(());
    }

    pub fn create_license_request(
        &mut self,
        ldm: &LicenseDecryptionModule,
        pssh: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        assert_eq!(pssh[12..28], WIDEVINE_SYSTEM_ID);
        check_pssh(&pssh);
        let client_identification: ClientIdentification =
            ClientIdentification::decode(ldm.identification_blob.clone().as_slice()).unwrap();
        let widevine_pssh_data: WidevinePsshData = WidevinePsshData {
            pssh_data: vec![pssh[32..].to_vec()],
            license_type: Some(LicenseType::Streaming.into()),
            request_id: Some(self.session_id.clone()),
        };
        let content: ContentIdentification = ContentIdentification {
            content_id_variant: Some(ContentIdVariant::WidevinePsshData(widevine_pssh_data)),
        };

        let mut license_request: LicenseRequest = LicenseRequest {
            content_id: Some(content),
            r#type: Some(RequestType::New.into()),
            request_time: Some(i64::try_from(current_time()).unwrap()),
            protocol_version: Some(ProtocolVersion::Version21.into()),
            key_control_nonce: Some(random::<u32>()),
            ..Default::default()
        };
        if let Some(signed_service_certificate) = &self.signed_service_certificate {
            let encrypted_client_identification =
                encrypt_client_identification(&client_identification, &signed_service_certificate);
            license_request.encrypted_client_id = Some(encrypted_client_identification);
        } else {
            license_request.client_id = Some(client_identification);
        }

        let raw_license_request: Vec<u8> = license_request.encode_to_vec();
        self.raw_license_request = Some(raw_license_request.clone());

        let mut signer = Signer::new(MessageDigest::sha1(), &ldm.private_key_pkey).unwrap();
        signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::custom(20))
            .unwrap();
        signer.update(&raw_license_request).unwrap();
        let signature: Vec<u8> = signer.sign_to_vec().unwrap();

        let signed_license_request: SignedMessage = SignedMessage {
            r#type: Some(MessageType::LicenseRequest.into()),
            msg: Some(raw_license_request),
            signature: Some(signature),
            ..Default::default()
        };

        return Ok(signed_license_request.encode_to_vec());
    }

    pub fn parse_license(
        self,
        ldm: &LicenseDecryptionModule,
        license: Vec<u8>,
    ) -> error::Result<Vec<KeyContainer>> {
        let signed_message: SignedMessage = SignedMessage::decode(&*license).unwrap();
        let mut decrypted_session_key: Vec<u8> = vec![0; ldm.private_key.size() as usize];
        ldm.private_key
            .private_decrypt(
                signed_message.session_key(),
                &mut decrypted_session_key,
                Padding::PKCS1_OAEP,
            )
            .unwrap();

        let raw_license_request = self.raw_license_request.unwrap();

        let encryption_key_base = vec![
            b"ENCRYPTION\x00".to_vec(),
            raw_license_request.clone(),
            b"\x00\x00\x00\x80".to_vec(),
        ]
        .concat();
        let authentication_key_base = vec![
            b"AUTHENTICATION\x00".to_vec(),
            raw_license_request.clone(),
            b"\x00\x00\x02\x00".to_vec(),
        ]
        .concat();

        let cmac = PKey::cmac(&Cipher::aes_128_cbc(), &decrypted_session_key[0..16]).unwrap();

        let mut cmac_signer = Signer::new_without_digest(&cmac).unwrap();
        cmac_signer
            .update(&vec![b"\x01".to_vec(), encryption_key_base.clone()].concat())
            .unwrap();
        let encryption_key = cmac_signer.sign_to_vec().unwrap();

        let mut cmac_signer = Signer::new_without_digest(&cmac).unwrap();
        cmac_signer
            .update(&vec![b"\x01".to_vec(), authentication_key_base.clone()].concat())
            .unwrap();
        let part_1 = cmac_signer.sign_to_vec().unwrap();

        let mut cmac_signer = Signer::new_without_digest(&cmac).unwrap();
        cmac_signer
            .update(&vec![b"\x02".to_vec(), authentication_key_base.clone()].concat())
            .unwrap();
        let part_2 = cmac_signer.sign_to_vec().unwrap();

        let server_key = vec![part_1, part_2].concat();

        let hmac = PKey::hmac(&server_key).unwrap();
        let mut hmac_signer = Signer::new(MessageDigest::sha256(), &hmac).unwrap();
        hmac_signer.update(signed_message.msg()).unwrap();
        let calculated_signature = hmac_signer.sign_to_vec().unwrap();
        assert_eq!(calculated_signature, signed_message.signature());

        let license: License = License::decode(signed_message.msg()).unwrap();
        let mut key_containers: Vec<KeyContainer> = Vec::new();
        for key_container in license.key {
            let key_id = if key_container.id().len() > 0 {
                hex::encode(key_container.id())
            } else {
                key_container.r#type().as_str_name().to_string()
            };
            let decrypted_key = decrypt(
                Cipher::aes_128_cbc(),
                &encryption_key,
                Some(key_container.iv()),
                key_container.key(),
            )
            .unwrap();
            let decrypted_key = hex::encode(decrypted_key);
            key_containers.push(KeyContainer {
                kid: key_id,
                key: decrypted_key,
            })
        }
        return Ok(key_containers);
    }
}

fn encrypt_client_identification(
    client_identification: &ClientIdentification,
    signed_service_certificate: &SignedDrmCertificate,
) -> EncryptedClientIdentification {
    let key: [u8; 16] = random::<[u8; 16]>();
    let iv: [u8; 16] = random::<[u8; 16]>();
    let service_certificate: DrmCertificate =
        DrmCertificate::decode(signed_service_certificate.drm_certificate()).unwrap();

    let encrypted_client_identification: Vec<u8> = openssl::symm::encrypt(
        Cipher::aes_128_cbc(),
        &key,
        Some(&iv),
        &client_identification.encode_to_vec(),
    )
    .unwrap();
    let public_key: Rsa<openssl::pkey::Public> =
        Rsa::public_key_from_der_pkcs1(service_certificate.public_key()).unwrap();
    let mut encrypted_key: Vec<u8> = vec![0; public_key.size() as usize];
    let length = public_key
        .public_encrypt(&key, &mut encrypted_key, Padding::PKCS1_OAEP)
        .unwrap();
    let encrypted_key: Vec<u8> = encrypted_key[..length].to_vec();

    let encrypted_client_identification: EncryptedClientIdentification =
        EncryptedClientIdentification {
            provider_id: Some(String::from(service_certificate.provider_id())),
            service_certificate_serial_number: Some(service_certificate.serial_number().to_vec()),
            encrypted_client_id: Some(encrypted_client_identification),
            encrypted_privacy_key: Some(encrypted_key),
            encrypted_client_id_iv: Some(iv.to_vec()),
            ..Default::default()
        };
    return encrypted_client_identification;
}

fn verify_service_certificate(
    signed_service_certificate: &SignedDrmCertificate,
) -> Result<bool, openssl::error::ErrorStack> {
    let public_key = Rsa::public_key_from_der_pkcs1(&WIDEVINE_ROOT_PUBLIC_KEY)?;
    let public_key = PKey::from_rsa(public_key)?;
    let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key)?;
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(20))?;
    verifier.update(&signed_service_certificate.drm_certificate())?;
    let verified = verifier.verify(signed_service_certificate.signature())?;
    return Ok(verified);
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_session_token() -> Vec<u8> {
    let random_bytes = random::<[u8; 4]>();
    let token = vec![
        random_bytes.to_vec(),
        b"\x00\x00\x00\x00".to_vec(),
        1_u64.to_le_bytes().to_vec(),
    ]
    .concat();
    return token;
}

fn check_pssh(pssh: &Vec<u8>) -> bool {
    match WidevinePsshData::decode(&pssh[32..]) {
        Ok(_pssh_data) => true,
        Err(_error) => false,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::error::check_request;
    use base64::{engine::general_purpose, Engine as _};
    use crunchyroll_rs::{
        crunchyroll::CrunchyrollBuilder, media::Media, Crunchyroll, Locale, Series,
    };
    use http::header;
    use regex::Regex;
    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use std::{env, fs};

    #[derive(Serialize, Debug)]
    struct AuthParameters {
        accounting_id: String,
        asset_id: String,
        session_id: String,
        user_id: String,
    }

    //noinspection SpellCheckingInspection
    const CRUNCHYROLL_SERVICE_CERTIFICATE: &str = "CrsCCAMSEKDc0WAwLAQT1SB2ogyBJEwYv4Tx7gUijgIwggEKAoIBAQC8Xc/GTRwZDtlnBThq8V382D1oJAM0F/YgCQtNDLz7vTWJ+QskNGi5Dd2qzO4s48Cnx5BLvL4H0xCRSw2Ed6ekHSdrRUwyoYOE+M/t1oIbccwlTQ7o+BpV1X6TB7fxFyx1jsBtRsBWphU65w121zqmSiwzZzJ4xsXVQCJpQnNI61gzHO42XZOMuxytMm0F6puNHTTqhyY3Z290YqvSDdOB+UY5QJuXJgjhvOUD9+oaLlvT+vwmV2/NJWxKqHBKdL9JqvOnNiQUF0hDI7Wf8Wb63RYSXKE27Ky31hKgx1wuq7TTWkA+kHnJTUrTEfQxfPR4dJTquE+IDLAi5yeVVxzbAgMBAAE6DGNhc3RsYWJzLmNvbUABEoADMmGXpXg/0qxUuwokpsqVIHZrJfu62ar+BF8UVUKdK5oYQoiTZd9OzK3kr29kqGGk3lSgM0/p499p/FUL8oHHzgsJ7Hajdsyzn0Vs3+VysAgaJAkXZ+k+N6Ka0WBiZlCtcunVJDiHQbz1sF9GvcePUUi2fM/h7hyskG5ZLAyJMzTvgnV3D8/I5Y6mCFBPb/+/Ri+9bEvquPF3Ff9ip3yEHu9mcQeEYCeGe9zR/27eI5MATX39gYtCnn7dDXVxo4/rCYK0A4VemC3HRai2X3pSGcsKY7+6we7h4IycjqtuGtYg8AbaigovcoURAZcr1d/G0rpREjLdVLG0Gjqk63Gx688W5gh3TKemsK3R1jV0dOfj3e6uV/kTpsNRL9KsD0v7ysBQVdUXEbJotcFz71tI5qc3jwr6GjYIPA3VzusD17PN6AGQniMwxJV12z/EgnUopcFB13osydpD2AaDsgWo5RWJcNf+fzCgtUQx/0Au9+xVm5LQBdv8Ja4f2oiHN3dw";
    //noinspection SpellCheckingInspection
    const CRUNCHYROLL_SAL_S1E1_PSSH: &str = "AAAAoXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIEIARIQmYVDQW4gNdatYCGbY/l5jRoIY2FzdGxhYnMiWGV5SmhjM05sZEVsa0lqb2lZelJqTlRnNE1UUmpORFEwTWpGaVpqRmlObUprTXpka01USm1NVFppWmpjaUxDSjJZWEpwWVc1MFNXUWlPaUpoZG10bGVTSjkyB2RlZmF1bHQ=";
    //noinspection SpellCheckingInspection
    const CRUNCHYROLL_SAL_S1E1_CONTENT_ID: &str = "GJWU2E72X";

    #[tokio::test]
    #[ignore]
    async fn crunchyroll() {
        dotenv::dotenv().unwrap();
        let etp_rt = env::var("etp_rt").unwrap();
        let client = CrunchyrollBuilder::predefined_client_builder()
            .build()
            .unwrap();
        let crunchy = Crunchyroll::builder()
            .locale(Locale::de_DE)
            .client(client)
            .login_with_etp_rt(&etp_rt)
            .await
            .unwrap();
        let demon_slayer = Series::from_id(&crunchy, "G9VHN9185").await.unwrap();
        let seasons = demon_slayer.seasons().await.unwrap();
        let season_1 = seasons
            .iter()
            .find(|season| season.season_number == 1)
            .unwrap();
        let episodes = season_1.episodes().await.unwrap();
        let episode_1 = episodes
            .iter()
            .find(|episode| episode.episode_number == 1)
            .unwrap();
        let stream = episode_1.stream().await.unwrap();
        let variants = stream.variants.get(&Locale::de_DE).unwrap();
        let drm_adaptive_hls = variants.drm_adaptive_hls.as_ref().unwrap();
        let regex = Regex::new(r"/p/(?<asset_id>[a-zA-Z0-9]+)_").unwrap();
        let asset_id = regex
            .captures(drm_adaptive_hls.url.as_str())
            .unwrap()
            .name("asset_id")
            .unwrap()
            .as_str();
        let drm_auth = AuthParameters {
            accounting_id: String::from("crunchyroll"),
            asset_id: String::from(asset_id),
            session_id: format!(
                "{}{}",
                rand::thread_rng().gen_range(0..1000),
                current_time()
            ),
            user_id: crunchy.account().await.unwrap().account_id,
        };

        crunchy
            .client()
            .get("https://www.crunchyroll.com")
            .send()
            .await
            .unwrap();

        let login_response = auth_with_etp_rt(&crunchy.client(), etp_rt.to_string())
            .await
            .unwrap();
        let response = crunchy
            .client()
            .get("https://cr-play-service.prd.crunchyrollsvc.com/v1/GJWU2E72X/web/chrome/play")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", login_response.access_token),
            )
            .send()
            .await
            .unwrap();
        let play_chrome: ChromePlay = check_request(
            String::from(
                "https://cr-play-service.prd.crunchyrollsvc.com/v1/GJWU2E72X/web/chrome/play",
            ),
            response,
        )
        .await
        .unwrap();

        crunchy
            .client()
            .post("https://pl.crunchyroll.com/drm/v1/auth")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", login_response.access_token),
            )
            .body(serde_json::to_string(&drm_auth).unwrap())
            .send()
            .await
            .unwrap();

        let device_client_id_blob =
            fs::read("security/device_client_id_blob").unwrap_or(Vec::new());
        let device_private_key = fs::read("security/device_private_key").unwrap_or(Vec::new());
        assert!(device_client_id_blob.len() > 0, "id blob was not given");
        assert!(device_private_key.len() > 0, "private key was not given");
        let ldm: LicenseDecryptionModule =
            LicenseDecryptionModule::new(&device_private_key, device_client_id_blob, None);

        //PSSH from .mpd search for something like "CENC"...
        let pssh = general_purpose::STANDARD.decode(CRUNCHYROLL_SAL_S1E1_PSSH).unwrap();
        let mut session = Session::new();
        session
            .set_service_certificate(
                general_purpose::STANDARD
                    .decode(CRUNCHYROLL_SERVICE_CERTIFICATE)
                    .unwrap(),
            )
            .unwrap();
        let license_request = session.create_license_request(&ldm, pssh);

        let response = crunchy
            .client()
            .post("https://cr-license-proxy.prd.crunchyrollsvc.com/v1/license/widevine")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", login_response.access_token),
            )
            .header("X-Cr-Content-Id", CRUNCHYROLL_SAL_S1E1_CONTENT_ID)
            .header("X-Cr-Video-Token", play_chrome.token)
            .body(license_request.unwrap())
            .send()
            .await
            .unwrap();

        let license_response: CrunchyLicense = check_request(
            String::from("https://cr-license-proxy.prd.crunchyrollsvc.com/v1/license/widevine"),
            response,
        )
        .await
        .unwrap();

        let key_pairs: Vec<String> = session
            .parse_license(
                &ldm,
                general_purpose::STANDARD
                    .decode(license_response.license)
                    .unwrap(),
            )
            .unwrap()
            .iter()
            .map(|container| format!("{}:{}\n", container.kid, container.key))
            .collect();
        fs::create_dir_all("security").unwrap();
        fs::write("security/crunchy-keys.txt", key_pairs.concat()).unwrap();
    }

    #[derive(Debug, Default, Deserialize)]
    #[allow(dead_code)]
    struct AuthResponse {
        access_token: String,
        /// Is [`None`] if generated via [`Executor::auth_anonymously`].
        refresh_token: Option<String>,
        expires_in: i32,
        token_type: String,
        scope: String,
        country: String,
        /// Is [`None`] if generated via [`Executor::auth_anonymously`].
        account_id: Option<String>,
    }

    async fn auth_with_etp_rt(client: &Client, etp_rt: String) -> error::Result<AuthResponse> {
        let endpoint = "https://www.crunchyroll.com/auth/v1/token";
        let resp = client
            .post(endpoint)
            .header(header::AUTHORIZATION, "Basic bm9haWhkZXZtXzZpeWcwYThsMHE6")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("etp_rt={etp_rt}"))
            /*
             */
            .body(
                serde_urlencoded::to_string([
                    ("grant_type", "etp_rt_cookie"),
                    ("scope", "offline_access"),
                ])
                .unwrap(),
            )
            .send()
            .await?;
        check_request(endpoint.to_string(), resp).await
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CrunchyLicense {
        pub service_version_info: ServiceVersionInfo,
        pub supported_tracks: Vec<SupportedTrack>,
        pub message_type: String,
        pub status: String,
        pub license: String,
        pub platform: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct ServiceVersionInfo {
        pub license_sdk_version: String,
        pub license_service_version: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SupportedTrack {
        #[serde(rename = "type")]
        pub type_field: String,
        pub key_id: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ChromePlay {
        pub audio_locale: String,
        pub bifs: String,
        pub burned_in_locale: String,
        pub captions: Captions,
        pub hard_subs: HardSubs,
        pub session: WatchSession,
        pub subtitles: Subtitles,
        pub token: String,
        pub url: String,
        pub versions: Vec<Version>,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Captions {}

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct HardSubs {
        #[serde(rename = "en-US")]
        pub en_us: HardSub,
        #[serde(rename = "de-DE")]
        pub de_de: HardSub,
        #[serde(rename = "es-419")]
        pub es_419: HardSub,
        #[serde(rename = "es-ES")]
        pub es_es: HardSub,
        #[serde(rename = "fr-FR")]
        pub fr_fr: HardSub,
        #[serde(rename = "it-IT")]
        pub it_it: HardSub,
        #[serde(rename = "pt-BR")]
        pub pt_br: HardSub,
        #[serde(rename = "ru-RU")]
        pub ru_ru: HardSub,
        #[serde(rename = "ar-SA")]
        pub ar_sa: HardSub,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct HardSub {
        pub hlang: String,
        pub url: String,
        pub quality: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WatchSession {
        pub renew_seconds: i64,
        pub no_network_retry_interval_seconds: i64,
        pub no_network_timeout_seconds: i64,
        pub maximum_pause_seconds: i64,
        pub session_expiration_seconds: i64,
        pub uses_stream_limits: bool,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Subtitles {
        #[serde(rename = "en-US")]
        pub en_us: Subtitle,
        #[serde(rename = "de-DE")]
        pub de_de: Subtitle,
        #[serde(rename = "es-419")]
        pub es_419: Subtitle,
        #[serde(rename = "es-ES")]
        pub es_es: Subtitle,
        #[serde(rename = "fr-FR")]
        pub fr_fr: Subtitle,
        #[serde(rename = "it-IT")]
        pub it_it: Subtitle,
        #[serde(rename = "pt-BR")]
        pub pt_br: Subtitle,
        #[serde(rename = "ru-RU")]
        pub ru_ru: Subtitle,
        #[serde(rename = "ar-SA")]
        pub ar_sa: Subtitle,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Subtitle {
        pub format: String,
        pub language: String,
        pub url: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Version {
        pub audio_locale: String,
        pub guid: String,
        pub is_premium_only: bool,
        pub media_guid: String,
        pub original: bool,
        pub season_guid: String,
        pub variant: String,
    }

    //noinspection SpellCheckingInspection
    const BITMOVIN_PSSH_B64: &str = "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==";
    const BITMOVIN_LICENSE_URL: &str = "https://cwip-shaka-proxy.appspot.com/no_auth";

    #[tokio::test]
    #[ignore]
    async fn bitmovin() {
        let device_client_id_blob =
            fs::read("security/device_client_id_blob").unwrap_or(Vec::new());
        let device_private_key = fs::read("security/device_private_key").unwrap_or(Vec::new());
        assert!(device_client_id_blob.len() > 0, "id blob was not given");
        assert!(device_private_key.len() > 0, "private key was not given");
        let ldm: LicenseDecryptionModule =
            LicenseDecryptionModule::new(&device_private_key, device_client_id_blob, None);
        let pssh = general_purpose::STANDARD.decode(BITMOVIN_PSSH_B64).unwrap();
        let mut session = Session::new();

        let client = Client::new();

        let service_certificate = client
            .post(BITMOVIN_LICENSE_URL)
            .body(SERVICE_CERTIFICATE_CHALLENGE.to_vec())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();

        session
            .set_service_certificate_from_message(service_certificate.to_vec())
            .unwrap();

        let license_request = session.create_license_request(&ldm, pssh);

        let license = client
            .post(BITMOVIN_LICENSE_URL)
            .body(license_request.unwrap())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let key_pairs: Vec<String> = session
            .parse_license(&ldm, license.to_vec())
            .unwrap()
            .iter()
            .map(|container| format!("{}:{}\n", container.kid, container.key))
            .collect();
        fs::create_dir_all("security").unwrap();
        fs::write("security/bitmovin-keys.txt", key_pairs.concat()).unwrap();
    }
}
