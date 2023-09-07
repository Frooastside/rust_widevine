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
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WIDEVINE_SYSTEM_ID: [u8; 16] = [
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
];

/// From Signed Root DRM Certificate (CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA==)
pub const WIDEVINE_ROOT_PUBLIC_KEY: [u8; 398] = [
    0x30, 0x82, 0x01, 0x8a, 0x02, 0x82, 0x01, 0x81, 0x00, 0xb4, 0xfe, 0x39, 0xc3, 0x65, 0x90, 0x03,
    0xdb, 0x3c, 0x11, 0x97, 0x09, 0xe8, 0x68, 0xcd, 0xf2, 0xc3, 0x5e, 0x9b, 0xf2, 0xe7, 0x4d, 0x23,
    0xb1, 0x10, 0xdb, 0x87, 0x65, 0xdf, 0xdc, 0xfb, 0x9f, 0x35, 0xa0, 0x57, 0x03, 0x53, 0x4c, 0xf6,
    0x6d, 0x35, 0x7d, 0xa6, 0x78, 0xdb, 0xb3, 0x36, 0xd2, 0x3f, 0x9c, 0x40, 0xa9, 0x95, 0x26, 0x72,
    0x7f, 0xb8, 0xbe, 0x66, 0xdf, 0xc5, 0x21, 0x98, 0x78, 0x15, 0x16, 0x68, 0x5d, 0x2f, 0x46, 0x0e,
    0x43, 0xcb, 0x8a, 0x84, 0x39, 0xab, 0xfb, 0xb0, 0x35, 0x80, 0x22, 0xbe, 0x34, 0x23, 0x8b, 0xab,
    0x53, 0x5b, 0x72, 0xec, 0x4b, 0xb5, 0x48, 0x69, 0x53, 0x3e, 0x47, 0x5f, 0xfd, 0x09, 0xfd, 0xa7,
    0x76, 0x13, 0x8f, 0x0f, 0x92, 0xd6, 0x4c, 0xdf, 0xae, 0x76, 0xa9, 0xba, 0xd9, 0x22, 0x10, 0xa9,
    0x9d, 0x71, 0x45, 0xd6, 0xd7, 0xe1, 0x19, 0x25, 0x85, 0x9c, 0x53, 0x9a, 0x97, 0xeb, 0x84, 0xd7,
    0xcc, 0xa8, 0x88, 0x82, 0x20, 0x70, 0x26, 0x20, 0xfd, 0x7e, 0x40, 0x50, 0x27, 0xe2, 0x25, 0x93,
    0x6f, 0xbc, 0x3e, 0x72, 0xa0, 0xfa, 0xc1, 0xbd, 0x29, 0xb4, 0x4d, 0x82, 0x5c, 0xc1, 0xb4, 0xcb,
    0x9c, 0x72, 0x7e, 0xb0, 0xe9, 0x8a, 0x17, 0x3e, 0x19, 0x63, 0xfc, 0xfd, 0x82, 0x48, 0x2b, 0xb7,
    0xb2, 0x33, 0xb9, 0x7d, 0xec, 0x4b, 0xba, 0x89, 0x1f, 0x27, 0xb8, 0x9b, 0x88, 0x48, 0x84, 0xaa,
    0x18, 0x92, 0x0e, 0x65, 0xf5, 0xc8, 0x6c, 0x11, 0xff, 0x6b, 0x36, 0xe4, 0x74, 0x34, 0xca, 0x8c,
    0x33, 0xb1, 0xf9, 0xb8, 0x8e, 0xb4, 0xe6, 0x12, 0xe0, 0x02, 0x98, 0x79, 0x52, 0x5e, 0x45, 0x33,
    0xff, 0x11, 0xdc, 0xeb, 0xc3, 0x53, 0xba, 0x7c, 0x60, 0x1a, 0x11, 0x3d, 0x00, 0xfb, 0xd2, 0xb7,
    0xaa, 0x30, 0xfa, 0x4f, 0x5e, 0x48, 0x77, 0x5b, 0x17, 0xdc, 0x75, 0xef, 0x6f, 0xd2, 0x19, 0x6d,
    0xdc, 0xbe, 0x7f, 0xb0, 0x78, 0x8f, 0xdc, 0x82, 0x60, 0x4c, 0xbf, 0xe4, 0x29, 0x06, 0x5e, 0x69,
    0x8c, 0x39, 0x13, 0xad, 0x14, 0x25, 0xed, 0x19, 0xb2, 0xf2, 0x9f, 0x01, 0x82, 0x0d, 0x56, 0x44,
    0x88, 0xc8, 0x35, 0xec, 0x1f, 0x11, 0xb3, 0x24, 0xe0, 0x59, 0x0d, 0x37, 0xe4, 0x47, 0x3c, 0xea,
    0x4b, 0x7f, 0x97, 0x31, 0x1c, 0x81, 0x7c, 0x94, 0x8a, 0x4c, 0x7d, 0x68, 0x15, 0x84, 0xff, 0xa5,
    0x08, 0xfd, 0x18, 0xe7, 0xe7, 0x2b, 0xe4, 0x47, 0x27, 0x12, 0x11, 0xb8, 0x23, 0xec, 0x58, 0x93,
    0x3c, 0xac, 0x12, 0xd2, 0x88, 0x6d, 0x41, 0x3d, 0xc5, 0xfe, 0x1c, 0xdc, 0xb9, 0xf8, 0xd4, 0x51,
    0x3e, 0x07, 0xe5, 0x03, 0x6f, 0xa7, 0x12, 0xe8, 0x12, 0xf7, 0xb5, 0xce, 0xa6, 0x96, 0x55, 0x3f,
    0x78, 0xb4, 0x64, 0x82, 0x50, 0xd2, 0x33, 0x5f, 0x91, 0x02, 0x03, 0x01, 0x00, 0x01,
];

pub const COMMON_SERVICE_CERTIFICATE: [u8; 716] = [
    0x08, 0x05, 0x12, 0xc7, 0x05, 0x0a, 0xc1, 0x02, 0x08, 0x03, 0x12, 0x10, 0x17, 0x05, 0xb9, 0x17,
    0xcc, 0x12, 0x04, 0x86, 0x8b, 0x06, 0x33, 0x3a, 0x2f, 0x77, 0x2a, 0x8c, 0x18, 0x82, 0xb4, 0x82,
    0x92, 0x05, 0x22, 0x8e, 0x02, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x99, 0xed,
    0x5b, 0x3b, 0x32, 0x7d, 0xab, 0x5e, 0x24, 0xef, 0xc3, 0xb6, 0x2a, 0x95, 0xb5, 0x98, 0x52, 0x0a,
    0xd5, 0xbc, 0xcb, 0x37, 0x50, 0x3e, 0x06, 0x45, 0xb8, 0x14, 0xd8, 0x76, 0xb8, 0xdf, 0x40, 0x51,
    0x04, 0x41, 0xad, 0x8c, 0xe3, 0xad, 0xb1, 0x1b, 0xb8, 0x8c, 0x4e, 0x72, 0x5a, 0x5e, 0x4a, 0x9e,
    0x07, 0x95, 0x29, 0x1d, 0x58, 0x58, 0x40, 0x23, 0xa7, 0xe1, 0xaf, 0x0e, 0x38, 0xa9, 0x12, 0x79,
    0x39, 0x30, 0x08, 0x61, 0x0b, 0x6f, 0x15, 0x8c, 0x87, 0x8c, 0x7e, 0x21, 0xbf, 0xfb, 0xfe, 0xea,
    0x77, 0xe1, 0x01, 0x9e, 0x1e, 0x57, 0x81, 0xe8, 0xa4, 0x5f, 0x46, 0x26, 0x3d, 0x14, 0xe6, 0x0e,
    0x80, 0x58, 0xa8, 0x60, 0x7a, 0xdc, 0xe0, 0x4f, 0xac, 0x84, 0x57, 0xb1, 0x37, 0xa8, 0xd6, 0x7c,
    0xcd, 0xeb, 0x33, 0x70, 0x5d, 0x98, 0x3a, 0x21, 0xfb, 0x4e, 0xec, 0xbd, 0x4a, 0x10, 0xca, 0x47,
    0x49, 0x0c, 0xa4, 0x7e, 0xaa, 0x5d, 0x43, 0x82, 0x18, 0xdd, 0xba, 0xf1, 0xca, 0xde, 0x33, 0x92,
    0xf1, 0x3d, 0x6f, 0xfb, 0x64, 0x42, 0xfd, 0x31, 0xe1, 0xbf, 0x40, 0xb0, 0xc6, 0x04, 0xd1, 0xc4,
    0xba, 0x4c, 0x95, 0x20, 0xa4, 0xbf, 0x97, 0xee, 0xbd, 0x60, 0x92, 0x9a, 0xfc, 0xee, 0xf5, 0x5b,
    0xba, 0xf5, 0x64, 0xe2, 0xd0, 0xe7, 0x6c, 0xd7, 0xc5, 0x5c, 0x73, 0xa0, 0x82, 0xb9, 0x96, 0x12,
    0x0b, 0x83, 0x59, 0xed, 0xce, 0x24, 0x70, 0x70, 0x82, 0x68, 0x0d, 0x6f, 0x67, 0xc6, 0xd8, 0x2c,
    0x4a, 0xc5, 0xf3, 0x13, 0x44, 0x90, 0xa7, 0x4e, 0xec, 0x37, 0xaf, 0x4b, 0x2f, 0x01, 0x0c, 0x59,
    0xe8, 0x28, 0x43, 0xe2, 0x58, 0x2f, 0x0b, 0x6b, 0x9f, 0x5d, 0xb0, 0xfc, 0x5e, 0x6e, 0xdf, 0x64,
    0xfb, 0xd3, 0x08, 0xb4, 0x71, 0x1b, 0xcf, 0x12, 0x50, 0x01, 0x9c, 0x9f, 0x5a, 0x09, 0x02, 0x03,
    0x01, 0x00, 0x01, 0x3a, 0x14, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x2e, 0x77, 0x69, 0x64,
    0x65, 0x76, 0x69, 0x6e, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x12, 0x80, 0x03, 0xae, 0x34, 0x73, 0x14,
    0xb5, 0xa8, 0x35, 0x29, 0x7f, 0x27, 0x13, 0x88, 0xfb, 0x7b, 0xb8, 0xcb, 0x52, 0x77, 0xd2, 0x49,
    0x82, 0x3c, 0xdd, 0xd1, 0xda, 0x30, 0xb9, 0x33, 0x39, 0x51, 0x1e, 0xb3, 0xcc, 0xbd, 0xea, 0x04,
    0xb9, 0x44, 0xb9, 0x27, 0xc1, 0x21, 0x34, 0x6e, 0xfd, 0xbd, 0xea, 0xc9, 0xd4, 0x13, 0x91, 0x7e,
    0x6e, 0xc1, 0x76, 0xa1, 0x04, 0x38, 0x46, 0x0a, 0x50, 0x3b, 0xc1, 0x95, 0x2b, 0x9b, 0xa4, 0xe4,
    0xce, 0x0f, 0xc4, 0xbf, 0xc2, 0x0a, 0x98, 0x08, 0xaa, 0xaf, 0x4b, 0xfc, 0xd1, 0x9c, 0x1d, 0xcf,
    0xcd, 0xf5, 0x74, 0xcc, 0xac, 0x28, 0xd1, 0xb4, 0x10, 0x41, 0x6c, 0xf9, 0xde, 0x88, 0x04, 0x30,
    0x1c, 0xbd, 0xb3, 0x34, 0xca, 0xfc, 0xd0, 0xd4, 0x09, 0x78, 0x42, 0x3a, 0x64, 0x2e, 0x54, 0x61,
    0x3d, 0xf0, 0xaf, 0xcf, 0x96, 0xca, 0x4a, 0x92, 0x49, 0xd8, 0x55, 0xe4, 0x2b, 0x3a, 0x70, 0x3e,
    0xf1, 0x76, 0x7f, 0x6a, 0x9b, 0xd3, 0x6d, 0x6b, 0xf8, 0x2b, 0xe7, 0x6b, 0xbf, 0x0c, 0xba, 0x4f,
    0xde, 0x59, 0xd2, 0xab, 0xcc, 0x76, 0xfe, 0xb6, 0x42, 0x47, 0xb8, 0x5c, 0x43, 0x1f, 0xbc, 0xa5,
    0x22, 0x66, 0xb6, 0x19, 0xfc, 0x36, 0x97, 0x95, 0x43, 0xfc, 0xa9, 0xcb, 0xbd, 0xbb, 0xfa, 0xfa,
    0x0e, 0x1a, 0x55, 0xe7, 0x55, 0xa3, 0xc7, 0xbc, 0xe6, 0x55, 0xf9, 0x64, 0x6f, 0x58, 0x2a, 0xb9,
    0xcf, 0x70, 0xaa, 0x08, 0xb9, 0x79, 0xf8, 0x67, 0xf6, 0x3a, 0x0b, 0x2b, 0x7f, 0xdb, 0x36, 0x2c,
    0x5b, 0xc4, 0xec, 0xd5, 0x55, 0xd8, 0x5b, 0xca, 0xa9, 0xc5, 0x93, 0xc3, 0x83, 0xc8, 0x57, 0xd4,
    0x9d, 0xaa, 0xb7, 0x7e, 0x40, 0xb7, 0x85, 0x1d, 0xdf, 0xd2, 0x49, 0x98, 0x80, 0x8e, 0x35, 0xb2,
    0x58, 0xe7, 0x5d, 0x78, 0xea, 0xc0, 0xca, 0x16, 0xf7, 0x04, 0x73, 0x04, 0xc2, 0x0d, 0x93, 0xed,
    0xe4, 0xe8, 0xff, 0x1c, 0x6f, 0x17, 0xe6, 0x24, 0x3e, 0x3f, 0x3d, 0xa8, 0xfc, 0x17, 0x09, 0x87,
    0x0e, 0xc4, 0x5f, 0xba, 0x82, 0x3a, 0x26, 0x3f, 0x0c, 0xef, 0xa1, 0xf7, 0x09, 0x3b, 0x19, 0x09,
    0x92, 0x83, 0x26, 0x33, 0x37, 0x05, 0x04, 0x3a, 0x29, 0xbd, 0xa6, 0xf9, 0xb4, 0x34, 0x2c, 0xc8,
    0xdf, 0x54, 0x3c, 0xb1, 0xa1, 0x18, 0x2f, 0x7c, 0x5f, 0xff, 0x33, 0xf1, 0x04, 0x90, 0xfa, 0xca,
    0x5b, 0x25, 0x36, 0x0b, 0x76, 0x01, 0x5e, 0x9c, 0x5a, 0x06, 0xab, 0x8e, 0xe0, 0x2f, 0x00, 0xd2,
    0xe8, 0xd5, 0x98, 0x61, 0x04, 0xaa, 0xcc, 0x4d, 0xd4, 0x75, 0xfd, 0x96, 0xee, 0x9c, 0xe4, 0xe3,
    0x26, 0xf2, 0x1b, 0x83, 0xc7, 0x05, 0x85, 0x77, 0xb3, 0x87, 0x32, 0xcd, 0xda, 0xbc, 0x6a, 0x6b,
    0xed, 0x13, 0xfb, 0x0d, 0x49, 0xd3, 0x8a, 0x45, 0xeb, 0x87, 0xa5, 0xf4,
];

pub const SERVICE_CERTIFICATE_CHALLANGE: [u8; 2] = [0x08, 0x04];

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
            identification_blob: identification_blob,
            private_key: private_key,
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
    raw_lincese_request: Option<Vec<u8>>,
}

impl Session {
    pub fn new() -> Session {
        return Session {
            session_id: generate_session_token(),
            signed_service_certificate: None,
            raw_lincese_request: None,
        };
    }

    pub fn set_default_service_certificate(&mut self) {
        self.set_service_certificate(COMMON_SERVICE_CERTIFICATE.to_vec())
            .unwrap();
    }

    pub fn set_service_certificate(
        &mut self,
        raw_service_certificate: Vec<u8>,
    ) -> error::Result<()> {
        let signed_service_certificate =
            SignedDrmCertificate::decode(&*raw_service_certificate).unwrap();
        let verified = verify_service_certificate(&signed_service_certificate).unwrap();
        println!("verified: {}", verified);
        if !verified {
            return Err(error::Error::Internal {
                message: String::from("TODO: Could not verify signature of service certificate"),
            });
        }
        self.signed_service_certificate = Some(signed_service_certificate);
        return Ok(());
    }

    pub fn set_service_certificate_from_message(&mut self, signed_message: Vec<u8>) {
        let signed_message: SignedMessage = SignedMessage::decode(&*signed_message).unwrap();
        self.set_service_certificate(signed_message.msg().to_vec())
            .unwrap();
    }

    pub fn create_license_request(
        &mut self,
        ldm: &LicenseDecryptionModule,
        pssh: &Vec<u8>,
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
            key_control_nonce: Some(rand::thread_rng().gen::<u32>()),
            ..Default::default()
        };
        if let Some(signed_service_certificate) = &self.signed_service_certificate {
            let encrypted_client_identification =
                encrypte_client_identification(&client_identification, &signed_service_certificate);
            license_request.encrypted_client_id = Some(encrypted_client_identification);
        } else {
            license_request.client_id = Some(client_identification);
        }

        let raw_license_request: Vec<u8> = license_request.encode_to_vec();
        self.raw_lincese_request = Some(raw_license_request.clone());

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

        let raw_license_request = self.raw_lincese_request.unwrap();

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

fn encrypte_client_identification(
    client_identification: &ClientIdentification,
    signed_service_certificate: &SignedDrmCertificate,
) -> EncryptedClientIdentification {
    let key: [u8; 16] = rand::thread_rng().gen::<[u8; 16]>();
    let iv: [u8; 16] = rand::thread_rng().gen::<[u8; 16]>();
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
) -> error::Result<bool> {
    let public_key = PKey::from_rsa(Rsa::public_key_from_der_pkcs1(&WIDEVINE_ROOT_PUBLIC_KEY)?)?;
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
    let random_bytes = rand::thread_rng().gen::<[u8; 4]>();
    let token = vec![
        random_bytes.to_vec(),
        b"\x00\x00\x00\x00".to_vec(),
        1_u64.to_le_bytes().to_vec(),
    ]
    .concat();
    return token;
}

fn check_pssh(pssh: &Vec<u8>) -> bool {
    match license_protocol::WidevinePsshData::decode(&pssh[32..]) {
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

    const CRUNCHYROLL_SERVICE_CERTIFICATE: &str = "CrsCCAMSEKDc0WAwLAQT1SB2ogyBJEwYv4Tx7gUijgIwggEKAoIBAQC8Xc/GTRwZDtlnBThq8V382D1oJAM0F/YgCQtNDLz7vTWJ+QskNGi5Dd2qzO4s48Cnx5BLvL4H0xCRSw2Ed6ekHSdrRUwyoYOE+M/t1oIbccwlTQ7o+BpV1X6TB7fxFyx1jsBtRsBWphU65w121zqmSiwzZzJ4xsXVQCJpQnNI61gzHO42XZOMuxytMm0F6puNHTTqhyY3Z290YqvSDdOB+UY5QJuXJgjhvOUD9+oaLlvT+vwmV2/NJWxKqHBKdL9JqvOnNiQUF0hDI7Wf8Wb63RYSXKE27Ky31hKgx1wuq7TTWkA+kHnJTUrTEfQxfPR4dJTquE+IDLAi5yeVVxzbAgMBAAE6DGNhc3RsYWJzLmNvbUABEoADMmGXpXg/0qxUuwokpsqVIHZrJfu62ar+BF8UVUKdK5oYQoiTZd9OzK3kr29kqGGk3lSgM0/p499p/FUL8oHHzgsJ7Hajdsyzn0Vs3+VysAgaJAkXZ+k+N6Ka0WBiZlCtcunVJDiHQbz1sF9GvcePUUi2fM/h7hyskG5ZLAyJMzTvgnV3D8/I5Y6mCFBPb/+/Ri+9bEvquPF3Ff9ip3yEHu9mcQeEYCeGe9zR/27eI5MATX39gYtCnn7dDXVxo4/rCYK0A4VemC3HRai2X3pSGcsKY7+6we7h4IycjqtuGtYg8AbaigovcoURAZcr1d/G0rpREjLdVLG0Gjqk63Gx688W5gh3TKemsK3R1jV0dOfj3e6uV/kTpsNRL9KsD0v7ysBQVdUXEbJotcFz71tI5qc3jwr6GjYIPA3VzusD17PN6AGQniMwxJV12z/EgnUopcFB13osydpD2AaDsgWo5RWJcNf+fzCgtUQx/0Au9+xVm5LQBdv8Ja4f2oiHN3dw";

    #[tokio::test]
    async fn chrome_cdm() {
        let device_client_id_blob =
            fs::read("security/device_client_id_blob").unwrap_or(Vec::new());
        let device_private_key = fs::read("security/device_private_key").unwrap_or(Vec::new());
        assert!(device_client_id_blob.len() > 0, "id blob was not given");
        assert!(device_private_key.len() > 0, "private key was not given");
        let _ldm: LicenseDecryptionModule =
            LicenseDecryptionModule::new(&device_private_key, device_client_id_blob, None);
        let mut session = Session::new();
        println!("{}", general_purpose::STANDARD.encode(WIDEVINE_SYSTEM_ID));
        session
            .set_service_certificate(
                general_purpose::STANDARD
                    .decode(CRUNCHYROLL_SERVICE_CERTIFICATE)
                    .unwrap(),
            )
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn crunchyroll() {
        dotenv::dotenv().unwrap();
        let etp_rt = env::var("etp_rt").unwrap();
        let client = CrunchyrollBuilder::predefined_client_builder()
            .build()
            .unwrap();
        let crunchy = Crunchyroll::builder()
            .locale(crunchyroll_rs::Locale::de_DE)
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
        let regex = Regex::new(r"\/p\/(?<asset_id>[a-zA-Z0-9]+)_").unwrap();
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
        //PSSH from .mpd search for something like cenc...
        let pssh = general_purpose::STANDARD.decode("AAAAoXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIEIARIQmYVDQW4gNdatYCGbY/l5jRoIY2FzdGxhYnMiWGV5SmhjM05sZEVsa0lqb2lZelJqTlRnNE1UUmpORFEwTWpGaVpqRmlObUprTXpka01USm1NVFppWmpjaUxDSjJZWEpwWVc1MFNXUWlPaUpoZG10bGVTSjkyB2RlZmF1bHQ=").unwrap();
        let mut session = Session::new();
        let license_request = session.create_license_request(&ldm, &pssh);

        let response = crunchy
            .client()
            .post("https://cr-license-proxy.prd.crunchyrollsvc.com/v1/license/widevine")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", login_response.access_token),
            )
            .header("X-Cr-Content-Id", "GJWU2E72X")
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
    #[serde(rename_all = "camelCase")]
    pub struct CrunchyLicense {
        #[serde(rename = "service_version_info")]
        pub service_version_info: ServiceVersionInfo,
        #[serde(rename = "supported_tracks")]
        pub supported_tracks: Vec<SupportedTrack>,
        #[serde(rename = "message_type")]
        pub message_type: String,
        pub status: String,
        pub license: String,
        pub platform: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ServiceVersionInfo {
        #[serde(rename = "license_sdk_version")]
        pub license_sdk_version: String,
        #[serde(rename = "license_service_version")]
        pub license_service_version: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupportedTrack {
        #[serde(rename = "type")]
        pub type_field: String,
        #[serde(rename = "key_id")]
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
    #[serde(rename_all = "camelCase")]
    pub struct Captions {}

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
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
    #[serde(rename_all = "camelCase")]
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
    #[serde(rename_all = "camelCase")]
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
    #[serde(rename_all = "camelCase")]
    pub struct Subtitle {
        pub format: String,
        pub language: String,
        pub url: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Version {
        #[serde(rename = "audio_locale")]
        pub audio_locale: String,
        pub guid: String,
        #[serde(rename = "is_premium_only")]
        pub is_premium_only: bool,
        #[serde(rename = "media_guid")]
        pub media_guid: String,
        pub original: bool,
        #[serde(rename = "season_guid")]
        pub season_guid: String,
        pub variant: String,
    }

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

        let client = reqwest::Client::new();

        let service_certificate = client
            .post(BITMOVIN_LICENSE_URL)
            .body(SERVICE_CERTIFICATE_CHALLANGE.to_vec())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();

        session.set_service_certificate_from_message(service_certificate.to_vec());

        let license_request = session.create_license_request(&ldm, &pssh);

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
