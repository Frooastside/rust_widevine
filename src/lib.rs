pub mod error;
pub mod license_protocol;

use license_protocol::SignedMessage;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer},
    symm::{decrypt, Cipher},
};
use prost::Message;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::Error,
    license_protocol::{
        license_request::content_identification::{ContentIdVariant, WidevinePsshData},
        ClientIdentification, License, LicenseRequest,
    },
};

use crate::license_protocol::{
    license_request::ContentIdentification, LicenseType, ProtocolVersion,
};

const WIDEVINE_SYSTEM_ID: [u8; 16] = [
    237, 239, 139, 169, 121, 214, 74, 206, 163, 200, 39, 220, 213, 29, 33, 237,
];

pub struct Session {
    pub session_id: Vec<u8>,
    raw_lincese_request: Option<Vec<u8>>,
    identifier_blob: Vec<u8>,
    private_key: Vec<u8>,
}

pub struct KeyContainer {
    pub kid: String,
    pub key: String,
}

impl Session {
    pub fn new(identifier_blob: Vec<u8>, private_key: Vec<u8>) -> Session {
        return Session {
            session_id: generate_session_token(),
            raw_lincese_request: None,
            identifier_blob: identifier_blob,
            private_key: private_key,
        };
    }

    pub fn create_license_request(&mut self, pssh: Vec<u8>) -> Result<Vec<u8>, Error> {
        assert_eq!(pssh[12..28], WIDEVINE_SYSTEM_ID);
        check_pssh(pssh.clone());
        let client_identification: ClientIdentification =
            ClientIdentification::decode(&*self.identifier_blob).unwrap();
        let mut pssh_data_vec: Vec<Vec<u8>> = Vec::new();
        pssh_data_vec.push(pssh[32..].to_vec());
        let widevine_pssh_data: WidevinePsshData = WidevinePsshData {
            pssh_data: pssh_data_vec,
            license_type: Some(LicenseType::Streaming.into()),
            request_id: Some(self.session_id.encode_to_vec()),
        };
        let content: ContentIdentification = ContentIdentification {
            content_id_variant: Some(ContentIdVariant::WidevinePsshData(widevine_pssh_data)),
        };
        let license_request: LicenseRequest = LicenseRequest {
            client_id: Some(client_identification),
            content_id: Some(content),
            r#type: Some(license_protocol::license_request::RequestType::New.into()),
            request_time: Some(i64::try_from(current_time()).unwrap()),
            protocol_version: Some(ProtocolVersion::Version21.into()),
            key_control_nonce: Some(rand::thread_rng().gen::<u32>()),
            ..Default::default()
        };

        self.raw_lincese_request = Some(license_request.encode_to_vec());

        let private_key = openssl::rsa::Rsa::private_key_from_pem(&self.private_key).unwrap();
        let key_pair = openssl::pkey::PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha1(), &key_pair).unwrap();
        signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::custom(20))
            .unwrap();
        signer
            .update(&self.raw_lincese_request.clone().unwrap())
            .unwrap();
        let signature = signer.sign_to_vec().unwrap();

        let signed_license_request: SignedMessage = license_protocol::SignedMessage {
            r#type: Some(license_protocol::signed_message::MessageType::LicenseRequest.into()),
            msg: Some(self.raw_lincese_request.clone().unwrap()),
            signature: Some(signature),
            ..Default::default()
        };

        return Ok(signed_license_request.encode_to_vec());
    }

    pub fn parse_license(self, license: Vec<u8>) -> error::Result<Vec<KeyContainer>> {
        let signed_message: SignedMessage = SignedMessage::decode(&*license).unwrap();
        let private_key = openssl::rsa::Rsa::private_key_from_pem(&self.private_key).unwrap();
        let mut decrypted_session_key: Vec<u8> = vec![0; private_key.size() as usize];
        private_key
            .private_decrypt(
                signed_message.session_key(),
                &mut decrypted_session_key,
                Padding::PKCS1_OAEP,
            )
            .unwrap();

        let encryption_key_base = vec![
            b"ENCRYPTION\x00".to_vec(),
            self.raw_lincese_request.clone().unwrap(),
            b"\x00\x00\x00\x80".to_vec(),
        ]
        .concat();
        let authentication_key_base = vec![
            b"AUTHENTICATION\x00".to_vec(),
            self.raw_lincese_request.clone().unwrap(),
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
        let mut decrypted_key_containers: Vec<KeyContainer> = Vec::new();
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
            decrypted_key_containers.push(KeyContainer {
                kid: key_id,
                key: decrypted_key,
            })
        }
        return Ok(decrypted_key_containers);
    }
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

fn check_pssh(pssh: Vec<u8>) -> bool {
    match license_protocol::WidevinePsshData::decode(&pssh[32..]) {
        Ok(_pssh_data) => true,
        Err(_error) => false,
    }
}

#[cfg(test)]
mod tests {

    use crate::error::check_request;

    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use crunchyroll_rs::{
        crunchyroll::CrunchyrollBuilder, media::Media, Crunchyroll, Locale, Series,
    };
    use http::header;
    use regex::Regex;
    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use std::{env, fs};

    #[derive(Serialize, Deserialize, Debug)]
    struct DrmAuth {
        accounting_id: String,
        asset_id: String,
        session_id: String,
        user_id: String,
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
        let drm_auth = DrmAuth {
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
        //PSSH from .mpd search for something like cenc...
        let pssh = general_purpose::STANDARD.decode("AAAAoXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIEIARIQmYVDQW4gNdatYCGbY/l5jRoIY2FzdGxhYnMiWGV5SmhjM05sZEVsa0lqb2lZelJqTlRnNE1UUmpORFEwTWpGaVpqRmlObUprTXpka01USm1NVFppWmpjaUxDSjJZWEpwWVc1MFNXUWlPaUpoZG10bGVTSjkyB2RlZmF1bHQ=").unwrap();
        let mut session = Session::new(device_client_id_blob, device_private_key);
        let license_request = session.create_license_request(pssh);

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
        let pssh = general_purpose::STANDARD.decode(BITMOVIN_PSSH_B64).unwrap();
        let mut session = Session::new(device_client_id_blob, device_private_key);
        let license_request = session.create_license_request(pssh);

        let client = reqwest::Client::new();
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
            .parse_license(general_purpose::STANDARD.decode(license).unwrap())
            .unwrap()
            .iter()
            .map(|container| format!("{}:{}\n", container.kid, container.key))
            .collect();
        fs::create_dir_all("security").unwrap();
        fs::write("security/bitmovin-keys.txt", key_pairs.concat()).unwrap();
    }
}
