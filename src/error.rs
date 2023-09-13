// Copyright 2022-NOW Crunchy Labs Team
// SPDX-License-Identifier: MIT

use http::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use std::fmt::{Debug, Display, Formatter};

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone, Debug)]
pub enum Error {
    Internal {
        message: String,
    },
    OpenSSL {
        message: String,
        stack: openssl::error::ErrorStack,
    },
    Input {
        message: String,
    },
    Request {
        message: String,
        status: Option<StatusCode>,
        url: String,
    },
    Decode {
        message: String,
        content: Vec<u8>,
        url: String,
    },
    Block {
        message: String,
        body: String,
        url: String,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Internal { message } => write!(f, "{message}"),
            Error::Request { message, url, .. } => {
                // the url can be 'n/a' when the error got triggered by the [`From<reqwest::Error>`]
                // implementation for this error struct
                if url != "n/a" {
                    write!(f, "{message} ({url})")
                } else {
                    write!(f, "{message}")
                }
            }
            Error::Decode {
                message,
                content,
                url,
            } => {
                let mut msg = message.clone();
                // the url is 'n/a' when the error got triggered by the [`From<serde_json::Error>`]
                // implementation for this error struct or [`VariantSegment::decrypt`]
                if url != "n/a" {
                    msg.push_str(&format!(" ({url})"))
                }
                if content.is_empty() {
                    write!(f, "{}", msg)
                } else {
                    write!(f, "{}: {}", msg, String::from_utf8_lossy(content.as_ref()))
                }
            }
            Error::Input { message } => write!(f, "{message}"),
            Error::Block { message, body, url } => write!(f, "{message} ({url}): {body}"),
            Error::OpenSSL { message, stack } => write!(f, "{message} {stack}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Decode {
            message: err.to_string(),
            content: vec![],
            url: "n/a".to_string(),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_request()
            || err.is_redirect()
            || err.is_timeout()
            || err.is_connect()
            || err.is_body()
            || err.is_status()
        {
            Error::Request {
                message: err.to_string(),
                status: err.status(),
                url: err.url().map_or("n/a".to_string(), |url| url.to_string()),
            }
        } else if err.is_decode() {
            Error::Decode {
                message: err.to_string(),
                content: vec![],
                url: err.url().map_or("n/a".to_string(), |url| url.to_string()),
            }
        } else if err.is_builder() {
            Error::Internal {
                message: err.to_string(),
            }
        } else {
            Error::Internal {
                message: "Could not determine request error type - {err}".to_string(),
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) fn is_request_error(value: Value, url: &String, status: &StatusCode) -> Result<()> {
    #[derive(Debug, Deserialize)]
    struct CodeFieldContext {
        code: String,
        field: String,
    }

    #[derive(Debug, Deserialize)]
    struct MessageType {
        message: String,
        #[serde(rename = "type")]
        error_type: String,
    }
    #[derive(Debug, Deserialize)]
    struct CodeContextError {
        code: String,
        context: Vec<CodeFieldContext>,
        #[serde(alias = "error")]
        message: Option<String>,
    }
    #[derive(Debug, Deserialize)]
    struct ConstraintsErrorContext {
        code: String,
        violated_constraints: Vec<(String, String)>,
    }
    #[derive(Debug, Deserialize)]
    struct ConstraintsError {
        code: String,
        context: Vec<ConstraintsErrorContext>,
    }

    if let Ok(err) = serde_json::from_value::<MessageType>(value.clone()) {
        return Err(Error::Request {
            message: format!("{} - {}", err.error_type, err.message),
            status: Some(*status),
            url: url.to_string(),
        });
    } else if let Ok(err) = serde_json::from_value::<CodeContextError>(value.clone()) {
        let mut details: Vec<String> = vec![];

        for item in err.context.iter() {
            details.push(format!("{}: {}", item.field, item.code))
        }

        return if let Some(message) = err.message {
            Err(Error::Request {
                message: format!("{} ({}) - {}", message, err.code, details.join(", ")),
                status: Some(*status),
                url: url.to_string(),
            })
        } else {
            Err(Error::Request {
                message: format!("({}) - {}", err.code, details.join(", ")),
                status: Some(*status),
                url: url.to_string(),
            })
        };
    } else if let Ok(err) = serde_json::from_value::<ConstraintsError>(value) {
        let details = err
            .context
            .iter()
            .map(|e| {
                format!(
                    "{}: ({})",
                    e.code,
                    e.violated_constraints
                        .iter()
                        .map(|(key, value)| format!("{key}: {value}"))
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            })
            .collect::<Vec<String>>();

        return Err(Error::Request {
            message: format!("{}: {}", err.code, details.join(", ")),
            status: Some(*status),
            url: url.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
use reqwest::Response;
#[cfg(test)]
use serde::de::DeserializeOwned;

#[cfg(test)]
pub(crate) async fn check_request<T: DeserializeOwned>(url: String, resp: Response) -> Result<T> {
    let content_length = resp.content_length().unwrap_or(0);
    let status = resp.status();
    let _raw = match resp.status().as_u16() {
        403 => {
            let raw = resp.bytes().await?;
            if raw.starts_with(b"<!DOCTYPE html>")
                && raw
                    .windows(31)
                    .any(|w| w == b"<title>Just a moment...</title>")
            {
                return Err(Error::Block {
                    message: "Triggered Cloudflare bot protection".to_string(),
                    body: String::from_utf8_lossy(raw.as_ref()).to_string(),
                    url,
                });
            }
            raw
        }
        404 => {
            return Err(Error::Request {
                message: "The requested resource is not present".to_string(),
                status: Some(resp.status()),
                url,
            })
        }
        429 => {
            let retry_secs =
                if let Some(retry_after) = resp.headers().get(http::header::RETRY_AFTER) {
                    retry_after.to_str().map_or(None, |retry_after_secs| {
                        retry_after_secs.parse::<u32>().ok()
                    })
                } else {
                    None
                };

            return Err(Error::Request {
                message: format!(
                    "Rate limit detected. {}",
                    retry_secs.map_or("Try again later".to_string(), |secs| format!(
                        "Try again in {secs} seconds"
                    ))
                ),
                status: Some(resp.status()),
                url,
            });
        }
        _ => resp.bytes().await?,
    };
    let mut raw: &[u8] = _raw.as_ref();

    // to ensure compatibility with `T`, convert a empty response to {}
    if raw.is_empty() && (content_length == 0) {
        raw = "{}".as_bytes();
    }

    let value: Value = serde_json::from_slice(raw).map_err(|e| Error::Decode {
        message: format!("{} at {}:{}", e, e.line(), e.column()),
        content: raw.to_vec(),
        url: url.clone(),
    })?;
    is_request_error(value.clone(), &url, &status)?;
    serde_json::from_value::<T>(value).map_err(|e| Error::Decode {
        message: format!("{} at {}:{}", e, e.line(), e.column()),
        content: raw.to_vec(),
        url,
    })
}
