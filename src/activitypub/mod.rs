use crate::crypto::HasPublicKey;
use crate::db;
use crate::db::models::{Account, Status};
use crate::routes::ui::view_helpers::HasBio;
use failure::Error;
use openssl::pkey::{PKey, Public};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use rocket::http::{self, Accept, ContentType, MediaType};
use rocket::request::{self, FromRequest, Request};
use rocket::response::{self, Content, Responder};
use serde::Serialize;
use serde_json::{json, Value};
use slog::slog_error;
use slog_scope::error;

/// Newtype for JSON which represents JSON-LD ActivityStreams2 objects.
///
/// Implements `Responder`, so we can return this from Rocket routes
/// and have Content-Type and friends be handled ✨automagically✨.
pub struct ActivityStreams<T = Value>(pub T);
impl<T> Responder<'static> for ActivityStreams<T>
where
    T: Serialize,
{
    fn respond_to(self, req: &Request) -> response::Result<'static> {
        serde_json::to_string(&self.0)
            .map(|string| {
                let ap_json = ContentType::new("application", "activity+json");

                Content(ap_json, string).respond_to(req).unwrap()
            })
            .map_err(|e| {
                error!("Failed to serialize ActivityStreams2 content: {:?}", e);

                http::Status::InternalServerError
            })
    }
}

#[derive(Debug)]
pub enum SignatureError {
    BadCount,
    Invalid,
    Missing,
}

pub struct HttpSignature {
    key_id: String,
    headers: String,
    signature: Vec<u8>,
}
impl HttpSignature {
    fn from_header(value: &str) -> Option<Self> {
        let mut key_id = String::new();
        let mut headers = String::new();
        let mut signature = Vec::new();

        for pair in value.split(",") {
            let kvpair = pair.split("=").collect::<Vec<_>>();
            if kvpair.len() != 2 {
                return None;
            };
            match kvpair[0] {
                "keyId" => {
                    if key_id.is_empty() && !kvpair[1].is_empty() {
                        key_id.push_str(kvpair[1].trim_matches('"'));
                    } else {
                        return None;
                    }
                },
                "headers" => {
                    if headers.is_empty() && !kvpair[1].is_empty() {
                        headers.push_str(kvpair[1].trim_matches('"'));
                    } else {
                        return None;
                    }
                },
                "signature" => {
                    if let Ok(bytes) = base64::decode(kvpair[1].trim_matches('"')) {
                        if signature.is_empty() && !bytes.is_empty() {
                            signature.extend(bytes.iter());
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                },
                &_ => {
                    return None;
                }
            }
        };

        if key_id.is_empty() || headers.is_empty() || signature.is_empty() {
            None
        } else {
            Some(Self {
                key_id: key_id,
                headers: headers,
                signature: signature,
            })
        }
    }

    fn get_key(&self) -> Option<PKey<Public>> {
        let mut resp = reqwest::get(&self.key_id).ok()?;
        if resp.status().is_success() {
            let json: Value = resp.json().ok()?;
            let pem = json["publickey"]["publickeypem"].as_str()?;
            PKey::public_key_from_pem(pem.as_bytes()).ok()
        } else {
            None
        }
    }
}

/// A Rocket guard which ensures a valid signature is present
pub struct SignatureGuard();
impl<'a, 'r> FromRequest<'a, 'r> for SignatureGuard {
    type Error = SignatureError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<SignatureGuard, SignatureError> {
        use rocket::Outcome;

        let sigs: Vec<_> = request.headers().get("signature").collect();
        match sigs.len() {
            0 => Outcome::Failure((http::Status::BadRequest, SignatureError::Missing)),
            1 => {
                if let Some(sg) = { try {
                    let sig = HttpSignature::from_header(sigs[0])?;
                    let key = sig.get_key()?;
                    let mut verifier = Verifier::new(MessageDigest::sha256(), &key).ok()?;
                    let source = sig.headers.split(" ").map(|name| (name, match name {
                        "(request-target)" => vec!(format!("{} {}", request.method().as_str().to_lowercase(), request.uri().path())),
                        header => request.headers().get(header).map(|s| s.to_string()).collect()
                    })).collect::<Vec<_>>();
                    let _guard = Some(()).filter(|_|  !source.iter().any(|(_,v)| v.is_empty()))?;
                    let verificand = source.iter().flat_map(|(k,vs)| vs.iter().map(move |v| format!("{}: {}", k, v))).collect::<Vec<_>>().join("\n");
                    verifier.update(verificand.as_bytes()).ok()?;
                    verifier.verify(&sig.signature).ok()?;
                    SignatureGuard()
                }} {
                    Outcome::Success(sg)
                } else {
                    Outcome::Failure((http::Status::BadRequest, SignatureError::Invalid))
                }
            },
            _ => Outcome::Failure((http::Status::BadRequest, SignatureError::BadCount)),
        }
    }
}

/// A Rocket guard which forwards to the next handler unless the `Accept` header
/// is an ActivityStreams media type.
pub struct ActivityGuard();
impl<'a, 'r> FromRequest<'a, 'r> for ActivityGuard {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<ActivityGuard, ()> {
        use rocket::Outcome;

        if request.accept().map(is_as).unwrap_or(false) {
            Outcome::Success(ActivityGuard())
        } else {
            Outcome::Forward(())
        }
    }
}

/// Helper used in [`ActivityGuard`]; returns true if `accept` is an ActivityStreams-compatible
/// media type.
///
/// [`ActivityGuard`]: ./struct.ActivityGuard.html
fn is_as(accept: &Accept) -> bool {
    let media_type = accept.preferred().media_type();

    // TODO: clean this up/make these const, if MediaType::new ever becomes a const fn
    let ap_json = MediaType::new("application", "activity+json");
    let ap_json_ld = MediaType::with_params(
        "application",
        "ld+json",
        ("profile", "https://www.w3.org/ns/activitystreams"),
    );

    media_type.exact_eq(&ap_json) || media_type.exact_eq(&ap_json_ld)
}

/// Trait implemented by structs which can serialize to
/// ActivityPub-compliant ActivityStreams2 JSON-LD.
pub trait AsActivityPub {
    fn as_activitypub(&self, db: &db::DbConnection) -> Result<ActivityStreams, Error>;
}

impl AsActivityPub for Account {
    fn as_activitypub(
        &self,
        conn: &db::DbConnection,
    ) -> Result<ActivityStreams<serde_json::Value>, Error> {
        Ok(ActivityStreams(json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Person",
            "id": self.get_uri(),

            "inbox": self.get_inbox_endpoint(),
            "outbox": self.get_outbox_endpoint(),

            "following": self.get_following_endpoint(),
            "followers": self.get_followers_endpoint(),

            "preferredUsername": self.username,
            "name": self.display_name.as_ref().map(String::as_str).unwrap_or(""),
            "summary": self.transformed_bio(&conn).as_ref().map(String::as_str).unwrap_or("<p></p>"),

            "publicKey": {
                "id": format!("{}#main-key", self.get_uri()),
                "owner": self.get_uri(),
                "publicKeyPem": self.public_key_pem()?,
            }
        })))
    }
}

impl AsActivityPub for Status {
    fn as_activitypub(
        &self,
        conn: &db::DbConnection,
    ) -> Result<ActivityStreams<serde_json::Value>, Error> {
        let account = self.account(conn)?;
        Ok(ActivityStreams(json!({
            "@context": ["https://www.w3.org/ns/activitystreams", {"sensitive": "as:sensitive"}],
            "type": "Note",
            "id": self.get_uri(conn)?,
            "attributedTo": account.get_uri(),

            "content": self.text,
            "summary": self.content_warning,
            "sensitive": self.content_warning.is_some(),
            "published": self.created_at.to_rfc3339(),

            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "cc": [account.get_followers_endpoint()],
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_ap_requests() {
        use std::str::FromStr;

        let accept_json = Accept::from_str("application/activity+json").unwrap();
        let accept_json_ld = Accept::from_str(
            "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
        )
        .unwrap();

        assert!(is_as(&accept_json_ld));
        assert!(is_as(&accept_json));
    }
}
