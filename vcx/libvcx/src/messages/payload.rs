use messages::message_type::*;
use messages::to_u8;
use messages::get_message::MessagePayload;
use settings::{ProtocolTypes, get_protocol_type};
use utils::libindy::crypto;
use error::prelude::*;
use messages::thread::Thread;
use serde_json::Value;

/// A Payload mixes two concerns, which may not be ideal from a
/// design perspective. However, I'm documenting its semantics for
/// clarity; if you refactor (please!), make sure you update the
/// comments here to keep them accurate. (See also comments on
/// the Protocols enum in settings.rs.)
///
/// The first concern is message formatting. So far we've had two
/// major approaches to message formatting. The first was based on
/// MsgPack, and was invented in early 2018, when the Indy community
/// was just beginning to understand the concept of A2A. The second
/// was invented in late 2018 and substantially refined for an agent
/// connectathon in spring 2019. It is JSON-oriented and reflects the
/// conventions of DIDComm as embodied in Aries RFCs written in late
/// 2018 and all of 2019. A third major approach is on the horizon,
/// which is a modified JSON based on JWMs, as envisioned by DIF. None
/// of the code here reflects the third mental model as of April 2020.
/// This is likely to change in the future.
///
/// The second concern is encryption. We've had three evolutions in
/// approach here. The first cut was Evernym-proprietary but pretty
/// close to what later became Indy HIPE 0020. The second cut was Indy
/// HIPE 0020. These two approaches are close enough that we haven't
/// distinguished between them in the code. The third cut was Aries RFC
/// 0019, which was broadly accepted by the Aries community and frozen
/// in Aries Interop Profile 1.0. It is likely that a fourth cut will
/// emerge, using JWEs and JWSes more canonically, as part of the
/// DIDComm effort at DIF.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Payloads {
    PayloadV1(PayloadV1),
    PayloadV2(PayloadV2),
}

/// PayloadV1 is MsgPack'ed and is used with old, Evernym-proprietary
/// A2A protocols that predate formalized protocol work in Indy
/// HIPEs. It uses the very first impl of anoncrypt/authcrypt -- one
/// that resembles but predates Indy HIPE 0020.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct PayloadV1 {
    #[serde(rename = "@type")]
    pub type_: PayloadTypeV1,
    #[serde(rename = "@msg")]
    pub msg: String,
}

/// PayloadV12 is MsgPack'ed and is used with old, Evernym-proprietary
/// A2A protocols that predate formalized protocol work in Indy
/// HIPEs. However, it uses a standard impl of anoncrypt()/authcrypt() for
/// encryption, as documented in Indy HIPE 0020 (https://j.mp/2K9RXhv).
/// It was the first move toward community compatibility in libvcx.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct PayloadV12 {
    #[serde(rename = "@type")]
    pub type_: PayloadTypeV2,
    #[serde(rename = "@msg")]
    pub msg: Value
}

/// PayloadV2 is JSON per Aries RFCs, and is used with Aries / DIDComm
/// protocols. It also uses a standard impl of anoncrypt()/authcrypt() for
/// encryption, as documented in Indy HIPE 0020 (https://j.mp/2K9RXhv).
/// It is thus compatible with early community efforts, but not yet evolved
/// enough for Aries Interop Profile 1.0. Contrast _decrypt_v3_message in
/// get_message.rs, which supports Aries RFC 0019 as snapshotted for AIP 1.0
/// (https://j.mp/2Vd0kiN).
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct PayloadV2 {
    #[serde(rename = "@type")]
    pub type_: PayloadTypeV2,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@msg")]
    pub msg: String,
    #[serde(rename = "~thread")]
    pub thread: Thread,
}

impl Payloads {
    // TODO: Refactor Error
    // this will become a CommonError, because multiple types (Connection/Issuer Credential) use this function
    // Possibly this function moves out of this file.
    // On second thought, this should stick as a ConnectionError.
    pub fn encrypt(my_vk: &str, their_vk: &str, data: &str, msg_type: PayloadKinds, thread: Option<Thread>, version: &ProtocolTypes) -> VcxResult<Vec<u8>> {
        match version {
            ProtocolTypes::V1 => {
                let payload = PayloadV1 {
                    type_: PayloadTypes::build_v1(msg_type, "json"),
                    msg: data.to_string(),
                };

                let bytes = rmp_serde::to_vec_named(&payload)
                    .map_err(|err| {
                        error!("could not encode create_keys msg: {}", err);
                        VcxError::from_msg(VcxErrorKind::InvalidMessagePack, format!("Cannot encrypt payload: {}", err))
                    })?;

                trace!("Sending payload: {:?}", bytes);
                crypto::prep_msg(&my_vk, &their_vk, &bytes)
            }
            ProtocolTypes::V2 |
            ProtocolTypes::V3 => {
                let thread = thread.ok_or(VcxError::from_msg(VcxErrorKind::InvalidState, "Thread info not found"))?;

                let payload = PayloadV2 {
                    type_: PayloadTypes::build_v2(msg_type),
                    id: String::new(),
                    msg: data.to_string(),
                    thread,
                };

                let message = ::serde_json::to_string(&payload)
                    .map_err(|err| {
                        error!("could not serialize create_keys msg: {}", err);
                        VcxError::from_msg(VcxErrorKind::SerializationError, format!("Cannot serialize payload: {}", err))
                    })?;

                let receiver_keys = ::serde_json::to_string(&vec![&their_vk])
                    .map_err(|err| VcxError::from_msg(VcxErrorKind::SerializationError, format!("Cannot serialize receiver keys: {}", err)))?;

                trace!("Sending payload: {:?}", message.as_bytes());
                crypto::pack_message(Some(my_vk), &receiver_keys, message.as_bytes())
            }
        }
    }

    pub fn decrypt_helper(my_vk: &str, payload: &MessagePayload) -> VcxResult<(String, Option<Thread>, Option<MessageTypeV2>)> {
        match payload {
            MessagePayload::V1(payload) => {
                // If we can do v1 style decryption
                if let Ok(payload) = Payloads::decrypt_payload_v1(my_vk, payload) {
                    // Return a VcxResult that contains the output String and no thread.
                    Ok((payload.msg, None, None))
                } else {
                    // Convert to a vector of u8.
                    let vec = to_u8(payload);
                    // Get a JSON value from the text -- or return VcxError on failure.
                    let json: Value = serde_json::from_slice(&vec[..])
                        .map_err(|err|
                            VcxError::from_msg(VcxErrorKind::InvalidMessagePack,
                                               format!("Cannot deserialize MessagePayload: {}", err)))?;
                    // If we got a JSON value, decrypt it in v12 style. If that fails, return
                    // VcxError. If it succeeds, get String output from the .msg property. It
                    // might be encoded as a String already, or it might be a JSON Value object
                    // that needs to be converted to a String.
                    let payload = Payloads::decrypt_payload_v12(&my_vk, &json)?;
                    let type_ = payload.type_;
                    let payload = match payload.msg {
                        serde_json::Value::String(_str) => _str,
                        value => value.to_string()
                    };
                    // Return a VcxResult that contains the output String and no thread.
                    Ok((payload, None, Some(type_)))
                }
            }
            // Else if we can do v2 style decryption
            MessagePayload::V2(payload) => {
                let payload = Payloads::decrypt_payload_v2(my_vk, payload)?;
                Ok((payload.msg, Some(payload.thread), None))
            }
        }
    }

    pub fn decrypt(my_vk: &str, payload: &MessagePayload) -> VcxResult<(String, Option<Thread>)> {
        Payloads::decrypt_helper(my_vk, payload).map(|(data, th, _)| (data, th))
    }

    pub fn decrypt_payload_v1(my_vk: &str, payload: &Vec<i8>) -> VcxResult<PayloadV1> {
        let (_, data) = crypto::parse_msg(&my_vk, &to_u8(payload))?;

        let my_payload: PayloadV1 = rmp_serde::from_slice(&data[..])
            .map_err(|err| VcxError::from_msg(
                VcxErrorKind::InvalidMessagePack,
                format!("Cannot decrypt payload: {}", err)))?;

        Ok(my_payload)
    }

    pub fn decrypt_payload_v2(_my_vk: &str, payload: &::serde_json::Value) -> VcxResult<PayloadV2> {
        let payload = ::serde_json::to_vec(&payload)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, err))?;

        let unpacked_msg = crypto::unpack_message(&payload)?;

        let message: ::serde_json::Value = ::serde_json::from_slice(unpacked_msg.as_slice())
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize payload: {}", err)))?;

        let message = message["message"].as_str()
            .ok_or(VcxError::from_msg(VcxErrorKind::InvalidJson, "Cannot find `message` field"))?.to_string();

        let mut my_payload: PayloadV2 = serde_json::from_str(&message)
            .map_err(|err| {
                error!("could not deserialize PayloadV2: {}", err);
                VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize payload: {}", err))
            })?;

        if my_payload.thread.thid.is_none() {
            my_payload.thread.thid = Some(my_payload.id.clone());
        }

        Ok(my_payload)
    }

    pub fn decrypt_payload_v12(_my_vk: &str, payload: &::serde_json::Value) -> VcxResult<PayloadV12> {
        let payload = ::serde_json::to_vec(&payload)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, err))?;

        let unpacked_msg = crypto::unpack_message(&payload)?;

        let message: ::serde_json::Value = ::serde_json::from_slice(unpacked_msg.as_slice())
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize payload: {}", err)))?;

        let message = message["message"].as_str()
            .ok_or(VcxError::from_msg(VcxErrorKind::InvalidJson, "Cannot find `message` field"))?.to_string();

        let my_payload: PayloadV12 = serde_json::from_str(&message)
            .map_err(|err| {
                error!("could not deserialize PayloadV12: {}", err);
                VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize payload: {}", err))
            })?;

        Ok(my_payload)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum PayloadTypes {
    PayloadTypeV1(PayloadTypeV1),
    PayloadTypeV2(PayloadTypeV2),
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct PayloadTypeV1 {
    name: String,
    ver: String,
    fmt: String,
}

type PayloadTypeV2 = MessageTypeV2;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum PayloadKinds {
    CredOffer,
    CredReq,
    Cred,
    Proof,
    ProofRequest,
    Other(String)
}

impl PayloadKinds {
    fn family(&self) -> MessageFamilies {
        match self {
            PayloadKinds::CredOffer => MessageFamilies::CredentialExchange,
            PayloadKinds::CredReq => MessageFamilies::CredentialExchange,
            PayloadKinds::Cred => MessageFamilies::CredentialExchange,
            PayloadKinds::Proof => MessageFamilies::CredentialExchange,
            PayloadKinds::ProofRequest => MessageFamilies::CredentialExchange,
            PayloadKinds::Other(family) => MessageFamilies::Unknown(family.to_string()),
        }
    }

    pub fn name<'a>(&'a self) -> &'a str {
        match get_protocol_type() {
            ProtocolTypes::V1 => {
                match self {
                    PayloadKinds::CredOffer => "CRED_OFFER",
                    PayloadKinds::CredReq => "CRED_REQ",
                    PayloadKinds::Cred => "CRED",
                    PayloadKinds::ProofRequest => "PROOF_REQUEST",
                    PayloadKinds::Proof => "PROOF",
                    PayloadKinds::Other(kind) => kind,
                }
            }
            ProtocolTypes::V2 |
            ProtocolTypes::V3 => {
                match self {
                    PayloadKinds::CredOffer => "credential-offer",
                    PayloadKinds::CredReq => "credential-request",
                    PayloadKinds::Cred => "credential",
                    PayloadKinds::ProofRequest => "presentation-request",
                    PayloadKinds::Proof => "presentation",
                    PayloadKinds::Other(kind) => kind,
                }
            }
        }
    }
}

impl PayloadTypes {
    pub fn build_v1(kind: PayloadKinds, fmt: &str) -> PayloadTypeV1 {
        PayloadTypeV1 {
            name: kind.name().to_string(),
            ver: MESSAGE_VERSION_V1.to_string(),
            fmt: fmt.to_string(),
        }
    }

    pub fn build_v2(kind: PayloadKinds) -> PayloadTypeV2 {
        PayloadTypeV2 {
            did: DID.to_string(),
            family: kind.family(),
            version: kind.family().version().to_string(),
            type_: kind.name().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_with_empty_payload_is_err() {
        assert!(Payloads::decrypt("my key", &MessagePayload::V1(Vec::new())).is_err());
    }

    #[test]
    fn decrypt_with_v1_payload_fails_with_bad_verkey() {
        let payload_bytes: Vec<i8> = (0..9).collect();
        let payload = MessagePayload::V1(payload_bytes);
        assert!(Payloads::decrypt("my key", &payload).is_err());
    }

    #[test]
    fn decrypt_with_v2_payload_fails_with_empty_verkey() {
        let payload = MessagePayload::V2(json!("{}"));
        assert!(Payloads::decrypt("", &payload).is_err());
    }
}