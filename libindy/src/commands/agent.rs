use errors::route::RouteError;
use serde_json;
use services::crypto::CryptoService;
use services::route::RouteService;
use services::wallet::WalletService;
use std::rc::Rc;
use std::result;

type Result<T> = result::Result<T, RouteError>;

pub enum RouteCommand {
    AuthPackMessage(
        String, // plaintext message
        String, //list of receiving keys
        String, //my verkey
        i32,    //wallet_handle
        Box<Fn(Result<String /*JWM serialized as string*/>) + Send>,
    ),
    AnonPackMessage(
        String, // plaintext message
        String, // list of receiving keys
        Box<Fn(Result<String /*JWM serialized as string*/>) + Send>,
    ),
    UnpackMessage(
        String, // AMES either JSON or Compact Serialization
        String, // my verkey
        i32,    // wallet handle
        Box<Fn(Result<(String, /*plaintext*/ String, /*sender_vk*/)>) + Send>,
    ),
}

pub struct RouteCommandExecutor {
    wallet_service: Rc<WalletService>,
    crypto_service: Rc<CryptoService>,
    route_service: Rc<RouteService>,
}

impl RouteCommandExecutor {
    pub fn new(
        wallet_service: Rc<WalletService>,
        crypto_service: Rc<CryptoService>,
        route_service: Rc<RouteService>,
    ) -> RouteCommandExecutor {
        RouteCommandExecutor {
            wallet_service,
            crypto_service,
            route_service,
        }
    }

    pub fn execute(&self, command: RouteCommand) {
        match command {
            RouteCommand::AuthPackMessage(message, recv_keys_json, my_vk, wallet_handle, cb) => {
                info!("PackMessage command received");
                cb(self.auth_pack_msg(&message, &recv_keys_json, my_vk, wallet_handle));
            }
            RouteCommand::AnonPackMessage(message, recv_keys_json, cb) => {
                info!("PackMessage command received");
                cb(self.anon_pack_msg(&message, &recv_keys_json));
            }
            RouteCommand::UnpackMessage(ames_json_str, my_vk, wallet_handle, cb) => {
                info!("UnpackMessage command received");
                cb(self.unpack_msg(&ames_json_str, &my_vk, wallet_handle));
            }
        };
    }

    pub fn auth_pack_msg(
        &self,
        message: &str,
        recv_keys_json: &str,
        my_vk: String,
        wallet_handle: i32,
    ) -> Result<String> {
        //convert type from json array to Vec<String>
        let recv_keys: Vec<&str> = serde_json::from_str(recv_keys_json).map_err(|err| {
            RouteError::SerializationError(format!("Failed to serialize recv_keys {:?}", err))
        })?;

        self.route_service.auth_pack_msg(
            message,
            recv_keys,
            &my_vk,
            wallet_handle,
            self.wallet_service.clone(),
            self.crypto_service.clone(),
        )

        //encrypt ciphertext
        let (sym_key, iv, ciphertext) = self.encrypt_ciphertext(message);

        //convert sender_vk to Key
        let my_key = &ws
            .get_indy_object(wallet_handle, sender_vk, &RecordOptions::id_value())
            .map_err(|err| RouteError::UnpackError(format!("Can't find my_key: {:?}", err)))?;

        //encrypt ceks
        let mut auth_recipients = vec![];

        for their_vk in recv_keys {
            auth_recipients.push(
                self.auth_encrypt_recipient(my_key, their_vk, &sym_key, cs.clone())
                    .map_err(|err| {
                        RouteError::PackError(format!("Failed to push auth recipient {}", err))
                    })?,
            );
        }

        //serialize AuthAMES
        let auth_ames_struct = AuthAMES {
            recipients: auth_recipients,
            ver: "AuthAMES/1.0/".to_string(),
            enc: "xsalsa20poly1305".to_string(),
            ciphertext: base64::encode(ciphertext.as_slice()),
            iv: base64::encode(&iv[..]),
        };
        serde_json::to_string(&auth_ames_struct)
            .map_err(|err| RouteError::PackError(format!("Failed to serialize authAMES {}", err)))
    }

    pub fn anon_pack_msg(&self, message: &str, recv_keys_json: &str) -> Result<String> {
        //convert type from json array to Vec<&str>
        let recv_keys: Vec<&str> = serde_json::from_str(recv_keys_json).map_err(|err| {
            RouteError::SerializationError(format!("Failed to serialize recv_keys {:?}", err))
        })?;

        self.route_service
            .anon_pack_msg(message, recv_keys, self.crypto_service.clone())
    }

    pub fn unpack_msg(
        &self,
        ames_json_str: &str,
        my_vk: &str,
        wallet_handle: i32,
    ) -> Result<(String, String)> {
        self.route_service.unpack_msg(
            ames_json_str,
            my_vk,
            wallet_handle,
            self.wallet_service.clone(),
            self.crypto_service.clone(),
        )
    }
}