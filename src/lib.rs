use std::{fmt, str};
use std::collections::BTreeMap;

use log::{debug, error, trace};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use base64::{ decode_config};
use serde_json::Value;

//#[derive(Serialize, Deserialize, Clone)]
#[derive(Clone, Debug, Deserialize, PartialEq)]
struct Config {
    claim: String,
    header: String,
}

#[cfg(not(test))]
#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(JwtHttpFilterRoot {
            config: None
        })
    });
}

struct JwtHttpFilterRoot {
    config: Option<Config>,
}

impl Context for JwtHttpFilterRoot {}

impl RootContext for JwtHttpFilterRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_string) = self.get_configuration() {
            match serde_json::from_slice(&config_string) {
                Ok(configuration) => {
                    //debug!("Read config claim {} to header {}",configuration.claim, configuration.header);
                    self.config = configuration;
                    return true;
                }
                Err(err) => error!("failed to configure filter: {}", err),
            }
        }
        false
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        match &self.config {
            Some(config) => {
                Some(Box::new(JwtHttpFilter {
                    context_id,
                    claim: config.claim.clone(),
                    header: config.header.clone(),
                }))
            }
            None => None
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct JwtHttpFilter {
    context_id: u32,
    claim: String,
    header: String,
}

impl Context for JwtHttpFilter {}

impl HttpContext for JwtHttpFilter {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let token: Option<String> = self.get_http_request_header("Authorization");
        debug!("request intercepted by the hello_wasm filter");

        // last expression is implicit returned. In case of match, the last command of
        // every case.

        // Check for Authorization header
        match token {
            // If Authorization header available
            Some(token) => {
                debug!("Authorization header available | token {}", token);
                match self.get_claims(token) {
                    Ok(claims) => {
                        let value = claims.get(&self.claim).unwrap();
                        debug!("Got jwt value {} for claim {}", value, self.claim);
                        self.add_http_request_header(&self.header, value.as_str().unwrap());
                    }
                    Err(err) => {
                        self.send_http_response(
                            400,
                            vec![("invalid", "request")],
                            Some(err.to_string().as_bytes()),
                        );
                    }
                }

                // this is the last expression
                Action::Continue
            }

            // Authorization header not available. Send a local response with 403
            None => {
                self.send_http_response(
                    403,
                    vec![],
                    Some(b"Access forbidden.\n"),
                );
                // this is the last expression
                Action::Pause
            }
        }
    }

    fn on_http_response_headers(&mut self, _: usize) -> Action {
        for (name, value) in &self.get_http_response_headers() {
            trace!("#{} <- {}: {}", self.context_id, name, value);
        }
        self.add_http_response_header("blah", "upstream");
        // last expression is implicit returned. Same as return Action::Continue;
        Action::Continue
    }

    fn on_log(&mut self) {
        debug!("#{} completed.", self.context_id);
    }
}

#[derive(Debug)]
enum AuthHeaderError {
    InvalidAuthHeaderError,
    JwtTokenError(String),
}

impl std::error::Error for AuthHeaderError {}

impl fmt::Display for AuthHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthHeaderError::InvalidAuthHeaderError => write!(f, "invalid auth header"),
            AuthHeaderError::JwtTokenError(error) => write!(f, "invalid jwt auth header {}", error),
        }
    }
}

impl JwtHttpFilter {
    fn get_claims(&self, token_string: String) -> Result<BTreeMap<String, Value>, AuthHeaderError> {
        match self.read_jwt(token_string) {
            Ok(jwt_string) => {
                let parse_result: Result<BTreeMap<String, Value>, String> = decode_claims(&jwt_string);
                match parse_result {
                    Ok(token) => {
                        //let claims: BTreeMap<String, String> = token.claims().to_owned();
                        return Ok(token.to_owned());
                    }
                    Err(err) => Err(AuthHeaderError::JwtTokenError(err))
                }
            }
            Err(err) => Err(err)
        }
    }


    fn read_jwt(&self, token: String) -> Result<String, AuthHeaderError> {
        if !token.starts_with("Bearer ") {
            return Err(AuthHeaderError::InvalidAuthHeaderError);
        }
        Ok(token.trim_start_matches("Bearer ").to_owned())
    }
}



// fn decode_claims2(token_string: &str) -> Result<BTreeMap<String, String>, String> {
//     match token_string.split_once('.') {
//         Some((_header, message)) => {
//             match message.split_once('.') {
//                 Some((claims, _signature)) => {
//                     println!("hallo: {}", claims);
//                     let claim_map = BTreeMap::new();
//                     return Ok(claim_map)
//                 }
//                 None => Err("Invalid JWT: No signature found".into())
//             }
//         }
//         None => Err("Invalid JWT: No header found".into())
//     }
//
// }

fn decode_claims(token_string: &str) -> Result<BTreeMap<String, Value>, String> {
    let result = token_string.split_once('.');
    if result.is_none() {
        return Err("Invalid JWT: No header found".into());
    }
    let (_header, message) = result.unwrap();

    let result = message.split_once('.');
    if result.is_none() {
        return Err("Invalid JWT: No signature found".into());
    }
    let (claims, _signature) = result.unwrap();

    let decoded_claims = String::from_utf8(decode_config(claims, base64::URL_SAFE_NO_PAD).unwrap());
    if decoded_claims.is_err() {
        return Err("utf8 decode failure".into())
    }

    let result = serde_json::from_str(&decoded_claims.unwrap());
    if result.is_err() {
        return Err("serializing failure".into())
    }
    let claim_map: BTreeMap<String, serde_json::Value> = result.unwrap();
    Ok(claim_map)
}

#[cfg(test)]
mod tests {
    use crate::{decode_claims};

    #[test]
    fn test_decode_claims() {
        let jwt_string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJkZW1vIn0.BnBTjKUMizZyzaRXUR0epc9fjYyFSjErvY2bw64OKLA";
        let result = decode_claims(jwt_string);
        assert_eq!(result.is_ok(),true);
        let claims = result.unwrap();

        assert_eq!(claims.get("sub").unwrap(),"1234567890");
        assert_eq!(claims.get("name").unwrap(),"John Doe");
        assert_eq!(claims.get("iat").unwrap(),1516239022);
        assert_eq!(claims.get("iss").unwrap(),"demo");

    }
}
