use actix_web::{get, post, web, App, HttpServer, Responder, middleware::Logger};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
};
use spl_token::{
    instruction::{initialize_mint, mint_to},
    ID as TOKEN_PROGRAM_ID,
};
use std::str::FromStr;

#[get("/")]
async fn index() -> impl Responder {
    "Hello, World!"
}
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    data: KeypairData,
}

#[post("/keypair")]
async fn hello() -> impl Responder {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    web::Json(ApiResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    })
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct TokenInstructionData {
    program_id: String,
    accounts: serde_json::Value, 
    instruction_data: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct TokenApiResponse {
    success: bool,
    data: TokenInstructionData,
}

#[post("/token/create")]
async fn create_token(req_body: web::Json<CreateTokenRequest>) -> web::Json<serde_json::Value> {
    let mint_authority = match Pubkey::from_str(&req_body.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid mintAuthority public key".to_string(),
            }).unwrap());
        }
    };
    
    let mint = match Pubkey::from_str(&req_body.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid mint public key".to_string(),
            }).unwrap());
        }
    };
    
    let decimals = req_body.decimals;
    
    let instruction = initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint,
        &mint_authority,
        Some(&mint_authority), 
        decimals,
    ).unwrap();
    
    let mut accounts_obj = serde_json::Map::new();
    for (i, acc) in instruction.accounts.iter().enumerate() {
        let account_info = serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        });
        accounts_obj.insert(format!("account_{}", i), account_info);
    }
    let accounts = serde_json::Value::Object(accounts_obj);
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    web::Json(serde_json::to_value(TokenApiResponse {
        success: true,
        data: TokenInstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }).unwrap())
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: SignMessageData,
}

#[post("/token/mint")]
async fn mint_token(req_body: web::Json<MintTokenRequest>) -> web::Json<serde_json::Value> {
    let mint = match Pubkey::from_str(&req_body.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid mint public key".to_string(),
            }).unwrap());
        }
    };
    
    let destination = match Pubkey::from_str(&req_body.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid destination public key".to_string(),
            }).unwrap());
        }
    };
    
    let authority = match Pubkey::from_str(&req_body.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid authority public key".to_string(),
            }).unwrap());
        }
    };
    
    let amount = req_body.amount;
    
    let instruction = mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination,
        &authority,
        &[],
        amount,
    ).unwrap();
    
    let mut accounts_obj = serde_json::Map::new();
    for (i, acc) in instruction.accounts.iter().enumerate() {
        let account_info = serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        });
        accounts_obj.insert(format!("account_{}", i), account_info);
    }
    let accounts = serde_json::Value::Object(accounts_obj);
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    web::Json(serde_json::to_value(TokenApiResponse {
        success: true,
        data: TokenInstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }).unwrap())
}

#[post("/message/sign")]
async fn sign_message(req_body: web::Json<SignMessageRequest>) -> web::Json<serde_json::Value> {
    // Check for missing fields
    if req_body.message.is_empty() || req_body.secret.is_empty() {
        return web::Json(serde_json::to_value(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        }).unwrap());
    }
    
    // Decode the secret key from base58
    let secret_bytes = match bs58::decode(&req_body.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid secret key format".to_string(),
            }).unwrap());
        }
    };
    
    // Create keypair from secret bytes
    let keypair = match Keypair::try_from(secret_bytes.as_slice()) {
        Ok(kp) => kp,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid secret key".to_string(),
            }).unwrap());
        }
    };
    
    // Sign the message
    let message_bytes = req_body.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    // Encode signature to base64
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());
    
    // Get public key as base58
    let public_key = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    
    web::Json(serde_json::to_value(SignMessageResponse {
        success: true,
        data: SignMessageData {
            signature: signature_b64,
            public_key,
            message: req_body.message.clone(),
        },
    }).unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(index)
            .service(hello)
            .service(create_token)
            .service(mint_token)
            .service(sign_message)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}