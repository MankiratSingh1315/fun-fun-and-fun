use actix_web::{get, post, web, App, HttpServer, Responder, middleware::Logger};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    system_instruction::transfer,
};
use spl_token::{
    instruction::{initialize_mint, mint_to, transfer as token_transfer},
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
    accounts: Vec<serde_json::Value>, 
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
    
    let accounts: Vec<serde_json::Value> = instruction.accounts.iter().map(|acc| {
        serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        })
    }).collect();
    
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

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: SignMessageData,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: VerifyMessageData,
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
    
    let accounts: Vec<serde_json::Value> = instruction.accounts.iter().map(|acc| {
        serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        })
    }).collect();
    
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

#[post("/message/verify")]
async fn verify_message(req_body: web::Json<VerifyMessageRequest>) -> web::Json<serde_json::Value> {
    // Check for missing fields
    if req_body.message.is_empty() || req_body.signature.is_empty() || req_body.pubkey.is_empty() {
        return web::Json(serde_json::to_value(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        }).unwrap());
    }
    
    // Decode the public key from base58
    let pubkey_bytes = match bs58::decode(&req_body.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid public key format".to_string(),
            }).unwrap());
        }
    };
    
    // Create pubkey from bytes
    let pubkey = match Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid public key".to_string(),
            }).unwrap());
        }
    };
    
    // Decode the signature from base64
    let signature_bytes = match general_purpose::STANDARD.decode(&req_body.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid signature format".to_string(),
            }).unwrap());
        }
    };
    
    // Create signature from bytes
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid signature".to_string(),
            }).unwrap());
        }
    };
    
    // Verify the signature
    let message_bytes = req_body.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);
    
    web::Json(serde_json::to_value(VerifyMessageResponse {
        success: true,
        data: VerifyMessageData {
            valid: is_valid,
            message: req_body.message.clone(),
            pubkey: req_body.pubkey.clone(),
        },
    }).unwrap())
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String, // Destination user address
    mint: String,        // Mint address
    owner: String,       // Owner address
    amount: u64,
}

#[post("/send/sol")]
async fn send_sol(req_body: web::Json<SendSolRequest>) -> web::Json<serde_json::Value> {
    // Check for missing fields and validate inputs
    if req_body.from.is_empty() || req_body.to.is_empty() {
        return web::Json(serde_json::to_value(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        }).unwrap());
    }
    
    // Validate lamports amount (must be positive)
    if req_body.lamports == 0 {
        return web::Json(serde_json::to_value(ErrorResponse {
            success: false,
            error: "Lamports amount must be greater than 0".to_string(),
        }).unwrap());
    }
    
    let from = match Pubkey::from_str(&req_body.from) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid from public key".to_string(),
            }).unwrap());
        }
    };
    
    let to = match Pubkey::from_str(&req_body.to) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid to public key".to_string(),
            }).unwrap());
        }
    };
    
    let lamports = req_body.lamports;
    
    let instruction = transfer(
        &from,
        &to,
        lamports,
    );
    
    let accounts: Vec<serde_json::Value> = instruction.accounts.iter().map(|acc| {
        serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        })
    }).collect();
    
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

#[post("/send/token")]
async fn send_token(req_body: web::Json<SendTokenRequest>) -> web::Json<serde_json::Value> {
    // Check for missing fields and validate inputs
    if req_body.destination.is_empty() || req_body.mint.is_empty() || req_body.owner.is_empty() {
        return web::Json(serde_json::to_value(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        }).unwrap());
    }
    
    // Validate amount (must be positive)
    if req_body.amount == 0 {
        return web::Json(serde_json::to_value(ErrorResponse {
            success: false,
            error: "Amount must be greater than 0".to_string(),
        }).unwrap());
    }
    
    let destination = match Pubkey::from_str(&req_body.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid destination user address".to_string(),
            }).unwrap());
        }
    };
    
    let mint = match Pubkey::from_str(&req_body.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid mint address".to_string(),
            }).unwrap());
        }
    };
    
    let owner = match Pubkey::from_str(&req_body.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return web::Json(serde_json::to_value(ErrorResponse {
                success: false,
                error: "Invalid owner address".to_string(),
            }).unwrap());
        }
    };
    
    let amount = req_body.amount;
    
    // Use token_transfer for transferring tokens between accounts
    let instruction = token_transfer(
        &TOKEN_PROGRAM_ID,
        &mint,         // source token account
        &destination,  // destination token account
        &owner,        // owner of source account
        &[],           // multisig signers
        amount,
    ).unwrap();
    
    // Convert accounts to array format with camelCase
    let mut accounts_array = Vec::new();
    for acc in instruction.accounts.iter() {
        let account_info = serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "isSigner": acc.is_signer
        });
        accounts_array.push(account_info);
    }
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let response = serde_json::json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": accounts_array,
            "instruction_data": instruction_data
        }
    });
    
    web::Json(response)
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
            .service(verify_message)
            .service(send_sol)
            .service(send_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}