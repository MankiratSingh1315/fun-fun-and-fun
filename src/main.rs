use actix_web::{get, post, web, App, HttpServer, Responder};
use serde::Serialize;
use solana_sdk::signer::{keypair::Keypair, Signer};

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



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index).service(hello))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}