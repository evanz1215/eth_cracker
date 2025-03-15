use chrono::Local;
use dotenv::dotenv;
use ethers::abi::Abi;
use ethers::{prelude::*, utils::hex};
use rand::Rng;
use rayon::prelude::*;
use serde_json;
use std::env;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::runtime::Runtime;

const TOKEN_LIST: [&str; 11] = [
    "ETH",                                        // ETH 餘額
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
    "0xC02aaa39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    "0x514910771AF9Ca656af840dff83E8264EcF986CA", // LINK
    "0x111111111117dC0aa78b770fA6A738034120C302", // 1INCH
    "0x0D8775F648430679A709E98d2b0Cb6250d2887EF", // BAT
    "0x408e41876cCCDC0F92210600ef50372656052a38", // REN
    "0x4fabb145d64652a948d72533023f6e7a623c7c53", // BUSD
    "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", // SHIBA
];

static CHECKED_KEYS: AtomicUsize = AtomicUsize::new(0);

/// 生成隨機私鑰
fn generate_random_private_key() -> H256 {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    H256::from(bytes)
}

/// 轉換私鑰為 ETH 地址
fn private_key_to_address(private_key: &H256) -> Address {
    let wallet = LocalWallet::from_bytes(private_key.as_bytes()).unwrap();
    wallet.address()
}

/// 查詢 ERC20 代幣餘額或 ETH 餘額
async fn get_balance(client: &Provider<Http>, address: Address, token: &str) -> U256 {
    if token == "ETH" {
        match client.get_balance(address, None).await {
            Ok(balance) => balance,
            Err(_) => U256::zero(),
        }
    } else {
        let token_address: Address = token.parse().unwrap();
        let token_contract = Contract::new(token_address, abi(), Arc::new(client.clone()));
        match token_contract
            .method::<_, U256>("balanceOf", address)
            .unwrap()
            .call()
            .await
        {
            Ok(balance) => balance,
            Err(_) => U256::zero(),
        }
    }
}

/// 獲取 ERC20 代幣 ABI
fn abi() -> Abi {
    serde_json::from_str(
        r#"[
        {
            "constant": true,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        }
    ]"#,
    )
    .unwrap()
}

/// 保存結果
fn save_to_file(address: Address, private_key: H256, token: &str, balance: U256) {
    let date = Local::now().format("%Y-%m-%d").to_string();
    let file_path = format!("results/{}.txt", date);

    create_dir_all("results").unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)
        .unwrap();

    let line = format!(
        "\n✅ 找到餘額! \n地址: {:?}\n私鑰: {:?}\n代幣: {}\n餘額: {}\n",
        address, private_key, token, balance
    );

    println!("{}", line);
    file.write_all(line.as_bytes()).unwrap();
}

/// 主執行邏輯
fn main() {
    dotenv().ok();
    let api_key = env::var("ALCHEMY_API_KEY").expect("Missing ALCHEMY_API_KEY in .env");
    let rpc_url = format!("https://eth-mainnet.g.alchemy.com/v2/{}", api_key);
    let client = Arc::new(Provider::<Http>::try_from(rpc_url).unwrap());

    let rt = Runtime::new().unwrap();
    let handle = rt.handle();

    (0..10_000).into_par_iter().for_each(|_| {
        let private_key = generate_random_private_key();
        let address = private_key_to_address(&private_key);
        let client_clone = Arc::clone(&client);
        let private_key_hex = format!("0x{}", hex::encode(private_key.as_bytes()));

        let current_count = CHECKED_KEYS.fetch_add(1, Ordering::Relaxed);

        println!(
            "🔎 檢查中: {} | 地址: {:?} | 私鑰: {}",
            current_count, address, private_key_hex
        );

        if current_count % 1000 == 0 {
            println!("🚀 進度: 已檢查 {} 個私鑰...", current_count);
        }

        handle.block_on(async move {
            for &token in &TOKEN_LIST {
                let balance = get_balance(&client_clone, address, token).await;
                if balance > U256::zero() {
                    save_to_file(address, private_key, token, balance);
                }
            }
        });
    });

    println!(
        "✅ 任務完成！共檢查 {} 個私鑰",
        CHECKED_KEYS.load(Ordering::Relaxed)
    );
}
