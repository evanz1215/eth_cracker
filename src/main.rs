use chrono::Local;
use dotenv::dotenv;
use ethers::abi::Abi;
use ethers::{prelude::*, utils::hex};
use rand::Rng;
use rayon::prelude::*;
use std::collections::HashMap;
use std::env;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use tokio::runtime::Runtime;

// ✅ 支援 ETH / BNB / ERC20 / BEP20 代幣
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

// ✅ 追蹤已檢查私鑰數量
static CHECKED_KEYS: AtomicUsize = AtomicUsize::new(0);

// ✅ 使用 `OnceLock` 延遲初始化 `HashMap`
static BALANCE_TRACKER: OnceLock<Mutex<HashMap<String, U256>>> = OnceLock::new();

/// 初始化 `BALANCE_TRACKER`
fn get_balance_tracker() -> &'static Mutex<HashMap<String, U256>> {
    BALANCE_TRACKER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 產生隨機私鑰
fn generate_random_private_key() -> H256 {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    H256::from(bytes)
}

/// 轉換私鑰為 ETH / BNB 地址
fn private_key_to_address(private_key: &H256) -> Address {
    let wallet = LocalWallet::from_bytes(private_key.as_bytes()).unwrap();
    wallet.address()
}

/// 查詢 ETH / BNB 或 ERC20 / BEP20 代幣餘額
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

/// 取得 ERC20 / BEP20 代幣 ABI
fn abi() -> Abi {
    serde_json::from_str(
        r#"[{
            "constant": true,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        }]"#,
    )
    .unwrap()
}

/// 儲存結果到文件
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

/// 更新幣種餘額統計
fn update_balance_tracker(token: &str, amount: U256) {
    let tracker = get_balance_tracker();
    let mut tracker_lock = tracker.lock().unwrap();
    let entry = tracker_lock
        .entry(token.to_string())
        .or_insert(U256::zero());
    *entry += amount;
}

/// 顯示目前所有幣種餘額
fn display_balance_summary() {
    let tracker = get_balance_tracker();
    let tracker_lock = tracker.lock().unwrap();
    println!("📊 當前總餘額統計：");
    for (token, balance) in tracker_lock.iter() {
        println!("   - {}: {}", token, balance);
    }
}

/// 主程式
fn main() {
    dotenv().ok();
    let api_key = env::var("ALCHEMY_API_KEY").expect("Missing ALCHEMY_API_KEY in .env");
    let rpc_url = format!("https://eth-mainnet.g.alchemy.com/v2/{}", api_key);
    let client = Arc::new(Provider::<Http>::try_from(rpc_url).unwrap());

    let rt = Runtime::new().unwrap();
    let handle = rt.handle();

    // 讀取 `MAX_KEYS` 參數
    let max_keys: usize = env::var("MAX_KEYS")
        .unwrap_or("0".to_string())
        .parse()
        .expect("MAX_KEYS 必須是數字");

    println!("🎯 目標: 檢查 {} 個私鑰 (0 = 無限運行)", max_keys);

    loop {
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

            handle.block_on(async move {
                for &token in &TOKEN_LIST {
                    let balance = get_balance(&client_clone, address, token).await;
                    if balance > U256::zero() {
                        save_to_file(address, private_key, token, balance);
                        update_balance_tracker(token, balance);
                    }
                }
            });

            if current_count % 100 == 0 {
                println!("🚀 進度: 已檢查 {} 個私鑰...", current_count);
                display_balance_summary();
            }

            if max_keys > 0 && current_count >= max_keys {
                println!("✅ 任務完成！共檢查 {} 個私鑰", max_keys);
                std::process::exit(0);
            }
        });
    }
}
