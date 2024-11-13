use std::env;

use alloy::{
    consensus::TxEnvelope,
    eips::eip2718::Encodable2718,
    network::{Ethereum, EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    contract Preconf is ERC721, Ownable {
        bool public isMinted;
        string private _tokenURI;

        constructor() ERC721("Preconf", "BASED") Ownable(msg.sender) {}

        function mint(address to) public onlyOwner {
            require(!isMinted, "NFT already minted");
            _safeMint(to, 0); // Token ID will be 0 since it's a 1-of-1
            isMinted = true;
        }

        function setTokenURI(string memory newTokenURI) public onlyOwner {
            _tokenURI = newTokenURI;
        }

        function tokenURI(uint256 _tokenId) public view override returns (string memory) {
            return _tokenURI;
        }
    }
);

#[tokio::main]
async fn main() -> Result<()> {
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY is not set");
    let preconf_contract: Address = env::var("PRECONF_CONTRACT")
        .expect("PRECONF_CONTRACT is not set")
        .parse()?; // on holesky
    let rpc_url = env::var("ETH_RPC_URL").expect("ETH_RPC_URL is not set");
    let mint_to: Address = env::var("MINT_TO_ADDR")
        .expect("MINT_TO_ADDR is not set")
        .parse()?;
    let signer: PrivateKeySigner = private_key.parse()?;
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(&rpc_url)
        .await?;
    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(signer.address()).await?;
    // println!("addr: {:?}, nonce: {:?}", signer.address(), nonce);
    let preconf = Preconf::new(preconf_contract, provider.clone());
    let tx_req = preconf.mint(mint_to).into_transaction_request();
    // println!("tx_req: {:?}", tx_req);
    let tx_type = tx_req.clone().preferred_type() as u8;
    let gas_limit = provider.estimate_gas(&tx_req).await?;
    let estimate_fee = provider.estimate_eip1559_fees(None).await?;
    let tx_req = tx_req
        .from(signer.address())
        .transaction_type(tx_type)
        .gas_limit(gas_limit)
        .nonce(nonce + 1)
        .max_fee_per_gas(estimate_fee.max_fee_per_gas)
        .max_priority_fee_per_gas(estimate_fee.max_priority_fee_per_gas);
    // println!("tx_req: {:?}", tx_req);
    let envelope_tx =
        match <TransactionRequest as TransactionBuilder<Ethereum>>::with_chain_id(tx_req, chain_id)
            .build(&wallet)
            .await
        {
            Ok(tx) => tx,
            Err(e) => {
                println!("Error building transaction: {:?}", e);
                return Ok(());
            }
        };
    println!("envelope tx: {:?}", envelope_tx);
    let raw_bytes = envelope_to_raw_bytes(&envelope_tx);
    println!("raw tx: {:?}", raw_bytes);
    // note: uncomment this if you want to send raw tx to the network
    // let tx = provider
    //     .send_raw_transaction(raw_bytes.to_vec().as_slice())
    //     .await?;
    // println!("tx: {:?}", tx);
    Ok(())
}

pub fn envelope_to_raw_bytes(tx: &TxEnvelope) -> Bytes {
    let mut encoded = Vec::new();
    // tx.network_encode(&mut encoded);
    tx.encode_2718(&mut encoded);
    encoded.into()
}
