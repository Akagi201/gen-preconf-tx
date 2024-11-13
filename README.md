# gen-preconf-tx

A tool to generate raw tx for preconf contract [0xc3591f9695a882fc9400889596cf8a609a06ef8c](https://etherscan.io/address/0xc3591f9695a882fc9400889596cf8a609a06ef8c)

## Usage

```sh
cargo build --release
export PRECONF_CONTRACT="0xc3591f9695a882fc9400889596cf8a609a06ef8c" # deployed preconf contract address
export ETH_RPC_URL="https://ethereum-rpc.publicnode.com"
export PRIVATE_KEY="0x111111" # the private key of the address which can mint the nft.
export MINT_TO_ADDR="" # the nft will be minted to this address
./target/release/gen-preconf-tx
```
