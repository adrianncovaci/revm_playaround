use ethers::{prelude::*, utils::parse_ether};
use revm_by_example::forked_db::bytes_to_string;
use std::str::FromStr;
use revm_by_example::{ forked_db::fork_factory::ForkFactory, * };

use revm::db::{ CacheDB, EmptyDB };



#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut dummy_inspector = DummyInspector::default();
    let client = get_client().await?;
    

    let latest_block = client.get_block_number().await?;
    let block = client.get_block(latest_block).await?;
    let cache_db = CacheDB::new(EmptyDB::default());
    let block_id = BlockId::Number(BlockNumber::Number(latest_block));

    let mut fork_factory = ForkFactory::new_sandbox_factory(
        client.clone(),
        cache_db,
        Some(block_id)
    );

    insert_dummy_account(&mut fork_factory)?;

    let fork_db = fork_factory.new_sandbox_fork();

    println!("Fork DB Accounts: {:?}", fork_db.db.accounts.keys());

    let mut evm = new_evm(fork_db.clone(), block.clone().unwrap(), &mut dummy_inspector);

    let dummy_address = Address::from_str("0x0093562c7e4BcC8e4D256A27e08C9ae6Ac4F895c")?;
    let receiver = Address::from_str("0x0093562c7E4BcC8e4D256A27E08C9ae6aC4f875C")?;
    let balance_of_data = erc20_balanceof().encode("balanceOf", dummy_address)?;

    let result = sim_call(
        Address::zero(),
        *XERO,
        balance_of_data.clone(),
        U256::zero(),
        false,
        &mut evm
    )?;

    assert!(!result.is_reverted, "BalanceOf call reverted, Reason: {:?}", bytes_to_string(result.output));

    let balance: U256 = erc20_balanceof().decode_output("balanceOf", &result.output)?;
    assert!(balance > parse_ether(1).unwrap(), "Balance is not bigger than 1 WETH: {}", balance);
    println!("Account Initial xai Balance: {}", to_readable(balance, *XERO));
    
    let value = U256::MAX;

    let transfer = xai_transfer().encode("transfer", (receiver, value))?;
    
    let _result = sim_call(
        dummy_address,
        *XERO,
        transfer,
        U256::zero(),
        false,
        &mut evm
    )?;
    
    drop(evm);
    
    println!("dummy_inspector: {:?}", dummy_inspector);

    Ok(())
}
