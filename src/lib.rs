pub mod forked_db;

use ethers::{prelude::*, utils::{parse_ether, keccak256}, abi::parse_abi};
use std::sync::Arc;
use std::str::FromStr;
use forked_db::{*, fork_factory::ForkFactory, fork_db::ForkDB};

use revm::primitives::{Bytecode, Bytes as rBytes, Address as rAddress, U256 as rU256, B256, AccountInfo, TransactTo, Log};
use bigdecimal::BigDecimal;
use lazy_static::lazy_static;
use revm::{
    inspector_handle_register,
    interpreter::{Interpreter, OpCode},
    Database, Evm, EvmContext, Inspector,
};



lazy_static!{
    pub static ref WETH: Address = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    pub static ref XERO: Address = Address::from_str("0xC5842df170b8C8D09EB851A8D5DB3dfa00669E3F").unwrap();
    pub static ref USDT: Address = Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    pub static ref USDC: Address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
}

#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub is_reverted: bool,
    pub logs: Vec<Log>,
    pub gas_used: u64,
    pub output: rBytes,
}


#[derive(Debug, Clone)]
pub struct Pool {
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub variant: PoolVariant,
}

impl Pool {
    pub fn variant(&self) -> U256 {
        match self.variant {
            PoolVariant::UniswapV2 => U256::zero(),
            PoolVariant::UniswapV3 => U256::one(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PoolVariant {
    UniswapV2,
    UniswapV3
}




pub async fn get_client() -> Result<Arc<Provider<Ws>>, anyhow::Error> {
    let url: &str = "wss://eth.merkle.io";
    let client = Provider::<Ws>::connect(url).await?;
    Ok(Arc::new(client))
}



/// Creates a new [Evm] instance with initial state from [ForkDB]
/// State changes are applied to [Evm]
pub fn new_evm(fork_db: ForkDB, block: Block<H256>, dummy_inspector: &mut DummyInspector) -> Evm<'_, &mut DummyInspector, ForkDB> {
    let mut evm = Evm::builder().with_db(fork_db)
        .with_external_context(dummy_inspector)
        .append_handler_register(inspector_handle_register)
        .build();


    let next_block = block.number.unwrap() + 1;
    let next_block = U256::from(next_block.as_u64());

    evm.block_mut().number = to_revm_u256(next_block);
    evm.block_mut().timestamp = to_revm_u256(block.timestamp + 12);
    evm.block_mut().coinbase = rAddress
        ::from_str("0xDecafC0FFEe15BAD000000000000000000000000")
        .unwrap();
    
    // Disable some checks for easier testing
    evm.cfg_mut().disable_balance_check = true;
    evm.cfg_mut().disable_block_gas_limit = true;
    evm.cfg_mut().disable_base_fee = true;
    evm
}



/// Simulates a call without any inspectors
/// Returns [SimulationResult]
pub fn sim_call<'a>(
    caller: Address,
    transact_to: Address,
    call_data: Bytes,
    value: U256,
    apply_changes: bool,
    evm: &mut Evm<'a, &'a mut DummyInspector, ForkDB>
) -> Result<SimulationResult, anyhow::Error> {
    evm.tx_mut().caller = caller.0.into();
    evm.tx_mut().transact_to = TransactTo::Call(transact_to.0.into());
    evm.tx_mut().data = rBytes::from(call_data.0);
    evm.tx_mut().value = to_revm_u256(value);


   let result = if apply_changes {
        evm.transact_commit()?
    } else {
        let res = evm.transact()?;
        res.result
    };

   println!("Simulation Result: {:?}", result);
   
    let is_reverted = match_output_reverted(&result);
    let logs = result.logs().to_vec();
    let gas_used = result.gas_used();
    let output = result.into_output().unwrap_or_default();

    let sim_result = SimulationResult {
        is_reverted,
        logs,
        gas_used,
        output,
    };

    Ok(sim_result)
}


/// Inserts a dummy EOA account to the fork factory
pub fn insert_dummy_account(fork_factory: &mut ForkFactory) -> Result<(), anyhow::Error> {

    // you can use whatever address you want for the dummy account as long as its a valid ethereum address and ideally not in use (Doesn't have a state)
    // you could use an online tool like: https://vanity-eth.tk/ to generate a random address
    let dummy_address = Address::from_str("0x0093562c7e4BcC8e4D256A27e08C9ae6Ac4F895c")?;

    // create a new account info
    // We also set 1 ETH in balance
    let account_info = AccountInfo {
        balance: rU256::from(1000000000000000000u128),
        nonce: 0,
        code_hash: B256::default(),
        code: None, // None because its not a contract
    };

    // insert the account info into the fork factory
    fork_factory.insert_account_info(dummy_address.0.into(), account_info);

    // Now we fund the dummy account with 1 WETH
    let xai_amount = U256::MAX;
    //let weth_address = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")?;
    let xai_address = Address::from_str("0xC5842df170b8C8D09EB851A8D5DB3dfa00669E3F")?;
    
    // To fund any ERC20 token to an account we need the balance storage slot of the token
    // For WETH its 3
    // An amazing online tool to see the storage mapping of any contract https://evm.storage/
    let xai_slot: U256 = keccak256(abi::encode(&[
        abi::Token::Address(dummy_address.0.into()),
        abi::Token::Uint(U256::from(1)),
    ])).into();

    // insert the erc20 token balance to the dummy account
    if let Err(e) = fork_factory.insert_account_storage(
        xai_address.0.into(),
        to_revm_u256(xai_slot),
        to_revm_u256(xai_amount),
    ) {
        return Err(anyhow::anyhow!("Failed to insert account storage: {}", e));
    }

    Ok(())
}
pub fn to_readable(amount: U256, token: Address) -> String {
    let decimals = match_decimals(token);
    let divisor_str = format!("1{:0>width$}", "", width = decimals as usize);
    let divisor = BigDecimal::from_str(&divisor_str).unwrap();
    let amount_as_decimal = BigDecimal::from_str(&amount.to_string()).unwrap();
    let amount = amount_as_decimal / divisor;
    let token = match token {
        t if t == *WETH => "WETH",
        t if t == *USDT => "USDT",
        t if t == *USDC => "USDC",
        _ => "Token"
    };
    format!("{:.4} {}", amount, token)
}

pub fn match_decimals(token: Address) -> u32 {
    match token {
       t if t == *WETH => 18,
       t if t == *USDT => 6,
       t if t == *USDC => 6,
        _ => 18
    }
}

pub fn erc20_balanceof() -> BaseContract {
    BaseContract::from(parse_abi(
        &["function balanceOf(address) public view returns (uint256)"]
    ).unwrap())
}

pub fn xai_transfer() -> BaseContract {
    BaseContract::from(parse_abi(
        &["function transfer(address to, uint256 amount) external virtual override returns (bool)"]
    ).unwrap())
}

#[derive(Default, Debug, Clone)]
pub struct DummyInspector {
    ret_val: Vec<String>,
}

impl<DB> Inspector<DB> for DummyInspector
where
    DB: Database,
{
    /// This method is called at each step of the EVM execution.
    /// It checks if the current opcode is valid and if so, it stores the opcode and its
    /// corresponding program counter in the `ret_val` vector.
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        if let Some(opcode) = OpCode::new(interp.current_opcode()) {
            match opcode {
                OpCode::GT | OpCode::LT => {
                    // Access the top two elements on the stack
                    let stack = interp.stack();
                    if stack.len() >= 2 {
                        let first = stack.peek(0).unwrap_or_default(); // Top of the stack
                        let second = stack.peek(1).unwrap_or_default(); // Second item on the stack
                        
                        // Print the current opcode, values being compared, and the program counter
                        let op_name = if opcode == OpCode::GT { "GT" } else { "LT" };
                        println!("{} at PC {}: comparing {} and {}", op_name, interp.program_counter(), first, second);
                        // Optionally store the result for later usage or analysis
                        self.ret_val.push(format!("{} at PC {}: {} > {}", op_name, interp.program_counter(), first, second));
                    }
                }
                _ => {}
            }
        }
    }
}
