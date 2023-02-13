use anyhow::{Context, Result};
use smoke_test::{
    smoke_test_environment::new_local_swarm,
    test_utils::{assert_balance, create_and_fund_account}, 
    operational_tooling::launch_swarm_with_op_tool_and_backend,
};
use diem_global_constants::{OWNER_ACCOUNT, OWNER_KEY};
use diem_types::account_address::AccountAddress;
use diem_sdk::{types::{LocalAccount, AccountKey}};
use forge::{NodeExt, Swarm, self};
use std::time::{Duration, Instant};
use diem_secure_storage::CryptoStorage;
use diem_secure_storage::KVStorage;
use std::{
    path::{PathBuf},
    process::Command,
};
use serde::Deserialize;
use diem_wallet::{Mnemonic, WalletLibrary};

#[derive(Debug, Deserialize)]
struct Metadata {
    pub workspace_root: PathBuf,
}

fn metadata() -> Result<Metadata> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version=1")
        .output()
        .context("Failed to query cargo metadata")?;

    serde_json::from_slice(&output.stdout).map_err(Into::into)
}


#[tokio::test]
async fn ol_test_demo() {
    let (mut swarm, _op_tool, _backend, storage) = launch_swarm_with_op_tool_and_backend(1).await;
    let owner_account = storage.get::<AccountAddress>(OWNER_ACCOUNT).unwrap().value;
    let keys = storage.export_private_key(OWNER_KEY).unwrap();
    let mut local_acct = LocalAccount::new(owner_account, keys, 0);
    swarm.chain_info().ol_send_demo_tx(&mut local_acct).await.unwrap();
}


#[tokio::test]
async fn ol_test_create_account() {
    // create swarm
    let (mut swarm, _op_tool, _backend, storage) = launch_swarm_with_op_tool_and_backend(1).await;

    let client = swarm.validators().next().unwrap().rest_client();
    // get the localaccount type for the first validator (which is the only account on the swarm chain)
    let owner_account = storage.get::<AccountAddress>(OWNER_ACCOUNT).unwrap().value;
    let keys = storage.export_private_key(OWNER_KEY).unwrap();
    let local_acct = LocalAccount::new(owner_account, keys, 0);

    // create a random account.
    let new_account = LocalAccount::generate(&mut rand::rngs::OsRng);

    swarm.chain_info().ol_create_account_by_coin(local_acct, &new_account).await.unwrap();

    assert_balance(&client, &new_account, 1000000).await;
}

#[tokio::test]
async fn ol_test_create_and_fund() {
    let mut swarm = new_local_swarm(1).await;
    let client = swarm.validators().next().unwrap().rest_client();

    let mut c = swarm.chain_info();
    let root = c.root_account();
    assert_balance(&client, root, 10000000).await;

    let account_0 = create_and_fund_account(&mut swarm, 100).await;

    assert_balance(&client, &account_0, 100).await;
}

#[tokio::test]
async fn ol_test_basic_restartability() {
    let mut swarm = new_local_swarm(4).await;
    let validator = swarm.validators_mut().next().unwrap();
    validator.restart().await.unwrap();
    validator
        .wait_until_healthy(Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    dbg!("validator healthy");
    let client = validator.rest_client();
    swarm.chain_info().ol_send_demo_tx_root(Some(client)).await.expect("could not send tx");
    dbg!("tx sent");
}

#[tokio::test]
async fn ol_test_mining() {
    // create swarm
    let (mut swarm, _op_tool, _backend, storage) = launch_swarm_with_op_tool_and_backend(1).await;

    let validator = swarm.validators().next().unwrap();
    let rpc_client = validator.json_rpc_client();
    let rest_client = validator.rest_client();

    // get the localaccount type for the first validator (which is the only account on the swarm chain)
    let owner_account = storage.get::<AccountAddress>(OWNER_ACCOUNT).unwrap().value;
    let keys = storage.export_private_key(OWNER_KEY).unwrap();
    let local_acct = LocalAccount::new(owner_account, keys, 0);

    // initializing new account
    let persona = "alice";
    let metadata = metadata().unwrap();

    let mnemonic_path = metadata.workspace_root.join(
        format!(
            "ol/fixtures/mnemonic/{}.mnem",
            persona
        )
    );

    let mnemonic = std::fs::read_to_string(mnemonic_path).unwrap();
    let mnem = Mnemonic::from(&mnemonic).unwrap();

    let mut wallet = WalletLibrary::new_from_mnemonic(mnem);
    wallet.generate_addresses(1).unwrap();
    let address = wallet.get_addresses().unwrap().into_iter().next().unwrap();
    let private_key = wallet.get_private_key(&address).unwrap();
    let account_key = AccountKey::from_private_key(private_key);

    let new_account = LocalAccount::new(address, account_key, 0);

    // create and fund the new account
    swarm.chain_info().ol_create_account_by_coin(local_acct, &new_account).await.unwrap();

    assert_balance(&rest_client, &new_account, 1_000_000).await;

    match rpc_client.get_miner_state(address) {
        Err(err) => {
            let err = err.json_rpc_error().unwrap();
            assert_eq!(err.message, "Server error: could not get tower state");
        },
        _ => {
            panic!("miner state for new account shouldn't exists");
        },
    }

    // Proof #0
    let proof_path = metadata.workspace_root.join(
        format!(
            "ol/fixtures/vdf_proofs/stage/{}/proof_0.json",
            persona
        )
    );
    let proof = std::fs::read_to_string(proof_path).unwrap();
    let block: ol_types::block::VDFProof = serde_json::from_str(&proof).unwrap();
    swarm.chain_info().ol_commit_proof(new_account, block).await.unwrap();

    let miner_state = rpc_client.get_miner_state(address).unwrap();
    let miner_state = miner_state.inner().as_ref().unwrap();

    assert_eq!(miner_state.verified_tower_height, 0);
    assert_eq!(miner_state.latest_epoch_mining, 1);
    assert_eq!(miner_state.count_proofs_in_epoch, 1);
    assert_eq!(miner_state.epochs_validating_and_mining, 0);
    assert_eq!(miner_state.epochs_since_last_account_creation, 0);
    assert_eq!(miner_state.actual_count_proofs_in_epoch, 1);
}
