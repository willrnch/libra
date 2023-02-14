// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{Coffer, NFTPublicInfo, PublicInfo, Result};
use diem_rest_client::Client as RestClient;
use diem_sdk::{
    client::BlockingClient,
    transaction_builder::{Currency, TransactionFactory, self},
    types::{
        account_address::AccountAddress, chain_id::ChainId,
        transaction::{authenticator::AuthenticationKey}, LocalAccount,
    },
};
use reqwest::Url;

#[derive(Debug)]
pub struct ChainInfo<'t> {
    pub root_account: &'t mut LocalAccount,
    pub treasury_compliance_account: &'t mut LocalAccount,
    pub designated_dealer_account: &'t mut LocalAccount,
    pub json_rpc_url: String,
    pub rest_api_url: String,
    pub chain_id: ChainId,
}

impl<'t> ChainInfo<'t> {
    pub fn new(
        root_account: &'t mut LocalAccount,
        treasury_compliance_account: &'t mut LocalAccount,
        designated_dealer_account: &'t mut LocalAccount,
        json_rpc_url: String,
        rest_api_url: String,
        chain_id: ChainId,
    ) -> Self {
        Self {
            root_account,
            treasury_compliance_account,
            designated_dealer_account,
            json_rpc_url,
            rest_api_url,
            chain_id,
        }
    }

    pub fn designated_dealer_account(&mut self) -> &mut LocalAccount {
        self.designated_dealer_account
    }

    pub fn root_account(&mut self) -> &mut LocalAccount {
        self.root_account
    }

    pub fn treasury_compliance_account(&mut self) -> &mut LocalAccount {
        self.root_account //////// 0L ////////
    }

    pub fn json_rpc(&self) -> &str {
        &self.json_rpc_url
    }

    pub fn json_rpc_client(&self) -> BlockingClient {
        BlockingClient::new(&self.json_rpc_url)
    }

    pub fn rest_api(&self) -> &str {
        &self.rest_api_url
    }

    pub fn rest_client(&self) -> RestClient {
        RestClient::new(Url::parse(self.rest_api()).unwrap())
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn transaction_factory(&self) -> TransactionFactory {
        TransactionFactory::new(self.chain_id())
    }

    pub async fn create_parent_vasp_account(
        &mut self,
        currency: Currency,
        authentication_key: AuthenticationKey,
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = self.rest_client();
        let treasury_compliance_account = self.treasury_compliance_account();

        let create_account_txn = treasury_compliance_account.sign_with_transaction_builder(
            factory.create_parent_vasp_account(
                currency,
                0,
                authentication_key,
                &format!("No. {} VASP", treasury_compliance_account.sequence_number()),
                false,
            ),
        );
        client.submit_and_wait(&create_account_txn).await?;
        Ok(())
    }

    pub async fn create_designated_dealer_account(
        &mut self,
        currency: Currency,
        authentication_key: AuthenticationKey,
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = self.rest_client();
        let treasury_compliance_account = self.treasury_compliance_account();

        let create_account_txn = treasury_compliance_account.sign_with_transaction_builder(
            factory.create_designated_dealer(
                currency,
                0, // sliding_nonce
                authentication_key,
                &format!("No. {} DD", treasury_compliance_account.sequence_number()),
                false, // add all currencies
            ),
        );
        client.submit_and_wait(&create_account_txn).await?;
        Ok(())
    }

    pub async fn fund(
        &mut self,
        currency: Currency,
        address: AccountAddress,
        amount: u64,
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = self.rest_client();
        let designated_dealer_account = self.root_account(); //////// 0L ////////
        let fund_account_txn = designated_dealer_account
            .sign_with_transaction_builder(factory.peer_to_peer(currency, address, amount));
        client.submit_and_wait(&fund_account_txn).await?;
        Ok(())
    }

    //////// 0L ////////
    /// Prints a single line of output to the node console.
    pub async fn ol_send_demo_tx(
        &mut self,
        account: &mut LocalAccount,
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = self.rest_client();
        // let diem_root = self.root_account();
        let txn = account
            .sign_with_transaction_builder(
              factory.payload(
                transaction_builder::stdlib::encode_demo_e2e_script_function(42)
              )
            );
        client.submit_and_wait(&txn).await?;
        Ok(())
    }

    //////// 0L ////////
    /// Prints a single line of output to the node console.
    pub async fn ol_send_demo_tx_root(
        &mut self,
        client: Option<RestClient>,
        // account: &mut LocalAccount,
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = client.unwrap_or(self.rest_client());

        let account = self.root_account();
        // let diem_root = self.root_account();
        let txn = account
            .sign_with_transaction_builder(
              factory.payload(
                transaction_builder::stdlib::encode_demo_e2e_script_function(42)
              )
            );
        client.submit_and_wait(&txn).await?;
        Ok(())
    }

    //////// 0L ////////
    /// Create account with coin.
    pub async fn ol_create_account_by_coin(
        &mut self,
        mut sending_account: LocalAccount,
        new_account: &LocalAccount,
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = self.rest_client();
        // let diem_root = self.root_account();
        let txn = sending_account
            .sign_with_transaction_builder(
              factory.payload(
                transaction_builder::stdlib::encode_create_user_by_coin_tx_script_function(
                  new_account.address(), 
                  new_account.authentication_key().prefix().to_vec(),
                  1
                )
              )
            );
        client.submit_and_wait(&txn).await?;
        Ok(())
    }

    pub fn into_public_info(self) -> PublicInfo<'t> {
        PublicInfo::new(
            self.json_rpc_url.clone(),
            self.chain_id,
            Coffer::TreasuryCompliance {
                transaction_factory: TransactionFactory::new(self.chain_id),
                rest_client: self.rest_client(),
                treasury_compliance_account: self.root_account, //////// 0L ////////
                designated_dealer_account: self.designated_dealer_account,
            },
            self.rest_api_url.clone(),
        )
    }

    pub fn into_nft_public_info(self) -> NFTPublicInfo<'t> {
        NFTPublicInfo::new(self.chain_id, self.rest_api_url.clone(), self.root_account)
    }

    /// Commit miner proof
    pub async fn ol_commit_proof(
        &mut self,
        mut account: LocalAccount,
        block: ol_types::block::VDFProof
    ) -> Result<()> {
        let factory = self.transaction_factory();
        let client = self.rest_client();


        let payload = transaction_builder::stdlib::encode_minerstate_commit_script_function(
           block.preimage.clone(),
           block.proof.clone(),
           block.difficulty(),
           block.security(),
        );

        println!("payload = {:?}", payload);
        
        println!("sign_with_transaction_builder");
        let txn = account
            .sign_with_transaction_builder(
                factory.payload(payload)
            );

        println!("client.submit_and_wait(&txn).await?;");

        match client.submit_and_wait(&txn).await {
            Ok(res) => {

            },
            Err(err) => {
                println!("error = {:?}", err);
            }
        }

        Ok(())
    }
}
