
#[macro_use]
extern crate jsonrpc_client_core;

extern crate serde_json;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
/// Keccak
///
/// Hex representation of a Keccak 256 hash
///
pub type Keccak = String;
/// Null
///
/// Null
///
pub type Null = serde_json::Value;
#[derive(Serialize, Deserialize)]
pub enum BlockHashOrNull {
    Keccak,
    Null
}
/// BlockNumber
///
/// The hex representation of the block's height
///
pub type BlockNumber = String;
#[derive(Serialize, Deserialize)]
pub enum BlockNumberOrNull {
    BlockNumber,
    Null
}
/// From
///
/// The sender of the transaction
///
pub type From = String;
/// TransactionGas
///
/// The gas limit provided by the sender in Wei
///
pub type TransactionGas = String;
/// TransactionGasPrice
///
/// The gas price willing to be paid by the sender in Wei
///
pub type TransactionGasPrice = String;
/// TransactionHash
///
/// Keccak 256 Hash of the RLP encoding of a transaction
///
pub type TransactionHash = String;
/// TransactionInput
///
/// The data field sent with the transaction
///
pub type TransactionInput = String;
/// TransactionNonce
///
/// The total number of prior transactions made by the sender
///
pub type TransactionNonce = String;
pub type Address = String;
#[derive(Serialize, Deserialize)]
pub enum To {
    Address,
    Null
}
/// Integer
///
/// Hex representation of the integer
///
pub type Integer = String;
#[derive(Serialize, Deserialize)]
pub enum TransactionIndex {
    Integer,
    Null
}
/// TransactionValue
///
/// Value of Ether being transferred in Wei
///
pub type TransactionValue = String;
/// TransactionSigV
///
/// ECDSA recovery id
///
pub type TransactionSigV = String;
/// TransactionSigR
///
/// ECDSA signature r
///
pub type TransactionSigR = String;
/// TransactionSigS
///
/// ECDSA signature s
///
pub type TransactionSigS = String;
/// BlockNumberTag
///
/// The optional block height description
///
#[derive(Serialize, Deserialize)]
pub enum BlockNumberTag {
    #[serde(rename = "earliest")]
    Earliest,
    #[serde(rename = "latest")]
    Latest,
    #[serde(rename = "pending")]
    Pending,
}
/// Addresses
///
/// List of contract addresses from which to monitor events
///
pub type Addresses = Vec<Address>;
#[derive(Serialize, Deserialize)]
pub enum OneOrArrayOfAddresses {
    Address,
    Addresses
}
/// Topic
///
/// 32 Bytes DATA of indexed log arguments. (In solidity: The first topic is the hash of the signature of the event (e.g. Deposit(address,bytes32,uint256))
///
pub type Topic = String;
/// LogTopics
///
/// Topics are order-dependent. Each topic can also be an array of DATA with 'or' options.
///
pub type LogTopics = Vec<Topic>;
/// StorageProofKey
///
/// The key used to get the storage slot in its account tree.
///
pub type StorageProofKey = String;
pub type From = String;
pub type AnyR7Vdx79W = serde_json::Value;
#[derive(Serialize, Deserialize)]
pub struct Transaction {
    pub(crate) blockHash: Option<BlockHashOrNull>,
    pub(crate) blockNumber: Option<BlockNumberOrNull>,
    pub(crate) from: Option<From>,
    pub(crate) gas: TransactionGas,
    pub(crate) gasPrice: TransactionGasPrice,
    pub(crate) hash: Option<TransactionHash>,
    pub(crate) input: Option<TransactionInput>,
    pub(crate) nonce: TransactionNonce,
    pub(crate) to: Option<To>,
    pub(crate) transactionIndex: Option<TransactionIndex>,
    pub(crate) value: Option<TransactionValue>,
    pub(crate) v: Option<TransactionSigV>,
    pub(crate) r: Option<TransactionSigR>,
    pub(crate) s: Option<TransactionSigS>,
}
pub type ObjectHAgrRKSz = HashMap<String, Option<serde_json::Value>>;
/// BlockHash
///
/// The hex representation of the Keccak 256 of the RLP encoded block
///
pub type BlockHash = String;
/// Nonce
///
/// A number only to be used once
///
pub type Nonce = String;
#[derive(Serialize, Deserialize)]
pub enum NonceOrNull {
    Nonce,
    Null
}
/// BlockShaUncles
///
/// Keccak hash of the uncles data in the block
///
pub type BlockShaUncles = String;
/// BlockLogsBloom
///
/// The bloom filter for the logs of the block or null when its the pending block
///
pub type BlockLogsBloom = String;
/// BlockTransactionsRoot
///
/// The root of the transactions trie of the block.
///
pub type BlockTransactionsRoot = String;
/// BlockStateRoot
///
/// The root of the final state trie of the block
///
pub type BlockStateRoot = String;
/// BlockReceiptsRoot
///
/// The root of the receipts trie of the block
///
pub type BlockReceiptsRoot = String;
#[derive(Serialize, Deserialize)]
pub enum AddressOrNull {
    Address,
    Null
}
/// BlockDifficulty
///
/// Integer of the difficulty for this block
///
pub type BlockDifficulty = String;
#[derive(Serialize, Deserialize)]
pub enum BlockTotalDifficulty {
    Integer,
    Null
}
/// BlockExtraData
///
/// The 'extra data' field of this block
///
pub type BlockExtraData = String;
/// BlockSize
///
/// Integer the size of this block in bytes
///
pub type BlockSize = String;
/// BlockGasLimit
///
/// The maximum gas allowed in this block
///
pub type BlockGasLimit = String;
/// BlockGasUsed
///
/// The total used gas by all transactions in this block
///
pub type BlockGasUsed = String;
/// BlockTimeStamp
///
/// The unix timestamp for when the block was collated
///
pub type BlockTimeStamp = String;
#[derive(Serialize, Deserialize)]
pub enum TransactionOrTransactionHash {
    Transaction,
    TransactionHash
}
/// TransactionsOrHashes
///
/// Array of transaction objects, or 32 Bytes transaction hashes depending on the last given parameter
///
pub type TransactionsOrHashes = Vec<TransactionOrTransactionHash>;
/// UncleHash
///
/// Block hash of the RLP encoding of an uncle block
///
pub type UncleHash = String;
/// UncleHashes
///
/// Array of uncle hashes
///
pub type UncleHashes = Vec<UncleHash>;
/// Block
///
/// The Block is the collection of relevant pieces of information (known as the block header), together with information corresponding to the comprised transactions, and a set of other block headers that are known to have a parent equal to the present block’s parent’s parent.
///
#[derive(Serialize, Deserialize)]
pub struct Block {
    pub(crate) number: Option<BlockNumberOrNull>,
    pub(crate) hash: Option<BlockHashOrNull>,
    pub(crate) parentHash: Option<BlockHash>,
    pub(crate) nonce: Option<NonceOrNull>,
    pub(crate) sha3Uncles: Option<BlockShaUncles>,
    pub(crate) logsBloom: Option<BlockLogsBloom>,
    pub(crate) transactionsRoot: Option<BlockTransactionsRoot>,
    pub(crate) stateRoot: Option<BlockStateRoot>,
    pub(crate) receiptsRoot: Option<BlockReceiptsRoot>,
    pub(crate) miner: Option<AddressOrNull>,
    pub(crate) difficulty: Option<BlockDifficulty>,
    pub(crate) totalDifficulty: Option<BlockTotalDifficulty>,
    pub(crate) extraData: Option<BlockExtraData>,
    pub(crate) size: Option<BlockSize>,
    pub(crate) gasLimit: Option<BlockGasLimit>,
    pub(crate) gasUsed: Option<BlockGasUsed>,
    pub(crate) timestamp: Option<BlockTimeStamp>,
    pub(crate) transactions: Option<TransactionsOrHashes>,
    pub(crate) uncles: Option<UncleHashes>,
}
/// LogAddress
///
/// Sender of the transaction
///
pub type LogAddress = String;
/// LogData
///
/// The data/input string sent along with the transaction
///
pub type LogData = String;
/// LogIndex
///
/// The index of the event within its transaction, null when its pending
///
pub type LogIndex = String;
/// LogIsRemoved
///
/// Whether or not the log was orphaned off the main chain
///
pub type LogIsRemoved = bool;
/// Log
///
/// An indexed event generated during a transaction
///
#[derive(Serialize, Deserialize)]
pub struct Log {
    pub(crate) address: Option<LogAddress>,
    pub(crate) blockHash: Option<BlockHash>,
    pub(crate) blockNumber: Option<BlockNumber>,
    pub(crate) data: Option<LogData>,
    pub(crate) logIndex: Option<LogIndex>,
    pub(crate) removed: Option<LogIsRemoved>,
    pub(crate) topics: Option<LogTopics>,
    pub(crate) transactionHash: Option<TransactionHash>,
    pub(crate) transactionIndex: Option<TransactionIndex>,
}
#[derive(Serialize, Deserialize)]
pub enum ReceiptContractAddress {
    Address,
    Null
}
/// ReceiptCumulativeGasUsed
///
/// The gas units used by the transaction
///
pub type ReceiptCumulativeGasUsed = String;
/// ReceiptGasUsed
///
/// The total gas used by the transaction
///
pub type ReceiptGasUsed = String;
/// Logs
///
/// An array of all the logs triggered during the transaction
///
pub type Logs = Vec<Log>;
/// BloomFilter
///
/// A 2048 bit bloom filter from the logs of the transaction. Each log sets 3 bits though taking the low-order 11 bits of each of the first three pairs of bytes in a Keccak 256 hash of the log's byte series
///
pub type BloomFilter = String;
/// ReceiptPostTransactionState
///
/// The intermediate stateRoot directly after transaction execution.
///
pub type ReceiptPostTransactionState = String;
/// ReceiptStatus
///
/// Whether or not the transaction threw an error.
///
pub type ReceiptStatus = bool;
/// Receipt
///
/// The receipt of a transaction
///
#[derive(Serialize, Deserialize)]
pub struct Receipt {
    pub(crate) blockHash: BlockHash,
    pub(crate) blockNumber: BlockNumber,
    pub(crate) contractAddress: ReceiptContractAddress,
    pub(crate) cumulativeGasUsed: ReceiptCumulativeGasUsed,
    pub(crate) from: From,
    pub(crate) gasUsed: ReceiptGasUsed,
    pub(crate) logs: Logs,
    pub(crate) logsBloom: BloomFilter,
    pub(crate) to: To,
    pub(crate) transactionHash: TransactionHash,
    pub(crate) transactionIndex: TransactionIndex,
    pub(crate) postTransactionState: Option<ReceiptPostTransactionState>,
    pub(crate) status: Option<ReceiptStatus>,
}
/// ProofAccountAddress
///
/// The address of the account or contract of the request
///
pub type ProofAccountAddress = String;
/// ProofNode
///
/// An individual node used to prove a path down a merkle-patricia-tree
///
pub type ProofNode = String;
/// ProofNodes
///
/// The set of node values needed to traverse a patricia merkle tree (from root to leaf) to retrieve a value
///
pub type ProofNodes = Vec<ProofNode>;
/// ProofAccountBalance
///
/// The Ether balance of the account or contract of the request
///
pub type ProofAccountBalance = String;
/// ProofAccountCodeHash
///
/// The code hash of the contract of the request (keccak(NULL) if external account)
///
pub type ProofAccountCodeHash = String;
/// ProofAccountNonce
///
/// The transaction count of the account or contract of the request
///
pub type ProofAccountNonce = String;
/// ProofAccountStorageHash
///
/// The storage hash of the contract of the request (keccak(rlp(NULL)) if external account)
///
pub type ProofAccountStorageHash = String;
/// StorageProofValue
///
/// The value of the storage slot in its account tree
///
pub type StorageProofValue = String;
/// StorageProof
///
/// Object proving a relationship of a storage value to an account's storageHash.
///
#[derive(Serialize, Deserialize)]
pub struct StorageProof {
    pub(crate) key: Option<StorageProofKey>,
    pub(crate) value: Option<StorageProofValue>,
    pub(crate) proof: Option<ProofNodes>,
}
/// StorageProofSet
///
/// Current block header PoW hash.
///
pub type StorageProofSet = Vec<StorageProof>;
/// ProofAccount
///
/// The merkle proofs of the specified account connecting them to the blockhash of the block specified
///
#[derive(Serialize, Deserialize)]
pub struct ProofAccount {
    pub(crate) address: Option<ProofAccountAddress>,
    pub(crate) accountProof: Option<ProofNodes>,
    pub(crate) balance: Option<ProofAccountBalance>,
    pub(crate) codeHash: Option<ProofAccountCodeHash>,
    pub(crate) nonce: Option<ProofAccountNonce>,
    pub(crate) storageHash: Option<ProofAccountStorageHash>,
    pub(crate) storageProof: Option<StorageProofSet>,
}
/// PowHash
///
/// Current block header PoW hash.
///
pub type PowHash = String;
/// SeedHash
///
/// The seed hash used for the DAG.
///
pub type SeedHash = String;
/// Difficulty
///
/// The boundary condition ('target'), 2^256 / difficulty.
///
pub type Difficulty = String;
/// SyncingDataStartingBlock
///
/// Block at which the import started (will only be reset, after the sync reached his head)
///
pub type SyncingDataStartingBlock = String;
/// SyncingDataCurrentBlock
///
/// The current block, same as eth_blockNumber
///
pub type SyncingDataCurrentBlock = String;
/// SyncingDataHighestBlock
///
/// The estimated highest block
///
pub type SyncingDataHighestBlock = String;
/// SyncingDataKnownStates
///
/// The known states
///
pub type SyncingDataKnownStates = String;
/// SyncingDataPulledStates
///
/// The pulled states
///
pub type SyncingDataPulledStates = String;
/// SyncingData
///
/// An object with sync status data
///
#[derive(Serialize, Deserialize)]
pub struct SyncingData {
    pub(crate) startingBlock: Option<SyncingDataStartingBlock>,
    pub(crate) currentBlock: Option<SyncingDataCurrentBlock>,
    pub(crate) highestBlock: Option<SyncingDataHighestBlock>,
    pub(crate) knownStates: Option<SyncingDataKnownStates>,
    pub(crate) pulledStates: Option<SyncingDataPulledStates>,
}
pub type BooleanVyG3AETh = bool;
pub type Data = String;
#[derive(Serialize, Deserialize)]
pub enum BlockNumberOrTag {
    BlockNumber,
    BlockNumberTag
}
pub type IsTransactionsIncluded = bool;
/// Filter
///
/// A filter used to monitor the blockchain for log/events
///
#[derive(Serialize, Deserialize)]
pub struct Filter {
    pub(crate) fromBlock: Option<BlockNumber>,
    pub(crate) toBlock: Option<BlockNumber>,
    pub(crate) address: Option<OneOrArrayOfAddresses>,
    pub(crate) topics: Option<LogTopics>,
}
/// Position
///
/// Hex representation of the storage slot where the variable exists
///
pub type Position = String;
/// StorageKeys
///
/// A storage key is indexed from the solidity compiler by the order it is declared. For mappings it uses the keccak of the mapping key with its position (and recursively for X-dimensional mappings)
///
pub type StorageKeys = serde_json::Value;
/// FilterId
///
/// An identifier used to reference the filter.
///
pub type FilterId = String;
/// Bytes
///
/// Hex representation of a variable length byte array
///
pub type Bytes = String;
pub type TransactionObjectWithSender = HashMap<String, Option<serde_json::Value>>;
/// DataWord
///
/// Hex representation of a 256 bit unit of data
///
pub type DataWord = String;
/// MixHash
///
/// The mix digest.
///
pub type MixHash = String;
pub type StringDoaGddGA = String;
pub type UnorderedSetOfObjectHAgrRKSzAfoBnX12 = Vec<ObjectHAgrRKSz>;
pub type ClientVersion = String;
pub type IsNetListening = bool;
/// NumConnectedPeers
///
/// Hex representation of number of connected peers
///
pub type NumConnectedPeers = String;
pub type NetworkId = String;
/// UnorderedSetOfAddressMvq5Ie3U
///
/// List of addresses
///
pub type UnorderedSetOfAddressMvq5Ie3U = Vec<Address>;
pub type ChainId = String;
/// GasPriceResult
///
/// Integer of the current gas price
///
pub type GasPriceResult = String;
#[derive(Serialize, Deserialize)]
pub enum IntegerOrNull {
    Integer,
    Null
}
#[derive(Serialize, Deserialize)]
pub enum BlockOrNull {
    Block,
    Null
}
pub type SetOfLogs = Vec<Log>;
#[derive(Serialize, Deserialize)]
pub enum TransactionOrNull {
    Transaction,
    Null
}
#[derive(Serialize, Deserialize)]
pub enum TransactionReceiptOrNull {
    Receipt,
    Null
}
#[derive(Serialize, Deserialize)]
pub enum ProofAccountOrNull {
    ProofAccount,
    Null
}
pub type GetWorkResults = (PowHash, SeedHash, Difficulty);
pub type LogResult = Vec<Log>;
/// Transactions
///
/// An array of transactions
///
pub type Transactions = Vec<Transaction>;
#[derive(Serialize, Deserialize)]
pub enum IsSyncingResult {
    SyncingData,
    BooleanVyG3AETh
}
#[derive(Serialize, Deserialize)]
pub enum AnyOfDataTransactionBlockNumberOrTagTransactionAddressBlockNumberBlockHashIsTransactionsIncludedBlockNumberOrTagIsTransactionsIncludedBlockHashBlockNumberOrTagAddressBlockNumberTransactionHashBlockHashIntegerBlockNumberOrTagIntegerFilterAddressPositionBlockNumberOrTagBlockHashIntegerBlockNumberOrTagIntegerTransactionHashAddressBlockNumberOrTagTransactionHashBlockHashIntegerBlockNumberIntegerBlockHashBlockNumberOrTagAddressStorageKeysBlockNumberOrTagFilterFilterIdFilterIdFilterIdAddressBytesTransactionObjectWithSenderTransactionObjectWithSenderBytesDataWordDataWordNoncePowHashMixHashStringDoaGddGAUnorderedSetOfObjectHAgrRKSzAfoBnX12StringDoaGddGAClientVersionKeccakIsNetListeningNumConnectedPeersNetworkIdUnorderedSetOfAddressMvq5Ie3UBlockNumberOrTagBytesChainIdAddressIntegerGasPriceResultGasPriceResultIntegerOrNullBlockOrNullBlockOrNullIntegerOrNullIntegerOrNullBytesBytesBytesBytesSetOfLogsDataWordTransactionOrNullTransactionOrNullTransactionOrNullNonceOrNullTransactionReceiptOrNullBlockOrNullBlockOrNullIntegerOrNullIntegerOrNullProofAccountOrNullGetWorkResultsIntegerBooleanVyG3AEThFilterIdIntegerLogResultSetOfLogsBooleanVyG3AEThFilterIdTransactionsIntegerBytesBytesTransactionHashKeccakBooleanVyG3AEThBooleanVyG3AEThIsSyncingResultStringDoaGddGABooleanVyG3AETh {
    Data,
    Transaction,
    BlockNumberOrTag,
    Address,
    BlockNumber,
    BlockHash,
    IsTransactionsIncluded,
    TransactionHash,
    Integer,
    Filter,
    Position,
    StorageKeys,
    FilterId,
    Bytes,
    TransactionObjectWithSender,
    DataWord,
    Nonce,
    PowHash,
    MixHash,
    StringDoaGddGA,
    UnorderedSetOfObjectHAgrRKSzAfoBnX12,
    ClientVersion,
    Keccak,
    IsNetListening,
    NumConnectedPeers,
    NetworkId,
    UnorderedSetOfAddressMvq5Ie3U,
    ChainId,
    GasPriceResult,
    IntegerOrNull,
    BlockOrNull,
    SetOfLogs,
    TransactionOrNull,
    NonceOrNull,
    TransactionReceiptOrNull,
    ProofAccountOrNull,
    GetWorkResults,
    BooleanVyG3AETh,
    LogResult,
    Transactions,
    IsSyncingResult
}

jsonrpc_client!(pub struct EthereumJSONRPC {
pub fn Web3ClientVersion(&mut self) -> RpcRequest<ClientVersion>;
pub fn Web3Sha3(&mut self, data: Data) -> RpcRequest<Keccak>;
pub fn NetListening(&mut self) -> RpcRequest<IsNetListening>;
pub fn NetPeerCount(&mut self) -> RpcRequest<NumConnectedPeers>;
pub fn NetVersion(&mut self) -> RpcRequest<NetworkId>;
pub fn EthAccounts(&mut self) -> RpcRequest<UnorderedSetOfAddressMvq5Ie3U>;
pub fn EthBlockNumber(&mut self) -> RpcRequest<BlockNumberOrTag>;
pub fn EthCall(&mut self, transaction: Transaction, blockNumber: BlockNumberOrTag) -> RpcRequest<Bytes>;
pub fn EthChainId(&mut self) -> RpcRequest<ChainId>;
pub fn EthCoinbase(&mut self) -> RpcRequest<Address>;
pub fn EthEstimateGas(&mut self, transaction: Transaction) -> RpcRequest<Integer>;
pub fn EthGasPrice(&mut self) -> RpcRequest<GasPriceResult>;
pub fn EthMaxPriorityFeePerGas(&mut self) -> RpcRequest<GasPriceResult>;
pub fn EthGetBalance(&mut self, address: Address, blockNumber: BlockNumber) -> RpcRequest<IntegerOrNull>;
pub fn EthGetBlockByHash(&mut self, blockHash: BlockHash, includeTransactions: IsTransactionsIncluded) -> RpcRequest<BlockOrNull>;
pub fn EthGetBlockByNumber(&mut self, blockNumber: BlockNumberOrTag, includeTransactions: IsTransactionsIncluded) -> RpcRequest<BlockOrNull>;
pub fn EthGetBlockTransactionCountByHash(&mut self, blockHash: BlockHash) -> RpcRequest<IntegerOrNull>;
pub fn EthGetBlockTransactionCountByNumber(&mut self, blockNumber: BlockNumberOrTag) -> RpcRequest<IntegerOrNull>;
pub fn EthGetCode(&mut self, address: Address, blockNumber: BlockNumber) -> RpcRequest<Bytes>;
pub fn EthGetRawTransactionByHash(&mut self, transactionHash: TransactionHash) -> RpcRequest<Bytes>;
pub fn EthGetRawTransactionByBlockHashAndIndex(&mut self, blockHash: BlockHash, index: Integer) -> RpcRequest<Bytes>;
pub fn EthGetRawTransactionByBlockNumberAndIndex(&mut self, blockNumber: BlockNumberOrTag, index: Integer) -> RpcRequest<Bytes>;
pub fn EthGetLogs(&mut self, filter: Filter) -> RpcRequest<SetOfLogs>;
pub fn EthGetStorageAt(&mut self, address: Address, key: Position, blockNumber: BlockNumberOrTag) -> RpcRequest<DataWord>;
pub fn EthGetTransactionByBlockHashAndIndex(&mut self, blockHash: BlockHash, index: Integer) -> RpcRequest<TransactionOrNull>;
pub fn EthGetTransactionByBlockNumberAndIndex(&mut self, blockNumber: BlockNumberOrTag, index: Integer) -> RpcRequest<TransactionOrNull>;
pub fn EthGetTransactionByHash(&mut self, transactionHash: TransactionHash) -> RpcRequest<TransactionOrNull>;
pub fn EthGetTransactionCount(&mut self, address: Address, blockNumber: BlockNumberOrTag) -> RpcRequest<NonceOrNull>;
pub fn EthGetTransactionReceipt(&mut self, transactionHash: TransactionHash) -> RpcRequest<TransactionReceiptOrNull>;
pub fn EthGetUncleByBlockHashAndIndex(&mut self, blockHash: BlockHash, index: Integer) -> RpcRequest<BlockOrNull>;
pub fn EthGetUncleByBlockNumberAndIndex(&mut self, uncleBlockNumber: BlockNumber, index: Integer) -> RpcRequest<BlockOrNull>;
pub fn EthGetUncleCountByBlockHash(&mut self, blockHash: BlockHash) -> RpcRequest<IntegerOrNull>;
pub fn EthGetUncleCountByBlockNumber(&mut self, blockNumber: BlockNumberOrTag) -> RpcRequest<IntegerOrNull>;
pub fn EthGetProof(&mut self, address: Address, storageKeys: StorageKeys, blockNumber: BlockNumberOrTag) -> RpcRequest<ProofAccountOrNull>;
pub fn EthGetWork(&mut self) -> RpcRequest<GetWorkResults>;
pub fn EthHashrate(&mut self) -> RpcRequest<Integer>;
pub fn EthMining(&mut self) -> RpcRequest<BooleanVyG3AETh>;
pub fn EthNewBlockFilter(&mut self) -> RpcRequest<FilterId>;
pub fn EthNewFilter(&mut self, filter: Filter) -> RpcRequest<Integer>;
pub fn EthGetFilterChanges(&mut self, filterId: FilterId) -> RpcRequest<LogResult>;
pub fn EthGetFilterLogs(&mut self, filterId: FilterId) -> RpcRequest<SetOfLogs>;
pub fn EthUninstallFilter(&mut self, filterId: FilterId) -> RpcRequest<BooleanVyG3AETh>;
pub fn EthNewPendingTransactionFilter(&mut self) -> RpcRequest<FilterId>;
pub fn EthPendingTransactions(&mut self) -> RpcRequest<Transactions>;
pub fn EthProtocolVersion(&mut self) -> RpcRequest<Integer>;
pub fn EthSign(&mut self, Address: Address, Message: Bytes) -> RpcRequest<Bytes>;
pub fn EthSignTransaction(&mut self, Transaction: TransactionObjectWithSender) -> RpcRequest<Bytes>;
pub fn EthSendTransaction(&mut self, Transaction: TransactionObjectWithSender) -> RpcRequest<TransactionHash>;
pub fn EthSendRawTransaction(&mut self, signedTransactionData: Bytes) -> RpcRequest<Keccak>;
pub fn EthSubmitHashrate(&mut self, hashRate: DataWord, id: DataWord) -> RpcRequest<BooleanVyG3AETh>;
pub fn EthSubmitWork(&mut self, nonce: Nonce, powHash: PowHash, mixHash: MixHash) -> RpcRequest<BooleanVyG3AETh>;
pub fn EthSyncing(&mut self) -> RpcRequest<IsSyncingResult>;
pub fn EthSubscribe(&mut self, subscriptioName: StringDoaGddGA, optionalArguments : UnorderedSetOfObjectHAgrRKSzAfoBnX12) -> RpcRequest<StringDoaGddGA>;
pub fn EthUnsubscribe(&mut self, subscriptionId: StringDoaGddGA) -> RpcRequest<BooleanVyG3AETh>;
});
