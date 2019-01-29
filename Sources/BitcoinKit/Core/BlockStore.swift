//
//  BlockStore.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

// swiftlint:disable closure_end_indentation

import Foundation

import GRDB

public struct Payment {
    public enum State {
        case sent
        case received
    }

    public let state: State
    public let index: Int64
    public let amount: Int64
    public let from: Address
    public let to: Address
    public let txid: Data
    
    public init(state: State, index: Int64, amount: Int64, from: Address, to: Address, txid: Data) {
        self.state = state
        self.index = index
        self.amount = amount
        self.from = from
        self.to = to
        self.txid = txid
    }
}

extension Payment: Equatable {
    static public func == (lhs: Payment, rhs: Payment) -> Bool {
        return lhs.txid == rhs.txid
    }
}

public protocol BlockStore {
    func addBlock(_ block: BlockMessage, hash: Data) throws
    func addMerkleBlock(_ merkleBlock: MerkleBlockMessage, hash: Data) throws
    func addTransaction(_ transaction: Transaction, hash: Data) throws
    func calculateBalance(address: Address) throws -> Int64
    func latestBlockHash() throws -> Data?
}

public class SQLiteBlockStore: BlockStore {
    public static func `default`() throws -> SQLiteBlockStore {
        return SQLiteBlockStore(network: Network.testnetBTC)
    }
    
    var dbPool: DatabasePool?
    let network: Network
    
    private var statements = [String: String]()
    
    public init(network: Network) {
        self.network = network
        self.openDB()
    }
    
    func openDB() {
        let cachesDir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        do {
            dbPool = try DatabasePool(path: cachesDir.appendingPathComponent("\(self.network.scheme)-blockchain.sqlite").path)
            try dbPool?.write { db in
                try db.execute(
                    """
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS block (
         id BLOB NOT NULL PRIMARY KEY,
         version INTEGER NOT NULL,
         prev_block BLOB NOT NULL,
         merkle_root BLOB NOT NULL,
         timestamp INTEGER NOT NULL,
         bits INTEGER NOT NULL,
         nonce INTEGER NOT NULL,
         txn_count INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS merkleblock (
         id BLOB NOT NULL PRIMARY KEY,
         version INTEGER NOT NULL,
         prev_block BLOB NOT NULL,
         merkle_root BLOB NOT NULL,
         timestamp INTEGER NOT NULL,
         bits INTEGER NOT NULL,
         nonce INTEGER NOT NULL,
         total_transactions INTEGER NOT NULL,
         hash_count INTEGER NOT NULL,
         hashes BLOB NOT NULL,
         flag_count INTEGER NOT NULL,
         flags BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS tx (
         id BLOB NOT NULL PRIMARY KEY,
         version INTEGER NOT NULL,
         flag INTEGER NOT NULL,
         tx_in_count INTEGER NOT NULL,
         tx_out_count INTEGER NOT NULL,
         lock_time INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS txin (
         script_length INTEGER NOT NULL,
         signature_script BLOB NOT NULL,
         sequence INTEGER NOT NULL,
         tx_id BLOB NOT NULL,
         txout_id BLOB NOT NULL,
         FOREIGN KEY(tx_id) REFERENCES tx(id)
         );
         CREATE TABLE IF NOT EXISTS txout (
         out_index INTEGER NOT NULL,
         value INTEGER NOT NULL,
         pk_script_length INTEGER NOT NULL,
         pk_script BLOB NOT NULL,
         tx_id BLOB NOT NULL,
         address_id TEXT,
         FOREIGN KEY(tx_id) REFERENCES tx(id)
         );
         CREATE VIEW IF NOT EXISTS view_tx AS
         SELECT tx.id, txout.address_id, txout.out_index, txout.value, txin.txout_id from tx
         LEFT JOIN txout on id = txout.tx_id
         LEFT JOIN txin on id = txin.txout_id;
         CREATE VIEW IF NOT EXISTS view_utxo AS
         SELECT tx.id, txout.address_id, txout.out_index, txout.value, txin.txout_id from tx
         LEFT JOIN txout on id = txout.tx_id
         LEFT JOIN txin on id = txin.txout_id
         WHERE txout_id IS NULL;
         """
                )
                
                statements["addBlock"] = """
                REPLACE INTO block
                (id, version, prev_block, merkle_root, timestamp, bits, nonce, txn_count)
                VALUES
                (?,  ?,       ?,          ?,           ?,         ?,    ?,     ?);
                """
                
                statements["addMerkleBlock"] = """
                REPLACE INTO merkleblock
                (id, version, prev_block, merkle_root, timestamp, bits, nonce, total_transactions, hash_count, hashes, flag_count, flags)
                VALUES
                (?,  ?,       ?,          ?,           ?,         ?,    ?,     ?,                  ?,          ?,      ?,          ?);
                """
                
                statements["addTransaction"] = """
                REPLACE INTO tx
                (id, version, flag, tx_in_count, tx_out_count, lock_time)
                VALUES
                (?,  ?,       ?,    ?,           ?,            ?);
                """
                
                statements["addTransactionInput"] = """
                INSERT INTO txin
                (script_length, signature_script, sequence, tx_id, txout_id)
                VALUES
                (?,             ?,                ?,        ?,     ?);
                """
                
                statements["addTransactionOutput"] = """
                INSERT INTO txout
                (out_index, value, pk_script_length, pk_script, tx_id, address_id)
                VALUES
                (?, ?,     ?,                ?,         ?,     ?);
                """
                
                statements["deleteTransactionInput"] = """
                DELETE FROM txin WHERE tx_id = ?;
                """
                
                statements["deleteTransactionOutput"] = """
                DELETE FROM txout WHERE tx_id = ?;
                """
                
                statements["calculateBalance"] = """
                SELECT value FROM view_utxo WHERE address_id == ?;
                """
                
                statements["transactions"] = """
                SELECT * FROM view_tx WHERE address_id == ?;
                """
                
                statements["latestBlockHash"] = """
                SELECT id FROM merkleblock ORDER BY timestamp DESC LIMIT 1;
                """
                
                statements["unspentTransactions"] = """
                SELECT * FROM view_utxo WHERE address_id == ?;
                """
            }
            
        } catch let error {
            print("Error: Can't init db for BTC with error: \(error.localizedDescription)")
        }
    }
    
    public func addBlock(_ block: BlockMessage, hash: Data) throws {
        print("-- \(#function) --")
        guard let sql = statements["addBlock"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                hash,
                Int64(block.version),
                block.prevBlock,
                block.merkleRoot,
                Int64(block.timestamp),
                Int64(block.bits),
                Int64(block.nonce),
                Int64(block.transactionCount.underlyingValue)
                ])
        }
    }
    
    public func addMerkleBlock(_ merkleBlock: MerkleBlockMessage, hash: Data) throws {
        guard let sql = statements["addMerkleBlock"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        let hashes = Data(merkleBlock.hashes.flatMap { $0 })
        let flags = Data(merkleBlock.flags)
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                hash,
                Int64(merkleBlock.version),
                merkleBlock.prevBlock,
                merkleBlock.merkleRoot,
                Int64(merkleBlock.timestamp),
                Int64(merkleBlock.bits),
                Int64(merkleBlock.nonce),
                Int64(merkleBlock.totalTransactions),
                Int64(merkleBlock.numberOfHashes.underlyingValue),
                hashes,
                Int64(merkleBlock.numberOfFlags.underlyingValue),
                flags
                ])
        }
    }
    
    public func addTransaction(_ transaction: BitcoinKit.Transaction, hash: Data) throws {
        guard let sql = statements["addTransaction"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                hash,
                Int64(transaction.version),
                0, // Not supported 'flag' currently
                Int64(transaction.txInCount.underlyingValue),
                Int64(transaction.txOutCount.underlyingValue),
                Int64(transaction.lockTime)
                ])
        }
        try deleteTransactionInput(txId: hash)
        for input in transaction.inputs {
            try addTransactionInput(input, txId: hash)
        }
        try deleteTransactionOutput(txId: hash)
        for (i, output) in transaction.outputs.enumerated() {
            try addTransactionOutput(index: i, output: output, txId: hash)
        }
    }
    
    public func calculateBalance(address: Address) throws -> Int64 {
        guard let sql = statements["calculateBalance"] else {
            print("sql query for \(#function) not found")
            return 0
        }
        
        return try dbPool?.read { db -> Int64 in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58]
            
            var balance: Int64 = 0
            for row in try Row.fetchAll(stmt) {
                let value = Int64.fromDatabaseValue(row[0])
                balance += value ?? 0
            }
            return balance
            } ?? 0
    }
    
    public func latestBlockHash() throws -> Data? {
        guard let sql = statements["latestBlockHash"] else {
            print("sql query for \(#function) not found")
            return nil
        }
        
        return try dbPool?.read { db -> Data?  in
            let stmt = try db.cachedSelectStatement(sql)
            
            if let row = try Row.fetchOne(stmt) {
                if let value = Data.fromDatabaseValue(row[0]){
                    return value
                }
            }
            return nil
        }
    }
    
    public func addTransactionInput(_ input: TransactionInput, txId: Data) throws {
        guard let sql = statements["addTransactionInput"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                Int64(input.scriptLength.underlyingValue),
                Int64(input.signatureScript.count),
                Int64(input.sequence),
                txId,
                input.previousOutput.hash
                ])
        }
    }
    
    public func addTransactionOutput(index: Int, output: TransactionOutput, txId: Data) throws {
        guard let sql = statements["addTransactionOutput"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        var address = ""
        if Script.isPublicKeyHashOut(output.lockingScript) {
            let pubKeyHash = Script.getPublicKeyHash(from: output.lockingScript)
            address = BitcoinKitHelpers.publicKeyToAddress(from: (Data([network.pubkeyhash]) + pubKeyHash))
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                Int64(index),
                Int64(output.value),
                Int64(output.scriptLength.underlyingValue),
                output.lockingScript,
                txId,
                address
                ])
        }
    }
    
    private func deleteTransactionInput(txId: Data) throws {
        guard let sql = statements["deleteTransactionInput"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [txId])
        }
    }
    
    private func deleteTransactionOutput(txId: Data) throws {
        guard let sql = statements["deleteTransactionOutput"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [txId])
        }
    }
    
    public func transactions(address: Address) throws -> [Payment] {
        guard let sql = statements["transactions"] else {
            print("sql query for \(#function) not found")
            return [Payment]()
        }
        
        return try dbPool?.read { db -> [Payment] in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58]
            
            var payments = [Payment]()
            
            for row in try Row.fetchAll(stmt) {
                if let txid = Data.fromDatabaseValue(row[0]),
                    let address = String.fromDatabaseValue(row[1]),
                    let index = Int64.fromDatabaseValue(row[2]),
                    let value = Int64.fromDatabaseValue(row[3]) {
                    payments.append(Payment(state: .received, index: index, amount: value, from: try! AddressFactory.create(address), to: try! AddressFactory.create(address), txid: txid))
                }
            }
            
            return payments
        } ?? [Payment]()
    }
    
    public func unspentTransactions(address: Address) throws -> [Payment] {
        guard let sql = statements["unspentTransactions"] else {
            print("sql query for \(#function) not found")
            return [Payment]()
        }
        
        return try dbPool?.read { db -> [Payment] in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58]
            
            var payments = [Payment]()
            
            for row in try Row.fetchAll(stmt) {
                if let txid = Data.fromDatabaseValue(row[0]),
                    let address = String.fromDatabaseValue(row[1]),
                    let index = Int64.fromDatabaseValue(row[2]),
                    let value = Int64.fromDatabaseValue(row[3]) {
                    payments.append(Payment(state: .received, index: index, amount: value, from: try! AddressFactory.create(address), to: try! AddressFactory.create(address), txid: txid))
                }
            }
            
            return payments
        } ?? [Payment]()
    }
}
