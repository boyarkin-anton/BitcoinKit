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

import GRDBCipher

public struct Payment {
    public enum State {
        case sent
        case received
        case unknown
    }

    public let state: State
    public let amount: Int64
    public let index: Int64
    public let from: Address
    public let to: Address
    public let txid: String
    public let blockHeight: Int64
    public let timestamp: Int64
    public let confirmations: Int64
    public let fee: Int64?
    
    public init(state: State, index: Int64, amount: Int64, from: Address, to: Address, txid: String, blockHeight: Int64, timestamp: Int64, confirmations: Int64, fee: Int64?) {
        self.state = state
        self.index = index
        self.amount = amount
        self.from = from
        self.to = to
        self.txid = txid
        self.blockHeight = blockHeight
        self.timestamp = timestamp
        self.confirmations = confirmations
        self.fee = fee
    }
}

extension Payment: Equatable {
    static public func == (lhs: Payment, rhs: Payment) -> Bool {
        return lhs.txid == rhs.txid
    }
}

public protocol BlockStore {
    func addBlock(_ block: BlockMessage, hash: Data, height: Int32) throws
    func addMerkleBlock(_ merkleBlock: MerkleBlockMessage, hash: Data, height: Int32) throws
    func addTransaction(_ transaction: Transaction, hash: Data, isProcessing: Bool) throws
    func calculateBalance(address: Address) throws -> Int64
    func latestBlockHash() throws -> Data?
    func latestBlockHeight() throws -> Int32?
    func transaction(with hash: String) throws -> Payment?
}

public class SQLiteBlockStore: BlockStore {
    public static func `default`() throws -> SQLiteBlockStore {
        return SQLiteBlockStore(network: Network.testnetBTC)
    }
    
    var dbPool: DatabasePool?
    let network: Network
    
    private var statements = [String: String]()
    
    public init(network: Network, name: String? = nil, passphrase: String? = nil) {
        self.network = network
        self.openDB(name: name, passphrase: passphrase)
    }
    
    func openDB(name: String? = nil, passphrase: String? = nil) {
        var configuration = Configuration()
        configuration.passphrase = passphrase
        
        var dbName = ""
        if let name = name {
            dbName = "\(name).sqlite"
        } else {
            dbName = "\(self.network.scheme)-\(self.network.name)-blockchain.sqlite"
        }
        
        let cachesDir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        do {
            dbPool = try DatabasePool(path: cachesDir.appendingPathComponent(dbName).path, configuration: configuration)
            try dbPool?.write { db in
                
                try db.create(table: "block", ifNotExists: true) { t in
                    t.column("id", .text).notNull()
                    t.column("version", .integer).notNull()
                    t.column("prev_block", .text).notNull()
                    t.column("merkle_root", .blob).notNull()
                    t.column("timestamp", .integer).notNull()
                    t.column("bits", .integer).notNull()
                    t.column("nonce", .integer).notNull()
                    t.column("txn_count", .integer).notNull()
                    t.column("height", .integer).notNull()
                    t.primaryKey(["id"])
                }
                
                try db.create(table: "merkleblock", ifNotExists: true) { t in
                    t.column("id", .text).notNull()
                    t.column("version", .integer).notNull()
                    t.column("prev_block", .text).notNull()
                    t.column("merkle_root", .blob).notNull()
                    t.column("timestamp", .integer).notNull()
                    t.column("bits", .integer).notNull()
                    t.column("nonce", .integer).notNull()
                    t.column("total_transactions", .integer).notNull()
                    t.column("hash_count", .integer).notNull()
                    t.column("hashes", .text).notNull()
                    t.column("flag_count", .integer).notNull()
                    t.column("flags", .blob).notNull()
                    t.column("height", .integer).notNull()
                    t.primaryKey(["id"])
                }
                
                try db.create(table: "tx", ifNotExists: true) { t in
                    t.column("id", .text).notNull()
                    t.column("version", .integer).notNull()
                    t.column("flag", .integer).notNull()
                    t.column("tx_in_count", .integer).notNull()
                    t.column("tx_out_count", .integer).notNull()
                    t.column("lock_time", .integer).notNull()
                    t.column("isProcessing", .boolean).notNull()
                    t.primaryKey(["id"])
                }
                
                try db.create(table: "txin", ifNotExists: true) { t in
                    t.column("script_length", .integer).notNull()
                    t.column("signature_script", .blob).notNull()
                    t.column("sequence", .integer).notNull()
                    t.column("tx_id", .text).notNull()
                    t.column("txout_index", .integer).notNull()
                    t.column("txout_id", .text).notNull()
                    t.column("address_id", .text)
                    t.foreignKey(["tx_id"], references: "tx", columns: ["id"])
                }
                
                try db.create(table: "txout", ifNotExists: true) { t in
                    t.column("out_index", .integer).notNull()
                    t.column("value", .integer).notNull()
                    t.column("pk_script_length", .integer).notNull()
                    t.column("pk_script", .blob).notNull()
                    t.column("tx_id", .text).notNull()
                    t.column("address_id", .text)
                    t.foreignKey(["tx_id"], references: "tx", columns: ["id"])
                }
                
                try db.execute(
"""
CREATE VIEW IF NOT EXISTS view_tx AS
    SELECT tx.id,
           txin.address_id AS in_address,
           txout.address_id AS out_address,
           txout.out_index,
           txout.value,
           merkleblock.height,
           merkleblock.timestamp
      FROM tx
           LEFT JOIN
           txout ON tx.id = txout.tx_id
           LEFT JOIN
           txin ON tx.id = txin.tx_id
           LEFT OUTER JOIN
           merkleblock ON merkleblock.hashes LIKE '%' || tx.id || '%'
     WHERE in_address != out_address;

CREATE VIEW IF NOT EXISTS view_utxo AS
    SELECT tx.id,
           txout.address_id AS out_address,
           txout.out_index,
           txout.value,
           spent_tx.tx_id AS spent_id
      FROM tx
           LEFT JOIN
           txout ON tx.id = txout.tx_id
           LEFT JOIN
           txin AS spent_tx ON spent_tx.txout_id = txout.tx_id AND
                               spent_tx.txout_index = txout.out_index
     WHERE spent_id IS NULL
     GROUP BY tx.id;

CREATE VIEW IF NOT EXISTS view_tx_fees AS
    SELECT input.id,
           in_address,
           in_value,
           out_value,
           in_value - out_value AS fee
      FROM (
               SELECT id,
                      address AS in_address,
                      sum(value) AS in_value
                 FROM (
                          SELECT DISTINCT tx.id AS id,
                                          prev.address_id AS address,
                                          prev.value AS value
                            FROM tx
                                 LEFT JOIN
                                 txin ON tx.id = txin.tx_id
                                 LEFT JOIN
                                 txout AS prev ON prev.tx_id = txin.txout_id AND
                                                  prev.out_index = txin.txout_index
                           WHERE address IS NOT NULL
                      )
                GROUP BY id
           )
           AS input
           LEFT JOIN
           (
               SELECT id,
                      address AS out_address,
                      sum(value) AS out_value
                 FROM (
                          SELECT DISTINCT tx.id AS id,
                                          address_id AS address,
                                          value AS value
                            FROM tx
                                 LEFT JOIN
                                 txout ON tx.id = txout.tx_id
                           WHERE address IS NOT ""
                      )
                GROUP BY id
           )
           AS output ON input.id = output.id
     WHERE fee IS NOT NULL;
"""
                )
                
                statements["addBlock"] = """
                REPLACE INTO block
                (id, version, prev_block, merkle_root, timestamp, bits, nonce, txn_count, height)
                VALUES
                (?,  ?,       ?,          ?,           ?,         ?,    ?,     ?,         ?);
                """
                
                statements["addMerkleBlock"] = """
                REPLACE INTO merkleblock
                (id, version, prev_block, merkle_root, timestamp, bits, nonce, total_transactions, hash_count, hashes, flag_count, flags, height)
                VALUES
                (?,  ?,       ?,          ?,           ?,         ?,    ?,     ?,                  ?,          ?,      ?,          ?,     ?);
                """
                
                statements["addTransaction"] = """
                REPLACE INTO tx
                (id, version, flag, tx_in_count, tx_out_count, lock_time, isProcessing)
                VALUES
                (?,  ?,       ?,    ?,           ?,            ?,         ?);
                """
                
                statements["addTransactionInput"] = """
                INSERT INTO txin
                (script_length, signature_script, sequence, tx_id, txout_index, txout_id, address_id)
                VALUES
                (?,             ?,                ?,        ?,     ?,           ?,        ?);
                """
                
                statements["addTransactionOutput"] = """
                INSERT INTO txout
                (out_index, value, pk_script_length, pk_script, tx_id, address_id)
                VALUES
                (?,         ?,     ?,                ?,         ?,     ?);
                """
                
                statements["deleteTransactionInput"] = """
                DELETE FROM txin WHERE tx_id = ?;
                """
                
                statements["deleteTransactionOutput"] = """
                DELETE FROM txout WHERE tx_id = ?;
                """
                
                statements["calculateBalance"] = """
                SELECT SUM(value) FROM view_utxo WHERE out_address == ?;
                """
                
                statements["getIncome"] = """
                SELECT SUM(value) FROM view_tx WHERE in_address != out_address AND out_address == ?;
                """
                
                statements["getExpenses"] = """
                SELECT SUM(value) FROM view_tx WHERE in_address != out_address AND in_address == ?;
                """
                
                statements["getFees"] = """
                SELECT SUM(fee) FROM view_tx_fees WHERE in_address == ?;
                """
                
                statements["transactions"] = """
                SELECT * FROM view_tx WHERE in_address != out_address AND (in_address == ? OR out_address == ?) GROUP BY id ORDER BY timestamp DESC;
                """
                
                statements["latestBlockHash"] = """
                SELECT id FROM merkleblock ORDER BY timestamp DESC LIMIT 1;
                """
                
                statements["latestBlockHeight"] = """
                SELECT height FROM merkleblock ORDER BY timestamp DESC LIMIT 1;
                """
                
                statements["unspentTransactions"] = """
                SELECT * FROM view_utxo WHERE out_address == ?
                """
                
                statements["transaction"] = """
                SELECT * FROM view_tx WHERE id == ?;
                """
                
                statements["transaction_fee"] = """
                SELECT * FROM view_tx_fees WHERE id == ?;
                """
            }
            
        } catch let error {
            print("Error: Can't init db for BTC with error: \(error.localizedDescription)")
        }
    }
    
    public func addBlock(_ block: BlockMessage, hash: Data, height: Int32) throws {
        guard let sql = statements["addBlock"] else {
            print("sql query for \(#function) not found")
            return
        }
        let height = 0
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                Data(hash.reversed()).hex,
                Int64(block.version),
                Data(block.prevBlock.reversed()).hex,
                block.merkleRoot,
                Int64(block.timestamp),
                Int64(block.bits),
                Int64(block.nonce),
                Int64(block.transactionCount.underlyingValue),
                Int64(height)
                ])
        }
    }
    
    public func addMerkleBlock(_ merkleBlock: MerkleBlockMessage, hash: Data, height: Int32) throws {
        guard let sql = statements["addMerkleBlock"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        let hashes = Data(merkleBlock.hashes.flatMap { Data($0.reversed()) })
        let flags = Data(merkleBlock.flags)
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            
            try stmt.execute(arguments: [
                Data(hash.reversed()).hex,
                Int64(merkleBlock.version),
                Data(merkleBlock.prevBlock.reversed()).hex,
                merkleBlock.merkleRoot,
                Int64(merkleBlock.timestamp),
                Int64(merkleBlock.bits),
                Int64(merkleBlock.nonce),
                Int64(merkleBlock.totalTransactions),
                Int64(merkleBlock.numberOfHashes.underlyingValue),
                hashes.hex,
                Int64(merkleBlock.numberOfFlags.underlyingValue),
                flags,
                Int64(height)
                ])
        }
    }
    
    public func addTransaction(_ transaction: BitcoinKit.Transaction, hash: Data, isProcessing: Bool) throws {
        guard let sql = statements["addTransaction"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                hash.hex,
                Int64(transaction.version),
                0, // Not supported 'flag' currently
                Int64(transaction.txInCount.underlyingValue),
                Int64(transaction.txOutCount.underlyingValue),
                Int64(transaction.lockTime),
                isProcessing
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
            
            return try Int64.fetchOne(stmt) ?? 0
            } ?? 0
    }
    
    private func getIncome(address: Address) throws -> Int64 {
        guard let sql = statements["getIncome"] else {
            print("sql query for \(#function) not found")
            return 0
        }
        
        return try dbPool?.read { db -> Int64 in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58]
                        
            return try Int64.fetchOne(stmt) ?? 0
            } ?? 0
    }
    
    private func getExpenses(address: Address) throws -> Int64 {
        guard let sql = statements["getExpenses"] else {
            print("sql query for \(#function) not found")
            return 0
        }
        
        return try dbPool?.read { db -> Int64 in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58]
            
            return try Int64.fetchOne(stmt) ?? 0
            } ?? 0
    }
    
    private func getFees(address: Address) throws -> Int64 {
        guard let sql = statements["getFees"] else {
            print("sql query for \(#function) not found")
            return 0
        }
        
        return try dbPool?.read { db -> Int64 in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58]
            
            return try Int64.fetchOne(stmt) ?? 0
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
                if let value = String.fromDatabaseValue(row[0]), let data = Data(hex: value) {
                    return Data(data.reversed())
                }
            }
            return nil
        }
    }
    
    public func latestBlockHeight() throws -> Int32? {
        guard let sql = statements["latestBlockHeight"] else {
            print("sql query for \(#function) not found")
            return nil
        }
        
        return try dbPool?.read { db -> Int32?  in
            let stmt = try db.cachedSelectStatement(sql)
            
            if let row = try Row.fetchOne(stmt) {
                if let value = Int64.fromDatabaseValue(row[0]){
                    return Int32(value)
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
        
        var address = ""
        if let unpackedAddress = input.address {
            address = unpackedAddress
        } else {
            address = AddressConverter.extract(from: input.signatureScript, with: self.network)?.base58 ?? ""
        }
        
        try dbPool?.write { db in
            let stmt = try db.cachedUpdateStatement(sql)
            try stmt.execute(arguments: [
                Int64(input.scriptLength.underlyingValue),
                input.signatureScript,
                Int64(input.sequence),
                txId.hex,
                Int64(input.previousOutput.index),
                Data(input.previousOutput.hash.reversed()).hex,
                address
                ])
        }
    }
    
    public func addTransactionOutput(index: Int, output: TransactionOutput, txId: Data) throws {
        guard let sql = statements["addTransactionOutput"] else {
            print("sql query for \(#function) not found")
            return
        }
        
        var address = ""
        if let unpackedAddress = output.address {
            address = unpackedAddress
        } else if Script.isPublicKeyHashOut(output.lockingScript) {
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
                txId.hex,
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
        
        let lastHeight = try latestBlockHeight() ?? 0
        
        return try dbPool?.read { db -> [Payment] in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [address.base58, address.base58]
            
            var payments = [Payment]()
            
            for row in try Row.fetchAll(stmt) {
                if let txid = String.fromDatabaseValue(row[0]),
                    let inAddress = String.fromDatabaseValue(row[1]),
                    let outAddress = String.fromDatabaseValue(row[2]),
                    let outIndex = Int64.fromDatabaseValue(row[3]),
                    let value = Int64.fromDatabaseValue(row[4]),
                    let blockHeight = Int64.fromDatabaseValue(row[5]),
                    let timestamp = Int64.fromDatabaseValue(row[6]) {
                    
                    let from = try! AddressFactory.create(inAddress)
                    let to = try! AddressFactory.create(outAddress)
                    let state: Payment.State = (outAddress == address.base58) ? .received : .sent
                    
                    var confirmations: Int64 = 0
                    if lastHeight > blockHeight {
                        confirmations = Int64(lastHeight) - blockHeight
                    }
                    
                    let fee = try self.getTransactionFee(for: txid, in: db)
                    
                    payments.append(Payment(state: state, index: outIndex, amount: value, from: from, to: to, txid: txid, blockHeight: blockHeight, timestamp: timestamp, confirmations: confirmations, fee: fee))
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
                if let txid = String.fromDatabaseValue(row[0]),
                    let outAddress = String.fromDatabaseValue(row[1]),
                    let outIndex = Int64.fromDatabaseValue(row[2]),
                    let value = Int64.fromDatabaseValue(row[3]) {
                    
                    let address = try! AddressFactory.create(outAddress)
                    
                    payments.append(Payment(state: .received, index: outIndex, amount: value, from: address, to: address, txid: txid, blockHeight: 0, timestamp: 0, confirmations: 0, fee: 0))
                }
            }
            
            return payments
        } ?? [Payment]()
    }
    
    public func transaction(with hash: String) throws -> Payment? {
        guard let sql = statements["transaction"] else {
            print("sql query for \(#function) not found")
            return nil
        }
        
        let lastHeight = try latestBlockHeight() ?? 0
        
        return try dbPool?.read { db -> Payment? in
            let stmt = try db.cachedSelectStatement(sql)
            stmt.arguments = [hash]
            
            if let row = try Row.fetchOne(stmt) {
                if let txid = String.fromDatabaseValue(row[0]),
                    let inAddress = String.fromDatabaseValue(row[1]),
                    let outAddress = String.fromDatabaseValue(row[2]),
                    let outIndex = Int64.fromDatabaseValue(row[3]),
                    let value = Int64.fromDatabaseValue(row[4]) {
                    
                    let blockHeight = Int64.fromDatabaseValue(row[5]) ?? -1
                    let timestamp = Int64.fromDatabaseValue(row[6]) ?? -1
                    
                    let from = try! AddressFactory.create(inAddress)
                    let to = try! AddressFactory.create(outAddress)
                    let state: Payment.State = .unknown
                    
                    var confirmations: Int64 = 0
                    if blockHeight > 0, lastHeight > blockHeight {
                        confirmations = Int64(lastHeight) - blockHeight
                    }
                    
                    let fee = try self.getTransactionFee(for: hash, in: db)
                    
                    return Payment(state: state, index: outIndex, amount: value, from: from, to: to, txid: txid, blockHeight: blockHeight, timestamp: timestamp, confirmations: confirmations, fee: fee)
                }
            }
            
            return nil
        }
    }
    
    private func getTransactionFee(for hash: String, in db: Database) throws -> Int64? {
        guard let sql = statements["transaction_fee"] else {
            print("sql query for \(#function) not found")
            return nil
        }
        
        let stmt = try db.cachedSelectStatement(sql)
        stmt.arguments = [hash]
        
        if let row = try Row.fetchOne(stmt) {
            if let value = Int64.fromDatabaseValue(row[4]){
                return value
            }
        }
        return nil
    }
}
