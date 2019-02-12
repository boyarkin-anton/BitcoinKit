//
//  AddressConverter.swift
//  BitcoinKit
//
//  Created by Anton Boyarkin on 12/02/2019.
//

import Foundation

class AddressConverter {
    enum ConversionError: Error {
        case invalidChecksum
        case invalidAddressLength
        case unknownAddressType
        case wrongAddressPrefix
    }
    
    let network: Network
    
    init(network: Network) {
        self.network = network
    }
    
    func convert(keyHash: Data, type: ScriptType) throws -> Address {
        let version: UInt8
        let addressType: AddressType
        switch type {
        case .p2pkh, .p2pk:
            version = network.pubkeyhash
            addressType = .pubkeyHash
        case .p2sh, .p2wpkhSh:
            version = network.scripthash
            addressType = .scriptHash
        default: throw ConversionError.unknownAddressType
        }
        return try convertToLegacy(keyHash: keyHash, version: version, addressType: addressType)
    }
    
    func convertToLegacy(keyHash: Data, version: UInt8, addressType: AddressType) throws -> LegacyAddress {
        var withVersion = (Data([version])) + keyHash
        let doubleSHA256 = Crypto.sha256sha256(withVersion)
        let checksum = doubleSHA256.prefix(4)
        withVersion += checksum
        let base58 = Base58.encode(withVersion)
        return try LegacyAddress(base58)
    }
    
    func extract(from signatureScript: Data) -> Address? {
        var payload: Data?
        var validScriptType: ScriptType = ScriptType.unknown
        let sigScriptCount = signatureScript.count
        
        var outputAddress: Address?
        
        if let script = Script(data: signatureScript), // PFromSH input {push-sig}{signature}{push-redeem}{script}
            let chunkData = script.chunks.last?.scriptData,
            let redeemScript = Script(data: chunkData),
            let opCode = redeemScript.chunks.last?.opCode.value {
            // parse PFromSH transaction input
            var verifyChunkCode: UInt8 = opCode
            if verifyChunkCode == OpCode.OP_ENDIF,
                redeemScript.chunks.count > 1,
                let opCode = redeemScript.chunks.suffix(2).first?.opCode {
                
                verifyChunkCode = opCode.value    // check pre-last chunk
            }
            if OpCode.pFromShCodes.contains(verifyChunkCode) {
                payload = chunkData                                     //full script
                validScriptType = .p2sh
            }
        }
        
        if payload == nil, sigScriptCount >= 106, signatureScript[0] >= 71, signatureScript[0] <= 74 {
            // parse PFromPKH transaction input
            let signatureOffset = signatureScript[0]
            let pubKeyLength = signatureScript[Int(signatureOffset + 1)]
            
            if (pubKeyLength == 33 || pubKeyLength == 65) && sigScriptCount == signatureOffset + pubKeyLength + 2 {
                payload = signatureScript.subdata(in: Int(signatureOffset + 2)..<sigScriptCount)    // public key
                validScriptType = .p2pkh
            }
        }
        if payload == nil, sigScriptCount == ScriptType.p2wpkhSh.size,
            signatureScript[0] == 0x16,
            (signatureScript[1] == 0 || (signatureScript[1] > 0x50 && signatureScript[1] < 0x61)),
            signatureScript[2] == 0x14 {
            // parse PFromWPKH-SH transaction input
            payload = signatureScript.subdata(in: 1..<sigScriptCount)      // 0014{20-byte-key-hash}
            validScriptType = .p2wpkhSh
        }
        if let payload = payload {
            let keyHash = Crypto.sha256ripemd160(payload)
            if let address = try? convert(keyHash: keyHash, type: validScriptType) {
                outputAddress = address
            }
        }
        return outputAddress
    }
}
