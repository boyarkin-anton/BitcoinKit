//
//  PeerGroup.swift
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

import Foundation

public class PeerGroup: PeerDelegate {
    public let blockChain: BlockChain
    public let maxConnections: Int

    public weak var delegate: PeerGroupDelegate?

    var peers = [String: Peer]()

    private var filters = [Data]()
    private var transactions = [Transaction]()
    
    private var currentPeerID: Int = 0
    
    private let peersQueue: DispatchQueue

    public init(blockChain: BlockChain, maxConnections: Int = 1) {
        self.blockChain = blockChain
        self.maxConnections = maxConnections
        
        peersQueue = DispatchQueue(label: "PeerGroup Local Queue", qos: .userInitiated)
    }

    public func start() {
        peersQueue.async {
            let network = self.blockChain.network
            for _ in self.peers.count..<self.maxConnections {
                let peer = Peer(host: network.dnsSeeds[self.currentPeerID % network.dnsSeeds.count], network: network)
                peer.delegate = self
                peer.connect()
                
                self.peers[peer.host] = peer
            }
            
            self.currentPeerID += 1
            
            self.delegate?.peerGroupDidStart(self)
        }
    }

    public func stop() {
        peersQueue.async {
            for peer in self.peers.values {
                peer.delegate = nil
                peer.disconnect()
            }
            self.peers.removeAll()

            self.delegate?.peerGroupDidStop(self)
        }
    }

    // filter: pubkey, pubkeyhash, scripthash, etc...
    public func addFilter(_ filter: Data) {
        filters.append(filter)
    }

    public func sendTransaction(transaction: Transaction) {
        if let peer = peers.values.first {
            peersQueue.async {
                peer.sendTransaction(transaction: transaction)
            }
        } else {
            transactions.append(transaction)
            start()
        }
    }

    public func peerDidConnect(_ peer: Peer) {
        peersQueue.async {
            if self.peers.filter({ $0.value.context.isSyncing }).isEmpty {
                let latestBlockHash = self.blockChain.latestBlockHash()
                let latestBlockHeight = self.blockChain.latestBlockHeight()
                peer.startSync(filters: self.filters, latestBlockHash: latestBlockHash, latestBlockHeight: latestBlockHeight)
            }
            if !self.transactions.isEmpty {
                for transaction in self.transactions {
                    peer.sendTransaction(transaction: transaction)
                }
            }
        }
    }

    public func peerDidDisconnect(_ peer: Peer) {
        peers[peer.host] = nil
        start()
    }

    public func peer(_ peer: Peer, didReceiveVersionMessage message: VersionMessage) {
        if message.userAgent?.value.contains("Bitcoin ABC:0.16") == true {
            print("it's old version. Let's try to disconnect and connect to aother peer.")
            peersQueue.async {
                peer.disconnect()
            }
        }
    }

    public func peer(_ peer: Peer, didReceiveMerkleBlockMessage message: MerkleBlockMessage, hash: Data, height: Int32) {
        try! blockChain.addMerkleBlock(message, hash: hash, height: height)
    }

    public func peer(_ peer: Peer, didReceiveTransaction transaction: Transaction, hash: Data) {
        try! blockChain.addTransaction(transaction, hash: hash)
        delegate?.peerGroupDidReceiveTransaction(self)
    }
    
    public func peer(_ peer: Peer, didChangedState state: PeerState) {
        delegate?.peerGroupDidChanged(state)
    }
}

public protocol PeerGroupDelegate: class {
    func peerGroupDidStart(_ peerGroup: PeerGroup)
    func peerGroupDidStop(_ peerGroup: PeerGroup)
    func peerGroupDidReceiveTransaction(_ peerGroup: PeerGroup)
    func peerGroupDidChanged(_ state: PeerState)
}

extension PeerGroupDelegate {
    public func peerGroupDidStart(_ peerGroup: PeerGroup) {}
    public func peerGroupDidStop(_ peerGroup: PeerGroup) {}
    public func peerGroupDidReceiveTransaction(_ peerGroup: PeerGroup) {}
    public func peerGroupDidChanged(_ state: PeerState) {}
}

public enum PeerState {
    case synced
    case syncing(progress: Double)
    case notSynced
}
