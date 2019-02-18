//
//  CheckpointSyncer.swift
//  BitcoinKit
//
//  Created by Anton Boyarkin on 18/02/2019.
//

import Foundation

public class CheckpointSyncer: PeerDelegate {
    public let network: Network
    public let maxConnections: Int
    
    var peers = [String: Peer]()
    
    private var filters = [Data]()
    private var transactions = [Transaction]()
    
    private var currentPeerID: Int = 0
    
    private let peersQueue: DispatchQueue
    
    private var checkpoints: [Checkpoint] = [Checkpoint]()
    
    private var finishAction: ((Checkpoint) -> Void)? = nil
    
    public private(set) var isSynced = false
    
    public init(network: Network, maxConnections: Int = 1) {
        self.network = network
        self.maxConnections = maxConnections
        
        peersQueue = DispatchQueue(label: "CheckpointSyncer Local Queue", qos: .userInitiated)
    }
    
    public func sync(_ completion: @escaping (Checkpoint) -> Void) {
        finishAction = completion
        start()
    }
    
    public func onFinish(_ action: @escaping (Checkpoint) -> Void) {
        if isSynced {
            action(latestCheckpoint())
        } else {
            finishAction = action
        }
    }
    
    public func start() {
        peersQueue.async {
            for _ in self.peers.count..<self.maxConnections {
                let peer = Peer(host: self.network.dnsSeeds[self.currentPeerID % self.network.dnsSeeds.count], network: self.network)
                peer.delegate = self
                peer.connect()
                
                self.peers[peer.host] = peer
            }
            
            self.currentPeerID += 1
        }
    }
    
    public func stop() {
        peersQueue.async {
            for peer in self.peers.values {
                peer.delegate = nil
                peer.disconnect()
            }
            self.peers.removeAll()
        }
    }
    
    public func peerDidConnect(_ peer: Peer) {
        peersQueue.async {
            if self.peers.filter({ $0.value.context.isSyncing }).isEmpty {
                let latestCheckpoint = self.latestCheckpoint()
                let latestBlockHash = latestCheckpoint.hash
                let latestBlockHeight = latestCheckpoint.height
                peer.startSync(filters: self.filters, latestBlockHash: latestBlockHash, latestBlockHeight: latestBlockHeight, onlyCheckpoints: true)
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
    
    public func peer(_ peer: Peer, didChangedState state: PeerState) {
        switch state {
        case .synced:
            isSynced = true
            self.stop()
            self.finishAction?(latestCheckpoint())
        default:
            return
        }
    }
    
    public func peer(_ peer: Peer, didReceiveCheckpoint checkpoint: Checkpoint) {
        self.checkpoints.append(checkpoint)
    }
    
    public func latestCheckpoint() -> Checkpoint {
        if let latestCheckpoint = checkpoints.last {
            return latestCheckpoint
        }
        if let latestCheckpoint = self.network.checkpoints.last {
            return latestCheckpoint
        }
        return Checkpoint(height: 0, hash: self.network.genesisBlock)
    }
}
