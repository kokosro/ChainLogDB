//
//  ServiceProtocols.swift
//  ChainLogDb
//
//  Protocols for injectable dependencies in ChainLog services
//
//  Apps implement these protocols to provide their own network layer
//  and authentication. This allows the package to be used in different
//  contexts (iOS app, macOS app, server, etc.)
//
//  Note: Core types like EncryptedChainLogEntry, ChainLogEntry, AppendChainLogRequest,
//  EncryptedGroupChainLogEntry, GroupChainLogEntry, and AppendGroupChainLogRequest
//  are defined in their respective model files.
//

import Foundation

// MARK: - Extended Credentials Provider

/// Extension to CredentialsProvider for address retrieval
extension CredentialsProvider {
    /// Get the user's Ethereum address derived from public key
    public func getAddress() -> Hex? {
        guard let publicKey = self.publicKey else { return nil }
        return Cryptograph.publicKeyToAddress(publicKey)
    }
}

// MARK: - Chain Log Network Provider

/// Protocol for network operations on chain logs
/// Apps implement this to provide their own API client
public protocol ChainLogNetworkProvider: Sendable {
    /// Get the current head of the chain log
    func getChainLogHead(dbName: String) async throws -> ChainLogHeadInfo?
    
    /// List chain log entries starting from an index
    func listChainLogs(startIndex: Int, limit: Int, dbName: String) async throws -> (entries: [EncryptedChainLogEntry], hasMore: Bool)
    
    /// Append a new entry to the chain log
    func appendChainLog(_ request: AppendChainLogRequest, dbName: String) async throws -> EncryptedChainLogEntry
}

/// Chain log head info (lightweight struct for head queries)
public struct ChainLogHeadInfo: Sendable {
    public let index: Int
    public let hash: String
    
    public init(index: Int, hash: String) {
        self.index = index
        self.hash = hash
    }
    
    /// Create from an encrypted entry
    public init(from entry: EncryptedChainLogEntry) {
        self.index = entry.index
        self.hash = entry.hash
    }
}

// MARK: - Group Chain Log Network Provider

/// Protocol for network operations on group chain logs
public protocol GroupChainLogNetworkProvider: Sendable {
    /// Get the current head of a group chain log
    func getGroupChainLogHead(groupId: String, dbName: String) async throws -> ChainLogHeadInfo?
    
    /// List group chain log entries starting from an index
    func listGroupChainLogs(groupId: String, startIndex: Int, limit: Int, dbName: String) async throws -> (entries: [EncryptedGroupChainLogEntry], hasMore: Bool)
    
    /// Append a new entry to a group chain log
    func appendGroupChainLog(_ request: AppendGroupChainLogRequest, groupId: String, dbName: String) async throws -> ServerGroupLogEntry
}
