//
//  ChainLog.swift
//  ChainLogDb
//
//  Chain log model for hash-linked, signed append-only logs
//

import Foundation
import ChainKeys

// MARK: - Constants

/// Zero hash used as prevHash for genesis (first) entry
public let ChainLogGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// MARK: - Chain Log Entry

/// A decrypted chain log entry with verified content
public struct ChainLogEntry: Codable, Identifiable, Equatable, Sendable {
    public let index: Int
    public let prevHash: String
    public let content: String      // decrypted
    public let nonce: String
    public let hash: String
    public let signature: String
    public let createdAt: Date
    
    public var id: Int { index }
    
    public init(
        index: Int,
        prevHash: String,
        content: String,
        nonce: String,
        hash: String,
        signature: String,
        createdAt: Date
    ) {
        self.index = index
        self.prevHash = prevHash
        self.content = content
        self.nonce = nonce
        self.hash = hash
        self.signature = signature
        self.createdAt = createdAt
    }
}

// MARK: - API Response Types (encrypted)

/// Raw chain log entry from server (content is encrypted)
public struct EncryptedChainLogEntry: Codable, Sendable {
    public let index: Int
    public let prevHash: String
    public let content: String      // encrypted
    public let nonce: String
    public let hash: String
    public let signature: String
    public let createdAt: Int       // Unix timestamp in milliseconds
}

// MARK: - Protocol Conformance

extension ChainLogEntry: ChainLogEntryProtocol {}
extension EncryptedChainLogEntry: EncryptedChainLogEntryProtocol {}

/// Response for GET /self/logs
public struct ChainLogsResponse: Codable {
    public let logs: [EncryptedChainLogEntry]
    public let hasMore: Bool
}

/// Response for GET /self/logs/head
public struct ChainLogHeadResponse: Codable {
    public let head: EncryptedChainLogEntry?
}

// MARK: - Request Types

/// Request body for POST /self/logs
public struct AppendChainLogRequest: Codable {
    public let index: Int
    public let prevHash: String
    public let content: String      // encrypted
    public let nonce: String
    public let hash: String
    public let signature: String
    
    public init(
        index: Int,
        prevHash: String,
        content: String,
        nonce: String,
        hash: String,
        signature: String
    ) {
        self.index = index
        self.prevHash = prevHash
        self.content = content
        self.nonce = nonce
        self.hash = hash
        self.signature = signature
    }
}

// MARK: - Chain Log Errors

public enum ChainLogError: Error, LocalizedError {
    case invalidHash
    case invalidSignature
    case chainBroken(expected: String, got: String)
    case conflictDetected(serverHead: EncryptedChainLogEntry)
    case encryptionFailed
    case noHead
    
    public var errorDescription: String? {
        switch self {
        case .invalidHash:
            return "Hash verification failed"
        case .invalidSignature:
            return "Signature verification failed"
        case .chainBroken(let expected, let got):
            return "Chain integrity broken: expected prevHash \(expected.prefix(8))..., got \(got.prefix(8))..."
        case .conflictDetected:
            return "Chain conflict detected - another device added an entry"
        case .encryptionFailed:
            return "Failed to encrypt log content"
        case .noHead:
            return "No chain head available"
        }
    }
}
