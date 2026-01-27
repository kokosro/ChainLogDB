//
//  GroupChainLog.swift
//  ChainLogDb
//
//  Privacy-Preserving Group Chain Log Types
//  Server only sees opaque ciphertext and verifies group membership proofs
//
//  Key privacy properties:
//  - senderAddress and epoch are INSIDE the ciphertext (hidden from server)
//  - groupSignature provides anonymous membership proof (BBS+ style)
//  - accessProof provides lightweight epoch verification
//

import Foundation
import ChainKeys

// MARK: - Constants

/// Zero hash used as prevHash for genesis (first) entry
public let GroupChainLogGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// MARK: - Server-Side Entry (Privacy-Preserving Wire Format)

/// What the server sees - only opaque ciphertext and membership proofs
/// Server CANNOT see: senderAddress, epoch, content
public struct ServerGroupLogEntry: Codable, Sendable {
    public let index: Int
    public let prevHash: String
    public let ciphertext: String           // Encrypted payload (content + all metadata)
    public let nonce: String
    public let hash: String                 // SHA256(index:prevHash:ciphertext:nonce)
    public let groupSignature: String       // BBS+ group signature (ZK membership proof)
    public let accessProof: String          // HMAC(epochAccessKey, hash)
    public let createdAt: Int               // Unix timestamp in milliseconds
    
    public init(
        index: Int,
        prevHash: String,
        ciphertext: String,
        nonce: String,
        hash: String,
        groupSignature: String,
        accessProof: String,
        createdAt: Int
    ) {
        self.index = index
        self.prevHash = prevHash
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.hash = hash
        self.groupSignature = groupSignature
        self.accessProof = accessProof
        self.createdAt = createdAt
    }
}

// MARK: - Encrypted Entry (with groupId for client convenience)

/// Server entry plus groupId (added by client/API layer)
public struct EncryptedGroupChainLogEntry: Codable, Sendable {
    public let index: Int
    public let prevHash: String
    public let ciphertext: String
    public let nonce: String
    public let hash: String
    public let groupSignature: String
    public let accessProof: String
    public let createdAt: Int
    public let groupId: String              // Added client-side for convenience
    
    public init(
        index: Int,
        prevHash: String,
        ciphertext: String,
        nonce: String,
        hash: String,
        groupSignature: String,
        accessProof: String,
        createdAt: Int,
        groupId: String
    ) {
        self.index = index
        self.prevHash = prevHash
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.hash = hash
        self.groupSignature = groupSignature
        self.accessProof = accessProof
        self.createdAt = createdAt
        self.groupId = groupId
    }
    
    /// Create from ServerGroupLogEntry with groupId
    public init(from serverEntry: ServerGroupLogEntry, groupId: String) {
        self.index = serverEntry.index
        self.prevHash = serverEntry.prevHash
        self.ciphertext = serverEntry.ciphertext
        self.nonce = serverEntry.nonce
        self.hash = serverEntry.hash
        self.groupSignature = serverEntry.groupSignature
        self.accessProof = serverEntry.accessProof
        self.createdAt = serverEntry.createdAt
        self.groupId = groupId
    }
}

// MARK: - Decrypted Payload (Inside Ciphertext)

/// What's encrypted inside the ciphertext - only group members can see this
public struct DecryptedPayload: Codable, Sendable {
    /// Application content (JSON string)
    public let content: String
    /// Who sent this (Ethereum address)
    public let senderAddress: Hex
    /// ECDSA signature of content (for non-repudiation within group)
    public let senderSignature: Hex
    /// MLS epoch when sent
    public let epoch: Int
    /// Client timestamp (milliseconds)
    public let timestamp: Int
    /// System operation (if any)
    public let systemOp: SystemOperation?
    
    public init(
        content: String,
        senderAddress: Hex,
        senderSignature: Hex,
        epoch: Int,
        timestamp: Int,
        systemOp: SystemOperation? = nil
    ) {
        self.content = content
        self.senderAddress = senderAddress
        self.senderSignature = senderSignature
        self.epoch = epoch
        self.timestamp = timestamp
        self.systemOp = systemOp
    }
}

// MARK: - System Operations

/// System operations for membership changes and epoch transitions
public enum SystemOperation: Codable, Sendable, Equatable {
    case epochTransition(newAccessKey: String, transitionProof: String)
    case joinRequest(requestId: String, inviteePublicKey: Hex, inviterAddress: Hex, encryptedWelcome: String, requestedAt: Int)
    case joinAccepted(requestId: String, newMemberAddress: Hex, memberCredential: String, newEpochAccessKey: String, transitionProof: String)
    case memberRemoved(removedAddress: Hex, revocationWitness: String, newEpochAccessKey: String, transitionProof: String)
    
    private enum CodingKeys: String, CodingKey {
        case type
        case newAccessKey, transitionProof
        case requestId, inviteePublicKey, inviterAddress, encryptedWelcome, requestedAt
        case newMemberAddress, memberCredential, newEpochAccessKey
        case removedAddress, revocationWitness
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        
        switch type {
        case "epoch_transition":
            let newAccessKey = try container.decode(String.self, forKey: .newAccessKey)
            let transitionProof = try container.decode(String.self, forKey: .transitionProof)
            self = .epochTransition(newAccessKey: newAccessKey, transitionProof: transitionProof)
            
        case "join_request":
            let requestId = try container.decode(String.self, forKey: .requestId)
            let inviteePublicKey = try container.decode(Hex.self, forKey: .inviteePublicKey)
            let inviterAddress = try container.decode(Hex.self, forKey: .inviterAddress)
            let encryptedWelcome = try container.decode(String.self, forKey: .encryptedWelcome)
            let requestedAt = try container.decode(Int.self, forKey: .requestedAt)
            self = .joinRequest(requestId: requestId, inviteePublicKey: inviteePublicKey, inviterAddress: inviterAddress, encryptedWelcome: encryptedWelcome, requestedAt: requestedAt)
            
        case "join_accepted":
            let requestId = try container.decode(String.self, forKey: .requestId)
            let newMemberAddress = try container.decode(Hex.self, forKey: .newMemberAddress)
            let memberCredential = try container.decode(String.self, forKey: .memberCredential)
            let newEpochAccessKey = try container.decode(String.self, forKey: .newEpochAccessKey)
            let transitionProof = try container.decode(String.self, forKey: .transitionProof)
            self = .joinAccepted(requestId: requestId, newMemberAddress: newMemberAddress, memberCredential: memberCredential, newEpochAccessKey: newEpochAccessKey, transitionProof: transitionProof)
            
        case "member_removed":
            let removedAddress = try container.decode(Hex.self, forKey: .removedAddress)
            let revocationWitness = try container.decode(String.self, forKey: .revocationWitness)
            let newEpochAccessKey = try container.decode(String.self, forKey: .newEpochAccessKey)
            let transitionProof = try container.decode(String.self, forKey: .transitionProof)
            self = .memberRemoved(removedAddress: removedAddress, revocationWitness: revocationWitness, newEpochAccessKey: newEpochAccessKey, transitionProof: transitionProof)
            
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Unknown system operation type: \(type)")
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .epochTransition(let newAccessKey, let transitionProof):
            try container.encode("epoch_transition", forKey: .type)
            try container.encode(newAccessKey, forKey: .newAccessKey)
            try container.encode(transitionProof, forKey: .transitionProof)
            
        case .joinRequest(let requestId, let inviteePublicKey, let inviterAddress, let encryptedWelcome, let requestedAt):
            try container.encode("join_request", forKey: .type)
            try container.encode(requestId, forKey: .requestId)
            try container.encode(inviteePublicKey, forKey: .inviteePublicKey)
            try container.encode(inviterAddress, forKey: .inviterAddress)
            try container.encode(encryptedWelcome, forKey: .encryptedWelcome)
            try container.encode(requestedAt, forKey: .requestedAt)
            
        case .joinAccepted(let requestId, let newMemberAddress, let memberCredential, let newEpochAccessKey, let transitionProof):
            try container.encode("join_accepted", forKey: .type)
            try container.encode(requestId, forKey: .requestId)
            try container.encode(newMemberAddress, forKey: .newMemberAddress)
            try container.encode(memberCredential, forKey: .memberCredential)
            try container.encode(newEpochAccessKey, forKey: .newEpochAccessKey)
            try container.encode(transitionProof, forKey: .transitionProof)
            
        case .memberRemoved(let removedAddress, let revocationWitness, let newEpochAccessKey, let transitionProof):
            try container.encode("member_removed", forKey: .type)
            try container.encode(removedAddress, forKey: .removedAddress)
            try container.encode(revocationWitness, forKey: .revocationWitness)
            try container.encode(newEpochAccessKey, forKey: .newEpochAccessKey)
            try container.encode(transitionProof, forKey: .transitionProof)
        }
    }
}

// MARK: - Client-Side Decrypted Entry

/// Fully decrypted group chain log entry (local view after decryption)
public struct GroupChainLogEntry: Codable, Identifiable, Equatable, Sendable {
    // Chain structure
    public let index: Int
    public let prevHash: String
    public let nonce: String
    public let hash: String
    public let createdAt: Date
    public let groupId: String
    
    // Decrypted payload
    public let content: String              // Decrypted content
    public let senderAddress: Hex           // Decrypted from payload
    public let senderSignature: Hex         // Decrypted from payload
    public let epoch: Int                   // Decrypted from payload
    public let timestamp: Int               // Client timestamp from payload
    
    // System operation (if any)
    public let systemOp: SystemOperation?
    
    public var id: String { "\(groupId)-\(index)" }
    
    public init(
        index: Int,
        prevHash: String,
        nonce: String,
        hash: String,
        createdAt: Date,
        groupId: String,
        content: String,
        senderAddress: Hex,
        senderSignature: Hex,
        epoch: Int,
        timestamp: Int,
        systemOp: SystemOperation? = nil
    ) {
        self.index = index
        self.prevHash = prevHash
        self.nonce = nonce
        self.hash = hash
        self.createdAt = createdAt
        self.groupId = groupId
        self.content = content
        self.senderAddress = senderAddress
        self.senderSignature = senderSignature
        self.epoch = epoch
        self.timestamp = timestamp
        self.systemOp = systemOp
    }
    
    /// Create from encrypted entry and decrypted payload
    public init(from encrypted: EncryptedGroupChainLogEntry, payload: DecryptedPayload) {
        self.index = encrypted.index
        self.prevHash = encrypted.prevHash
        self.nonce = encrypted.nonce
        self.hash = encrypted.hash
        self.createdAt = Date(timeIntervalSince1970: Double(encrypted.createdAt) / 1000)
        self.groupId = encrypted.groupId
        self.content = payload.content
        self.senderAddress = payload.senderAddress
        self.senderSignature = payload.senderSignature
        self.epoch = payload.epoch
        self.timestamp = payload.timestamp
        self.systemOp = payload.systemOp
    }
}

// MARK: - Protocol Conformance

extension GroupChainLogEntry: ChainLogEntryProtocol {}
extension EncryptedGroupChainLogEntry: EncryptedChainLogEntryProtocol {}

// MARK: - API Response Types

/// Response for GET /groups/:groupId/logs/:dbName
public struct GroupChainLogsResponse: Codable {
    public let logs: [ServerGroupLogEntry]
    public let hasMore: Bool
}

/// Response for GET /groups/:groupId/logs/:dbName/head
public struct GroupChainLogHeadResponse: Codable {
    public let head: ServerGroupLogEntry?
}

// MARK: - Request Types

/// Request body for POST /groups/:groupId/logs/:dbName (privacy-preserving)
public struct AppendGroupChainLogRequest: Codable {
    public let index: Int
    public let prevHash: String
    public let ciphertext: String           // Encrypted payload
    public let nonce: String
    public let hash: String
    public let groupSignature: String       // BBS+ group signature
    public let accessProof: String          // HMAC(epochAccessKey, hash)
    // Optional: for epoch transitions only
    public let newEpochAccessKey: String?
    public let epochTransitionProof: String?
    
    public init(
        index: Int,
        prevHash: String,
        ciphertext: String,
        nonce: String,
        hash: String,
        groupSignature: String,
        accessProof: String,
        newEpochAccessKey: String? = nil,
        epochTransitionProof: String? = nil
    ) {
        self.index = index
        self.prevHash = prevHash
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.hash = hash
        self.groupSignature = groupSignature
        self.accessProof = accessProof
        self.newEpochAccessKey = newEpochAccessKey
        self.epochTransitionProof = epochTransitionProof
    }
}

/// Request body for POST /groups (privacy-preserving)
public struct CreateGroupRequest: Codable {
    public let groupId: String
    public let groupPublicKey: String       // BBS+ group public key (JSON)
    public let initialAccessKey: String     // Epoch 0 access key (hex)
    
    public init(groupId: String, groupPublicKey: String, initialAccessKey: String) {
        self.groupId = groupId
        self.groupPublicKey = groupPublicKey
        self.initialAccessKey = initialAccessKey
    }
}

// MARK: - Group Info

/// Minimal group info from server
public struct GroupInfo: Codable, Identifiable, Sendable {
    public let groupId: String
    public let createdAt: Int               // Unix timestamp in milliseconds
    
    public var id: String { groupId }
    
    public init(groupId: String, createdAt: Int) {
        self.groupId = groupId
        self.createdAt = createdAt
    }
}

// MARK: - Group Chain Log Errors

public enum GroupChainLogError: Error, LocalizedError {
    case invalidHash
    case invalidSignature
    case invalidGroupSignature(String)
    case invalidAccessProof
    case invalidEpochTransition
    case chainBroken(expected: String, got: String)
    case conflictDetected(serverHead: EncryptedGroupChainLogEntry)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case noHead
    case notAMember
    case invalidEpoch(expected: Int, got: Int)
    case senderNotMember(address: Hex)
    case unknownSender
    case readonlyMode
    case pendingJoin
    case missingCredential
    
    public var errorDescription: String? {
        switch self {
        case .invalidHash:
            return "Hash verification failed"
        case .invalidSignature:
            return "Signature verification failed"
        case .invalidGroupSignature(let msg):
            return "Invalid group signature: \(msg)"
        case .invalidAccessProof:
            return "Invalid access proof"
        case .invalidEpochTransition:
            return "Invalid epoch transition proof"
        case .chainBroken(let expected, let got):
            return "Chain integrity broken: expected prevHash \(expected.prefix(8))..., got \(got.prefix(8))..."
        case .conflictDetected:
            return "Chain conflict detected - another member added an entry"
        case .encryptionFailed(let msg):
            return "Failed to encrypt log content: \(msg)"
        case .decryptionFailed(let msg):
            return "Failed to decrypt log content: \(msg)"
        case .noHead:
            return "No chain head available"
        case .notAMember:
            return "You are not a member of this group"
        case .invalidEpoch(let expected, let got):
            return "Invalid epoch: expected \(expected), got \(got)"
        case .senderNotMember(let address):
            return "Sender \(address.truncatedAddress) is not a member of the group"
        case .unknownSender:
            return "Could not identify sender"
        case .readonlyMode:
            return "Group is in readonly mode during membership transition"
        case .pendingJoin:
            return "A join request is pending"
        case .missingCredential:
            return "Missing BBS+ member credential"
        }
    }
}

// MARK: - Verification Result

public struct VerificationResult: Sendable {
    public let valid: Bool
    public let error: String?
    
    public init(valid: Bool, error: String? = nil) {
        self.valid = valid
        self.error = error
    }
    
    public static func success() -> VerificationResult {
        VerificationResult(valid: true)
    }
    
    public static func failure(_ error: String) -> VerificationResult {
        VerificationResult(valid: false, error: error)
    }
}
