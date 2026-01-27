//
//  StorageProvider.swift
//  ChainLogDb
//
//  Protocol defining storage operations for MLS group state and credentials
//
//  Apps can implement this protocol to customize storage behavior
//  (e.g., using Keychain, encrypted files, or cloud sync).
//

import Foundation

// MARK: - Storage Provider Protocol

/// Protocol for storing and retrieving MLS group state and credentials
/// Implement this protocol to provide custom storage for your app
public protocol StorageProvider: Sendable {
    
    // MARK: - Group State
    
    /// Save an MLS group state
    func saveGroupState(_ state: GroupState, groupId: String) async throws
    
    /// Load an MLS group state
    func loadGroupState(groupId: String) async throws -> GroupState?
    
    /// Delete an MLS group state
    func deleteGroupState(groupId: String) async throws
    
    /// List all stored group IDs
    func listGroupIds() async throws -> [String]
    
    // MARK: - Member Credentials
    
    /// Save a member credential for a group
    func saveCredential(_ credential: MemberCredential, groupId: String) async throws
    
    /// Load a member credential for a group
    func loadCredential(groupId: String) async throws -> MemberCredential?
    
    /// Delete a member credential
    func deleteCredential(groupId: String) async throws
    
    // MARK: - Group Public Keys
    
    /// Save a group public key
    func saveGroupPublicKey(_ key: GroupPublicKey, groupId: String) async throws
    
    /// Load a group public key
    func loadGroupPublicKey(groupId: String) async throws -> GroupPublicKey?
    
    /// Delete a group public key
    func deleteGroupPublicKey(groupId: String) async throws
}

// MARK: - Storage Provider Errors

public enum StorageProviderError: Error, LocalizedError {
    case notInitialized
    case serializationFailed(String)
    case deserializationFailed(String)
    case itemNotFound(String)
    case writeError(Error)
    case readError(Error)
    case deleteError(Error)
    
    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "Storage provider not initialized"
        case .serializationFailed(let msg):
            return "Serialization failed: \(msg)"
        case .deserializationFailed(let msg):
            return "Deserialization failed: \(msg)"
        case .itemNotFound(let id):
            return "Item not found: \(id)"
        case .writeError(let error):
            return "Write error: \(error.localizedDescription)"
        case .readError(let error):
            return "Read error: \(error.localizedDescription)"
        case .deleteError(let error):
            return "Delete error: \(error.localizedDescription)"
        }
    }
}

// MARK: - Codable Helpers

/// Helper enum with nonisolated static methods for encoding/decoding GroupState
/// This avoids Swift 6 actor isolation issues with Codable
public enum GroupStateCodable: Sendable {
    
    /// Encode GroupState to Data
    public nonisolated static func encode(_ state: GroupState) throws -> Data {
        let encoder = JSONEncoder()
        return try encoder.encode(state)
    }
    
    /// Decode GroupState from Data
    public nonisolated static func decode(from data: Data) throws -> GroupState {
        let decoder = JSONDecoder()
        return try decoder.decode(GroupState.self, from: data)
    }
    
    /// Encode GroupState to JSON String
    public nonisolated static func encodeToString(_ state: GroupState) throws -> String {
        let data = try encode(state)
        guard let string = String(data: data, encoding: .utf8) else {
            throw StorageProviderError.serializationFailed("Failed to convert data to string")
        }
        return string
    }
    
    /// Decode GroupState from JSON String
    public nonisolated static func decodeFromString(_ string: String) throws -> GroupState {
        guard let data = string.data(using: .utf8) else {
            throw StorageProviderError.deserializationFailed("Invalid UTF-8 string")
        }
        return try decode(from: data)
    }
}

/// Helper enum for credential encoding/decoding
public enum MemberCredentialCodable: Sendable {
    
    public nonisolated static func encode(_ credential: MemberCredential) throws -> Data {
        try JSONEncoder().encode(credential)
    }
    
    public nonisolated static func decode(from data: Data) throws -> MemberCredential {
        try JSONDecoder().decode(MemberCredential.self, from: data)
    }
}

/// Helper enum for group public key encoding/decoding
public enum GroupPublicKeyCodable: Sendable {
    
    public nonisolated static func encode(_ key: GroupPublicKey) throws -> Data {
        try JSONEncoder().encode(key)
    }
    
    public nonisolated static func decode(from data: Data) throws -> GroupPublicKey {
        try JSONDecoder().decode(GroupPublicKey.self, from: data)
    }
}
