//
//  FileStorageProvider.swift
//  ChainLogDb
//
//  Default file-based implementation of StorageProvider
//
//  Stores data in JSON files in the app's documents directory.
//  Provides in-memory caching for fast access.
//

import Foundation

// MARK: - File Storage Provider

/// File-based implementation of StorageProvider
/// Stores MLS group state and credentials as JSON files
public actor FileStorageProvider: StorageProvider {
    
    // MARK: - Constants
    
    private static let stateFileName = "state.json"
    private static let credentialFileName = "credential.json"
    private static let publicKeyFileName = "publickey.json"
    
    // MARK: - Properties
    
    /// Base directory for all storage
    private let baseDirectory: URL
    
    /// In-memory cache for group states
    private var stateCache: [String: GroupState] = [:]
    
    /// In-memory cache for credentials
    private var credentialCache: [String: MemberCredential] = [:]
    
    /// In-memory cache for group public keys
    private var publicKeyCache: [String: GroupPublicKey] = [:]
    
    // MARK: - Initialization
    
    /// Initialize with a custom base directory
    /// - Parameter baseDirectory: Directory to store files (will be created if needed)
    public init(baseDirectory: URL) {
        self.baseDirectory = baseDirectory
        
        // Create base directory if needed
        try? FileManager.default.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
    }
    
    /// Initialize with a subdirectory in the app's documents folder
    /// - Parameter subdirectory: Name of subdirectory (e.g., "groups")
    public init(subdirectory: String = "chainlog-groups") {
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        self.baseDirectory = documentsPath.appendingPathComponent(subdirectory, isDirectory: true)
        
        try? FileManager.default.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
    }
    
    // MARK: - Private Helpers
    
    /// Get directory for a specific group
    private func groupDirectory(groupId: String) -> URL {
        baseDirectory.appendingPathComponent(groupId, isDirectory: true)
    }
    
    /// Ensure group directory exists
    private func ensureGroupDirectory(groupId: String) throws {
        let dir = groupDirectory(groupId: groupId)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    
    // MARK: - Group State Storage
    
    public func saveGroupState(_ state: GroupState, groupId: String) async throws {
        try ensureGroupDirectory(groupId: groupId)
        
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.stateFileName)
        
        let data = try GroupStateCodable.encode(state)
        try data.write(to: fileURL, options: .completeFileProtection)
        
        // Update cache
        stateCache[groupId] = state
    }
    
    public func loadGroupState(groupId: String) async throws -> GroupState? {
        // Check cache first
        if let cached = stateCache[groupId] {
            return cached
        }
        
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.stateFileName)
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        
        let data = try Data(contentsOf: fileURL)
        let state = try GroupStateCodable.decode(from: data)
        
        // Update cache
        stateCache[groupId] = state
        
        return state
    }
    
    public func deleteGroupState(groupId: String) async throws {
        let groupDir = groupDirectory(groupId: groupId)
        
        // Remove entire group directory (includes all related files)
        if FileManager.default.fileExists(atPath: groupDir.path) {
            try FileManager.default.removeItem(at: groupDir)
        }
        
        // Clear from caches
        stateCache.removeValue(forKey: groupId)
        credentialCache.removeValue(forKey: groupId)
        publicKeyCache.removeValue(forKey: groupId)
    }
    
    public func listGroupIds() async throws -> [String] {
        guard FileManager.default.fileExists(atPath: baseDirectory.path) else {
            return []
        }
        
        let contents = try FileManager.default.contentsOfDirectory(
            at: baseDirectory,
            includingPropertiesForKeys: [.isDirectoryKey]
        )
        
        return contents.compactMap { url in
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
                  isDirectory.boolValue else {
                return nil
            }
            
            // Check if this directory contains a state file
            let stateFile = url.appendingPathComponent(Self.stateFileName)
            guard FileManager.default.fileExists(atPath: stateFile.path) else {
                return nil
            }
            
            return url.lastPathComponent
        }
    }
    
    // MARK: - Credential Storage
    
    public func saveCredential(_ credential: MemberCredential, groupId: String) async throws {
        try ensureGroupDirectory(groupId: groupId)
        
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.credentialFileName)
        
        let data = try MemberCredentialCodable.encode(credential)
        try data.write(to: fileURL, options: .completeFileProtection)
        
        credentialCache[groupId] = credential
    }
    
    public func loadCredential(groupId: String) async throws -> MemberCredential? {
        if let cached = credentialCache[groupId] {
            return cached
        }
        
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.credentialFileName)
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        
        let data = try Data(contentsOf: fileURL)
        let credential = try MemberCredentialCodable.decode(from: data)
        
        credentialCache[groupId] = credential
        
        return credential
    }
    
    public func deleteCredential(groupId: String) async throws {
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.credentialFileName)
        
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
        
        credentialCache.removeValue(forKey: groupId)
    }
    
    // MARK: - Group Public Key Storage
    
    public func saveGroupPublicKey(_ key: GroupPublicKey, groupId: String) async throws {
        try ensureGroupDirectory(groupId: groupId)
        
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.publicKeyFileName)
        
        let data = try GroupPublicKeyCodable.encode(key)
        try data.write(to: fileURL, options: .completeFileProtection)
        
        publicKeyCache[groupId] = key
    }
    
    public func loadGroupPublicKey(groupId: String) async throws -> GroupPublicKey? {
        if let cached = publicKeyCache[groupId] {
            return cached
        }
        
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.publicKeyFileName)
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        
        let data = try Data(contentsOf: fileURL)
        let key = try GroupPublicKeyCodable.decode(from: data)
        
        publicKeyCache[groupId] = key
        
        return key
    }
    
    public func deleteGroupPublicKey(groupId: String) async throws {
        let fileURL = groupDirectory(groupId: groupId)
            .appendingPathComponent(Self.publicKeyFileName)
        
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
        
        publicKeyCache.removeValue(forKey: groupId)
    }
    
    // MARK: - Cache Management
    
    /// Clear all in-memory caches
    public func clearCache() {
        stateCache.removeAll()
        credentialCache.removeAll()
        publicKeyCache.removeAll()
    }
    
    /// Clear all stored data (caches and files)
    public func clearAll() throws {
        if FileManager.default.fileExists(atPath: baseDirectory.path) {
            try FileManager.default.removeItem(at: baseDirectory)
        }
        
        try FileManager.default.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
        
        clearCache()
    }
    
    /// Preload all data into memory cache
    public func preloadAll() async throws {
        let groupIds = try await listGroupIds()
        
        for groupId in groupIds {
            _ = try await loadGroupState(groupId: groupId)
            _ = try await loadCredential(groupId: groupId)
            _ = try await loadGroupPublicKey(groupId: groupId)
        }
    }
}

// MARK: - Sendable Wrapper for non-isolated access

/// Non-isolated wrapper for FileStorageProvider
/// Use when you need synchronous access patterns
public struct FileStorageProviderRef: Sendable {
    public let provider: FileStorageProvider
    
    public init(baseDirectory: URL) {
        self.provider = FileStorageProvider(baseDirectory: baseDirectory)
    }
    
    public init(subdirectory: String = "chainlog-groups") {
        self.provider = FileStorageProvider(subdirectory: subdirectory)
    }
}
