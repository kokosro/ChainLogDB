//
//  ChainLogCore.swift
//  ChainLogDb
//
//  Protocol abstractions for ChainLog services
//  Shared logic between personal ChainLogService and GroupChainLogService
//

import Foundation

// MARK: - Constants

/// Default database name for backward compatibility
public let ChainLogDefaultDBName = "default"

// Note: ChainLogGenesisHash and GroupChainLogGenesisHash are defined in their respective model files

// MARK: - ChainLog Entry Protocol

/// Protocol for chain log entries (both personal and group)
public protocol ChainLogEntryProtocol {
    var index: Int { get }
    var prevHash: String { get }
    var hash: String { get }
    var createdAt: Date { get }
}

// MARK: - Encrypted Entry Protocol

/// Protocol for encrypted chain log entries
public protocol EncryptedChainLogEntryProtocol {
    var index: Int { get }
    var prevHash: String { get }
    var hash: String { get }
    var createdAt: Int { get } // Unix timestamp ms
}

// MARK: - ChainLog Service Protocol

/// Protocol for chain log services
/// Provides shared interface for both personal and group chain log services
public protocol ChainLogServiceProtocol: ObservableObject {
    associatedtype Entry: ChainLogEntryProtocol
    associatedtype EncryptedEntry: EncryptedChainLogEntryProtocol
    
    /// Database name
    var dbName: String { get }
    
    /// Genesis hash for chain validation
    var genesisHash: String { get }
    
    /// All chain log entries in ascending order by index
    var entries: [Entry] { get }
    
    /// Whether initial sync is in progress
    var isSyncing: Bool { get }
    
    /// Whether the service is initialized
    var isInitialized: Bool { get }
    
    /// Last sync error, if any
    var syncError: Error? { get }
    
    /// The current head (latest entry)
    var head: Entry? { get }
    
    /// Decrypt and verify an encrypted entry
    func decryptAndVerify(_ encrypted: EncryptedEntry) async throws -> Entry
    
    /// Get entry index
    func getIndex(_ entry: Entry) -> Int
    
    /// Get entry hash
    func getHash(_ entry: Entry) -> String
    
    /// Get entry prevHash
    func getPrevHash(_ entry: Entry) -> String
    
    /// Get entry by index
    func entry(at index: Int) -> Entry?
    
    /// Get entries in a range
    func entries(from startIndex: Int, limit: Int) -> [Entry]
    
    /// Initialize the service
    func initialize() async throws
    
    /// Sync with server
    func sync() async
    
    /// Cleanup resources
    func cleanup() async
    
    /// Append a new log entry
    func appendLog(content: String) async throws -> Entry
    
    /// Process an encrypted entry from WebSocket or external source
    func processEncryptedEntry(_ encrypted: EncryptedEntry) async throws -> Entry?
}

// MARK: - Default Implementations

public extension ChainLogServiceProtocol {
    /// Default genesis hash
    var genesisHash: String {
        ChainLogGenesisHash
    }
    
    /// Default database name
    var dbName: String {
        ChainLogDefaultDBName
    }
    
    /// The current head (latest entry)
    var head: Entry? {
        entries.last
    }
    
    /// Get entry by index
    func entry(at index: Int) -> Entry? {
        entries.first { $0.index == index }
    }
    
    /// Get entries in a range
    func entries(from startIndex: Int, limit: Int = 100) -> [Entry] {
        Array(entries.filter { $0.index >= startIndex }.prefix(limit))
    }
    
    /// Validate chain link for an entry
    func validateChainLink(entry: Entry, lastEntry: Entry?) -> Bool {
        if getIndex(entry) == 0 {
            // Genesis entry
            return getPrevHash(entry) == genesisHash
        }
        
        guard let last = lastEntry else {
            // Can't validate without a previous entry for non-genesis
            return false
        }
        
        // Check sequential index
        guard getIndex(entry) == getIndex(last) + 1 else {
            return false
        }
        
        // Check hash link
        return getPrevHash(entry) == getHash(last)
    }
    
    /// Append entry to local cache if it maintains chain integrity
    /// - Parameters:
    ///   - entry: The entry to append
    ///   - entries: The current entries array (inout)
    /// - Returns: true if entry was added, false otherwise
    func appendEntryIfValid(_ entry: Entry, to entries: inout [Entry]) -> Bool {
        // Check if we already have this entry
        if entries.contains(where: { getIndex($0) == getIndex(entry) }) {
            return false
        }
        
        // Verify chain link
        if getIndex(entry) == 0 {
            // Genesis entry
            guard getPrevHash(entry) == genesisHash else {
                print("[ChainLogCore] Invalid genesis prevHash for \(dbName)")
                return false
            }
        } else if let lastEntry = entries.last {
            // Check that this entry links to our last entry
            if getIndex(entry) == getIndex(lastEntry) + 1 {
                guard getPrevHash(entry) == getHash(lastEntry) else {
                    print("[ChainLogCore] Chain broken at index \(getIndex(entry)) for \(dbName)")
                    return false
                }
            } else if getIndex(entry) > getIndex(lastEntry) + 1 {
                // Gap in chain - caller should trigger sync
                print("[ChainLogCore] Gap detected: have \(getIndex(lastEntry)), got \(getIndex(entry)) for \(dbName)")
                return false
            }
        }
        
        // Insert in order
        if let insertIndex = entries.firstIndex(where: { getIndex($0) > getIndex(entry) }) {
            entries.insert(entry, at: insertIndex)
        } else {
            entries.append(entry)
        }
        
        return true
    }
}

// MARK: - Note on Errors
// ChainLogError is defined in Models/ChainLog.swift
// GroupChainLogError is defined in Models/GroupChainLog.swift
