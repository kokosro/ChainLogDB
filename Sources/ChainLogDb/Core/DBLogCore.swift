//
//  DBLogCore.swift
//  ChainLogDb
//
//  Protocol abstractions for DBLog services
//  Shared logic between personal DBLogService and GroupDBLogService
//

import Foundation

// MARK: - DBLog Service Protocol

/// Protocol for DBLog services
/// Provides shared interface for both personal and group DBLog services
public protocol DBLogServiceProtocol: ObservableObject {
    associatedtype ChainEntry
    
    /// Database name
    var dbName: String { get }
    
    /// Whether the service is ready for operations
    var isReady: Bool { get }
    
    /// Whether initialization is in progress
    var isInitializing: Bool { get }
    
    /// Last processed chain log index
    var lastProcessedChainIndex: Int { get }
    
    /// Last processed DBLog index (within a chain entry)
    var lastProcessedDBLogIndex: Int { get }
    
    /// Initialize the service
    func initialize() async throws
    
    /// Cleanup resources
    func cleanup() async
    
    /// Sync with server and process new entries
    func sync() async throws -> Set<String>
    
    /// Append DBLog actions to the chain
    func append(_ actions: [DBLogAction]) async throws
    
    /// Create a table through the log
    func createTable(_ name: String, columns: [String: String]) async throws
    
    /// Set (upsert) a row through the log
    func set(table: String, id: String, data: [String: DBLogValue]) async throws
    
    /// Delete a row through the log
    func delete(table: String, id: String) async throws
    
    /// Migrate a table schema through the log
    func migrate(table: String, version: Int, operations: [MigrationOp]) async throws
    
    // Note: batch() is not part of protocol since builder types differ
    // Personal DBLogService uses BatchBuilder
    // GroupDBLogService uses GroupDBBatchBuilder
    
    // MARK: - Query Operations
    
    /// Query all rows from a table
    func queryAll(table: String) async throws -> [[String: Any]]
    
    /// Query a single row by id
    func get(table: String, id: String) async throws -> [String: Any]?
    
    /// Query with a WHERE condition
    func query(table: String, where condition: String) async throws -> [[String: Any]]
    
    /// Execute a raw SQL query (SELECT only)
    func rawQuery(_ sql: String) async throws -> [[String: Any]]
    
    /// Count rows in a table
    func count(table: String) async throws -> Int
    
    /// Check if a table exists
    func tableExists(_ name: String) async throws -> Bool
    
    /// Get schema version for a table
    func schemaVersion(for table: String) async throws -> Int
}

// MARK: - Default Implementations

public extension DBLogServiceProtocol {
    /// Default database name
    var dbName: String {
        ChainLogDefaultDBName
    }
}

// MARK: - DBLog Core Helper

/// Helper class for shared DBLog processing logic
public final class DBLogCoreHelper<ChainEntry> {
    
    // MARK: - Properties
    
    private(set) var lastProcessedChainIndex: Int = -1
    private(set) var lastProcessedDBLogIndex: Int = -1
    
    private let getChainIndex: (ChainEntry) -> Int
    private let getContent: (ChainEntry) -> String
    
    // MARK: - Initialization
    
    public init(
        getChainIndex: @escaping (ChainEntry) -> Int,
        getContent: @escaping (ChainEntry) -> String
    ) {
        self.getChainIndex = getChainIndex
        self.getContent = getContent
    }
    
    // MARK: - State Management
    
    /// Set initial processed indices (after loading from database metadata)
    public func setInitialIndices(chainIndex: Int, dbLogIndex: Int) {
        lastProcessedChainIndex = chainIndex
        lastProcessedDBLogIndex = dbLogIndex
    }
    
    /// Reset state
    public func cleanup() {
        lastProcessedChainIndex = -1
        lastProcessedDBLogIndex = -1
    }
    
    // MARK: - Processing
    
    /// Parse chain entry content into DBLog actions
    public func parseContent(_ entry: ChainEntry) -> [DBLogAction]? {
        let content = getContent(entry)
        return try? DBLogParser.parse(content)
    }
    
    /// Process a single chain entry
    /// - Parameters:
    ///   - entry: The chain entry to process
    ///   - processActions: Closure to process the parsed actions
    /// - Returns: Set of affected table names
    public func processChainEntry(
        _ entry: ChainEntry,
        processActions: ([DBLogAction], Int) throws -> Void
    ) -> Set<String> {
        let chainIndex = getChainIndex(entry)
        
        // Parse the content as DBLog actions
        guard let actions = parseContent(entry), !actions.isEmpty else {
            // Entry might not be DBLog content, skip it
            lastProcessedChainIndex = chainIndex
            return Set()
        }
        
        // Extract affected tables
        let affectedTables = Set(actions.map { getTableFromAction($0) })
        
        // Process actions
        do {
            try processActions(actions, chainIndex)
        } catch {
            print("[DBLogCore] Error processing entry \(chainIndex): \(error)")
            return Set()
        }
        
        // Update local state
        lastProcessedChainIndex = chainIndex
        
        // Get max dblogindex
        let maxDBLogIndex = actions.reduce(-1) { max, action in
            let idx: Int
            switch action {
            case .schema(let a): idx = a.dblogindex
            case .set(let a): idx = a.dblogindex
            case .delete(let a): idx = a.dblogindex
            case .migrate(let a): idx = a.dblogindex
            }
            return Swift.max(max, idx)
        }
        lastProcessedDBLogIndex = maxDBLogIndex
        
        return affectedTables
    }
    
    /// Process pending chain log entries
    /// - Parameters:
    ///   - entries: All chain entries
    ///   - processActions: Closure to process the parsed actions
    /// - Returns: Set of all affected table names
    public func processPendingLogs(
        _ entries: [ChainEntry],
        processActions: ([DBLogAction], Int) throws -> Void
    ) -> Set<String> {
        let pending = entries.filter { getChainIndex($0) > lastProcessedChainIndex }
        
        guard !pending.isEmpty else {
            return Set()
        }
        
        var allAffectedTables = Set<String>()
        
        for entry in pending.sorted(by: { getChainIndex($0) < getChainIndex($1) }) {
            let tables = processChainEntry(entry, processActions: processActions)
            allAffectedTables.formUnion(tables)
        }
        
        return allAffectedTables
    }
    
    // MARK: - Helpers
    
    private func getTableFromAction(_ action: DBLogAction) -> String {
        switch action {
        case .schema(let a): return a.table
        case .set(let a): return a.table
        case .delete(let a): return a.table
        case .migrate(let a): return a.table
        }
    }
}
