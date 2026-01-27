//
//  DBLogProcessor.swift
//  ChainLogDb
//
//  Pure functions that process DBLog actions and generate SQL statements
//  Stateless and side-effect free - easily testable and portable to other platforms
//

import Foundation

// MARK: - DBLog Processor

/// Pure functions for converting DBLog actions to SQL statements
/// All methods are nonisolated to allow usage from any actor context
public enum DBLogProcessor {
    
    // MARK: - Main Entry Point
    
    /// Convert a DBLogAction to SQL statement(s)
    /// Returns an array since migrations may produce multiple statements
    nonisolated public static func sqlStatements(for action: DBLogAction) -> [String] {
        switch action {
        case .schema(let schemaAction):
            return [processSchema(schemaAction)]
        case .set(let setAction):
            return [processSet(setAction)]
        case .delete(let deleteAction):
            return [processDelete(deleteAction)]
        case .migrate(let migrateAction):
            return processMigrate(migrateAction)
        }
    }
    
    /// Process multiple actions and return all SQL statements in order
    nonisolated public static func sqlStatements(for actions: [DBLogAction]) -> [String] {
        actions.flatMap { sqlStatements(for: $0) }
    }
    
    // MARK: - Schema Processing
    
    /// Generate CREATE TABLE statement from SchemaAction
    /// Uses IF NOT EXISTS for idempotency
    nonisolated public static func processSchema(_ action: SchemaAction) -> String {
        let tableName = sanitizeIdentifier(action.table)
        
        // Sort columns for deterministic output (helpful for testing)
        // But ensure 'id' comes first if present
        let sortedColumns = action.columns.sorted { lhs, rhs in
            if lhs.key == "id" { return true }
            if rhs.key == "id" { return false }
            return lhs.key < rhs.key
        }
        
        let columnDefs = sortedColumns.map { column, type in
            "\(sanitizeIdentifier(column)) \(type)"
        }.joined(separator: ", ")
        
        return "CREATE TABLE IF NOT EXISTS \(tableName) (\(columnDefs))"
    }
    
    // MARK: - Set Processing
    
    /// Generate INSERT OR REPLACE statement from SetAction
    /// This provides upsert semantics - idempotent for replay
    nonisolated public static func processSet(_ action: SetAction) -> String {
        let tableName = sanitizeIdentifier(action.table)
        
        // Build column list (id + data keys)
        var columns = ["id"]
        var values = [action.id.sqlEscaped]
        
        // Sort data keys for deterministic output
        let sortedData = action.data.sorted { $0.key < $1.key }
        
        for (key, value) in sortedData {
            columns.append(sanitizeIdentifier(key))
            values.append(value.sqlLiteral)
        }
        
        let columnList = columns.joined(separator: ", ")
        let valueList = values.joined(separator: ", ")
        
        return "INSERT OR REPLACE INTO \(tableName) (\(columnList)) VALUES (\(valueList))"
    }
    
    // MARK: - Delete Processing
    
    /// Generate DELETE statement from DeleteAction
    nonisolated public static func processDelete(_ action: DeleteAction) -> String {
        let tableName = sanitizeIdentifier(action.table)
        return "DELETE FROM \(tableName) WHERE id = \(action.id.sqlEscaped)"
    }
    
    // MARK: - Migration Processing
    
    /// Generate ALTER TABLE statements from MigrateAction
    /// SQLite has limited ALTER TABLE support, so some operations require table recreation
    nonisolated public static func processMigrate(_ action: MigrateAction) -> [String] {
        var statements: [String] = []
        let tableName = sanitizeIdentifier(action.table)
        
        for operation in action.migration.operations {
            switch operation {
            case .addColumn(let column, let columnType):
                // SQLite supports ADD COLUMN directly
                let columnName = sanitizeIdentifier(column)
                statements.append("ALTER TABLE \(tableName) ADD COLUMN \(columnName) \(columnType)")
                
            case .dropColumn(let column):
                // SQLite 3.35.0+ supports DROP COLUMN
                let columnName = sanitizeIdentifier(column)
                statements.append("ALTER TABLE \(tableName) DROP COLUMN \(columnName)")
                
            case .renameColumn(let from, let to):
                // SQLite 3.25.0+ supports RENAME COLUMN
                let fromName = sanitizeIdentifier(from)
                let toName = sanitizeIdentifier(to)
                statements.append("ALTER TABLE \(tableName) RENAME COLUMN \(fromName) TO \(toName)")
                
            case .renameTable(let to):
                let newName = sanitizeIdentifier(to)
                statements.append("ALTER TABLE \(tableName) RENAME TO \(newName)")
            }
        }
        
        return statements
    }
    
    // MARK: - Utility Functions
    
    /// Sanitize an identifier (table or column name) for safe SQL use
    /// Wraps in double quotes and escapes any internal quotes
    nonisolated public static func sanitizeIdentifier(_ identifier: String) -> String {
        // Remove any existing quotes and escape internal double quotes
        let cleaned = identifier
            .replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(cleaned)\""
    }
    
    /// Validate that a table name is reasonable
    nonisolated public static func isValidTableName(_ name: String) -> Bool {
        // Must be non-empty, start with letter/underscore, contain only alphanumeric/underscore
        let pattern = "^[a-zA-Z_][a-zA-Z0-9_]*$"
        return name.range(of: pattern, options: .regularExpression) != nil
    }
    
    /// Validate that a column name is reasonable
    nonisolated public static func isValidColumnName(_ name: String) -> Bool {
        isValidTableName(name) // Same rules as table names
    }
    
    // MARK: - Query Building Helpers
    
    /// Generate SELECT * query for a table
    nonisolated public static func selectAll(from table: String) -> String {
        "SELECT * FROM \(sanitizeIdentifier(table))"
    }
    
    /// Generate SELECT * query with WHERE clause
    nonisolated public static func selectAll(from table: String, where condition: String) -> String {
        "SELECT * FROM \(sanitizeIdentifier(table)) WHERE \(condition)"
    }
    
    /// Generate SELECT * query for a single row by id
    nonisolated public static func selectById(from table: String, id: String) -> String {
        "SELECT * FROM \(sanitizeIdentifier(table)) WHERE id = \(id.sqlEscaped)"
    }
    
    /// Generate SELECT COUNT(*) query
    nonisolated public static func selectCount(from table: String) -> String {
        "SELECT COUNT(*) as count FROM \(sanitizeIdentifier(table))"
    }
    
    /// Generate SELECT COUNT(*) query with WHERE clause
    nonisolated public static func selectCount(from table: String, where condition: String) -> String {
        "SELECT COUNT(*) as count FROM \(sanitizeIdentifier(table)) WHERE \(condition)"
    }
    
    /// Generate query to check if table exists
    nonisolated public static func tableExistsQuery(_ table: String) -> String {
        let escaped = table.replacingOccurrences(of: "'", with: "''")
        return "SELECT name FROM sqlite_master WHERE type='table' AND name='\(escaped)'"
    }
    
    /// Generate query to get table schema (columns)
    nonisolated public static func tableSchemaQuery(_ table: String) -> String {
        "PRAGMA table_info(\(sanitizeIdentifier(table)))"
    }
    
    // MARK: - Metadata Table Helpers
    
    /// SQL to create the internal metadata table for tracking processed logs
    nonisolated public static var createMetadataTableSQL: String {
        """
        CREATE TABLE IF NOT EXISTS "_dblog_meta" (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    }
    
    /// SQL to create the schema versions table for tracking migrations
    nonisolated public static var createSchemaVersionsTableSQL: String {
        """
        CREATE TABLE IF NOT EXISTS "_dblog_schema_versions" (
            table_name TEXT PRIMARY KEY,
            version INTEGER NOT NULL DEFAULT 0
        )
        """
    }
    
    /// Generate SQL to update last processed chain index
    nonisolated public static func updateLastChainIndex(_ index: Int) -> String {
        "INSERT OR REPLACE INTO \"_dblog_meta\" (key, value) VALUES ('last_chain_index', '\(index)')"
    }
    
    /// Generate SQL to update last processed dblog index
    nonisolated public static func updateLastDBLogIndex(_ index: Int) -> String {
        "INSERT OR REPLACE INTO \"_dblog_meta\" (key, value) VALUES ('last_dblog_index', '\(index)')"
    }
    
    /// Generate SQL to get schema version for a table
    nonisolated public static func getSchemaVersion(for table: String) -> String {
        "SELECT version FROM \"_dblog_schema_versions\" WHERE table_name = \(table.sqlEscaped)"
    }
    
    /// Generate SQL to update schema version for a table
    nonisolated public static func updateSchemaVersion(for table: String, version: Int) -> String {
        "INSERT OR REPLACE INTO \"_dblog_schema_versions\" (table_name, version) VALUES (\(table.sqlEscaped), \(version))"
    }
    
    // MARK: - Prepared Statement Support
    
    /// Generate a prepared statement with parameter placeholders
    /// Safer than string interpolation for user data
    nonisolated public static func preparedStatement(for action: DBLogAction) -> DBLogPreparedStatement {
        switch action {
        case .schema(let schemaAction):
            // Schema statements don't have user data, so no parameters
            return DBLogPreparedStatement(sql: processSchema(schemaAction))
            
        case .set(let setAction):
            return preparedSet(setAction)
            
        case .delete(let deleteAction):
            return preparedDelete(deleteAction)
            
        case .migrate(let migrateAction):
            // Migrations don't have user data parameters
            let statements = processMigrate(migrateAction)
            // Return first statement; caller should use sqlStatements for migrations
            return DBLogPreparedStatement(sql: statements.first ?? "")
        }
    }
    
    /// Generate prepared INSERT OR REPLACE statement
    nonisolated private static func preparedSet(_ action: SetAction) -> DBLogPreparedStatement {
        let tableName = sanitizeIdentifier(action.table)
        
        var columns = ["id"]
        var placeholders = ["?"]
        var parameters: [DBLogValue] = [.string(action.id)]
        
        let sortedData = action.data.sorted { $0.key < $1.key }
        
        for (key, value) in sortedData {
            columns.append(sanitizeIdentifier(key))
            placeholders.append("?")
            parameters.append(value)
        }
        
        let columnList = columns.joined(separator: ", ")
        let placeholderList = placeholders.joined(separator: ", ")
        
        let sql = "INSERT OR REPLACE INTO \(tableName) (\(columnList)) VALUES (\(placeholderList))"
        return DBLogPreparedStatement(sql: sql, parameters: parameters)
    }
    
    /// Generate prepared DELETE statement
    nonisolated private static func preparedDelete(_ action: DeleteAction) -> DBLogPreparedStatement {
        let tableName = sanitizeIdentifier(action.table)
        let sql = "DELETE FROM \(tableName) WHERE id = ?"
        return DBLogPreparedStatement(sql: sql, parameters: [.string(action.id)])
    }
}

// MARK: - String SQL Escaping Extension

extension String {
    /// Escape a string value for SQL (wraps in single quotes, escapes internal quotes)
    nonisolated var sqlEscaped: String {
        let escaped = self.replacingOccurrences(of: "'", with: "''")
        return "'\(escaped)'"
    }
}

// MARK: - Prepared Statement Support

/// For parameterized queries (safer than string interpolation)
public struct DBLogPreparedStatement: Sendable, Equatable {
    public let sql: String
    public let parameters: [DBLogValue]
    
    nonisolated public init(sql: String, parameters: [DBLogValue] = []) {
        self.sql = sql
        self.parameters = parameters
    }
}
