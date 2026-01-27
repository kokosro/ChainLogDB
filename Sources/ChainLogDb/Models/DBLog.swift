//
//  DBLog.swift
//  ChainLogDb
//
//  Log-driven database models for the programmable event store
//  Each ChainLog entry contains encrypted JSON with DBLog actions
//

import Foundation

// MARK: - DBLog Entry

/// A single DBLog entry containing one or more actions within a ChainLog entry
public struct DBLogEntry: Codable, Sendable {
    public let v: Int                    // Version for format evolution
    public let dblogindex: Int           // Index within the ChainLog entry
    public let action: String            // Action type discriminator
    
    // Action-specific fields (decoded separately based on action type)
    private enum CodingKeys: String, CodingKey {
        case v, dblogindex, action
    }
}

// MARK: - DBLog Action Types

/// Discriminated union of all DBLog actions
public enum DBLogAction: Codable, Sendable, Equatable {
    case schema(SchemaAction)
    case set(SetAction)
    case delete(DeleteAction)
    case migrate(MigrateAction)
    
    private enum CodingKeys: String, CodingKey {
        case action
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let action = try container.decode(String.self, forKey: .action)
        
        switch action {
        case "schema":
            let schemaAction = try SchemaAction(from: decoder)
            self = .schema(schemaAction)
        case "set":
            let setAction = try SetAction(from: decoder)
            self = .set(setAction)
        case "delete":
            let deleteAction = try DeleteAction(from: decoder)
            self = .delete(deleteAction)
        case "migrate":
            let migrateAction = try MigrateAction(from: decoder)
            self = .migrate(migrateAction)
        default:
            throw DecodingError.dataCorruptedError(forKey: .action, in: container, debugDescription: "Unknown action type: \(action)")
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .schema(let schemaAction):
            try container.encode("schema", forKey: .action)
            try schemaAction.encode(to: encoder)
        case .set(let setAction):
            try container.encode("set", forKey: .action)
            try setAction.encode(to: encoder)
        case .delete(let deleteAction):
            try container.encode("delete", forKey: .action)
            try deleteAction.encode(to: encoder)
        case .migrate(let migrateAction):
            try container.encode("migrate", forKey: .action)
            try migrateAction.encode(to: encoder)
        }
    }
}

// MARK: - Schema Action

/// Creates a new table with specified columns
public struct SchemaAction: Codable, Sendable, Equatable {
    public let v: Int
    public let dblogindex: Int
    public let table: String
    public let columns: [String: String]  // column name -> SQL type (e.g., "TEXT PRIMARY KEY")
    
    public init(v: Int = 1, dblogindex: Int, table: String, columns: [String: String]) {
        self.v = v
        self.dblogindex = dblogindex
        self.table = table
        self.columns = columns
    }
}

// MARK: - Set Action

/// Inserts or updates a row in a table (upsert)
public struct SetAction: Codable, Sendable, Equatable {
    public let v: Int
    public let dblogindex: Int
    public let table: String
    public let id: String
    public let data: [String: DBLogValue]  // Row data excluding id
    
    public init(v: Int = 1, dblogindex: Int, table: String, id: String, data: [String: DBLogValue]) {
        self.v = v
        self.dblogindex = dblogindex
        self.table = table
        self.id = id
        self.data = data
    }
}

// MARK: - Delete Action

/// Removes a row from a table by id
public struct DeleteAction: Codable, Sendable, Equatable {
    public let v: Int
    public let dblogindex: Int
    public let table: String
    public let id: String
    
    public init(v: Int = 1, dblogindex: Int, table: String, id: String) {
        self.v = v
        self.dblogindex = dblogindex
        self.table = table
        self.id = id
    }
}

// MARK: - Migrate Action

/// Alters table schema with versioned operations
public struct MigrateAction: Codable, Sendable, Equatable {
    public let v: Int
    public let dblogindex: Int
    public let table: String
    public let migration: Migration
    
    public init(v: Int = 1, dblogindex: Int, table: String, migration: Migration) {
        self.v = v
        self.dblogindex = dblogindex
        self.table = table
        self.migration = migration
    }
}

/// Migration definition with version and operations
public struct Migration: Codable, Sendable, Equatable {
    public let version: Int
    public let operations: [MigrationOp]
    
    public init(version: Int, operations: [MigrationOp]) {
        self.version = version
        self.operations = operations
    }
}

/// Individual migration operations
public enum MigrationOp: Codable, Sendable, Equatable {
    case addColumn(column: String, columnType: String)
    case dropColumn(column: String)
    case renameColumn(from: String, to: String)
    case renameTable(to: String)
    
    private enum CodingKeys: String, CodingKey {
        case op, column, columnType, from, to
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let op = try container.decode(String.self, forKey: .op)
        
        switch op {
        case "add_column":
            let column = try container.decode(String.self, forKey: .column)
            let columnType = try container.decode(String.self, forKey: .columnType)
            self = .addColumn(column: column, columnType: columnType)
        case "drop_column":
            let column = try container.decode(String.self, forKey: .column)
            self = .dropColumn(column: column)
        case "rename_column":
            let from = try container.decode(String.self, forKey: .from)
            let to = try container.decode(String.self, forKey: .to)
            self = .renameColumn(from: from, to: to)
        case "rename_table":
            let to = try container.decode(String.self, forKey: .to)
            self = .renameTable(to: to)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .op,
                in: container,
                debugDescription: "Unknown migration operation: \(op)"
            )
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .addColumn(let column, let columnType):
            try container.encode("add_column", forKey: .op)
            try container.encode(column, forKey: .column)
            try container.encode(columnType, forKey: .columnType)
        case .dropColumn(let column):
            try container.encode("drop_column", forKey: .op)
            try container.encode(column, forKey: .column)
        case .renameColumn(let from, let to):
            try container.encode("rename_column", forKey: .op)
            try container.encode(from, forKey: .from)
            try container.encode(to, forKey: .to)
        case .renameTable(let to):
            try container.encode("rename_table", forKey: .op)
            try container.encode(to, forKey: .to)
        }
    }
}

// MARK: - DBLog Value (Type-safe JSON values)

/// Type-safe wrapper for JSON values in DBLog data
public enum DBLogValue: Sendable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([DBLogValue])
    case object([String: DBLogValue])
}

extension DBLogValue: Equatable {
    nonisolated public static func == (lhs: DBLogValue, rhs: DBLogValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null):
            return true
        case (.bool(let a), .bool(let b)):
            return a == b
        case (.int(let a), .int(let b)):
            return a == b
        case (.double(let a), .double(let b)):
            return a == b
        case (.string(let a), .string(let b)):
            return a == b
        case (.array(let a), .array(let b)):
            return a == b
        case (.object(let a), .object(let b)):
            return a == b
        default:
            return false
        }
    }
}

extension DBLogValue: Codable {
    nonisolated public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if container.decodeNil() {
            self = .null
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let int = try? container.decode(Int.self) {
            self = .int(int)
        } else if let double = try? container.decode(Double.self) {
            self = .double(double)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let array = try? container.decode([DBLogValue].self) {
            self = .array(array)
        } else if let object = try? container.decode([String: DBLogValue].self) {
            self = .object(object)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unable to decode DBLogValue"
            )
        }
    }
    
    nonisolated public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let value):
            try container.encode(value)
        case .int(let value):
            try container.encode(value)
        case .double(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

extension DBLogValue {
    /// Convert to SQL-compatible value for binding
    nonisolated public var sqlValue: Any? {
        switch self {
        case .null:
            return nil
        case .bool(let value):
            return value ? 1 : 0
        case .int(let value):
            return value
        case .double(let value):
            return value
        case .string(let value):
            return value
        case .array(let value):
            // Store arrays as JSON strings
            let encoder = JSONEncoder()
            if let data = try? encoder.encode(value),
               let json = String(data: data, encoding: .utf8) {
                return json
            }
            return nil
        case .object(let value):
            // Store objects as JSON strings
            let encoder = JSONEncoder()
            if let data = try? encoder.encode(value),
               let json = String(data: data, encoding: .utf8) {
                return json
            }
            return nil
        }
    }
    
    /// Convert to SQL literal string for queries
    nonisolated public var sqlLiteral: String {
        switch self {
        case .null:
            return "NULL"
        case .bool(let value):
            return value ? "1" : "0"
        case .int(let value):
            return String(value)
        case .double(let value):
            return String(value)
        case .string(let value):
            // Escape single quotes for SQL
            let escaped = value.replacingOccurrences(of: "'", with: "''")
            return "'\(escaped)'"
        case .array, .object:
            let encoder = JSONEncoder()
            if let data = try? encoder.encode(self),
               let json = String(data: data, encoding: .utf8) {
                let escaped = json.replacingOccurrences(of: "'", with: "''")
                return "'\(escaped)'"
            }
            return "NULL"
        }
    }
}

// MARK: - DBLog Action Parsing

/// Parser for converting raw JSON into typed DBLogAction
public enum DBLogParser {
    
    /// Parse a JSON string containing an array of DBLog actions
    public static func parse(_ json: String) throws -> [DBLogAction] {
        guard let data = json.data(using: .utf8) else {
            throw DBLogError.invalidJSON("Unable to convert string to data")
        }
        return try parse(data)
    }
    
    /// Parse JSON data containing an array of DBLog actions
    public static func parse(_ data: Data) throws -> [DBLogAction] {
        let decoder = JSONDecoder()
        
        // First, decode as array of raw JSON objects to inspect action type
        let jsonArray: [[String: Any]]
        do {
            guard let array = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                throw DBLogError.invalidJSON("Expected array of objects")
            }
            jsonArray = array
        } catch let error as DBLogError {
            throw error
        } catch {
            throw DBLogError.invalidJSON(error.localizedDescription)
        }
        
        var actions: [DBLogAction] = []
        
        for (index, jsonObject) in jsonArray.enumerated() {
            guard let action = jsonObject["action"] as? String else {
                throw DBLogError.missingField("action", index: index)
            }
            
            // Re-encode individual object for type-specific decoding
            let objectData = try JSONSerialization.data(withJSONObject: jsonObject)
            
            switch action {
            case "schema":
                let schemaAction = try decoder.decode(SchemaAction.self, from: objectData)
                actions.append(.schema(schemaAction))
            case "set":
                let setAction = try decoder.decode(SetAction.self, from: objectData)
                actions.append(.set(setAction))
            case "delete":
                let deleteAction = try decoder.decode(DeleteAction.self, from: objectData)
                actions.append(.delete(deleteAction))
            case "migrate":
                let migrateAction = try decoder.decode(MigrateAction.self, from: objectData)
                actions.append(.migrate(migrateAction))
            default:
                throw DBLogError.unknownAction(action, index: index)
            }
        }
        
        return actions
    }
    
    /// Serialize DBLog actions to JSON string
    public static func serialize(_ actions: [DBLogAction]) throws -> String {
        var jsonArray: [[String: Any]] = []
        let encoder = JSONEncoder()
        encoder.outputFormatting = [] // Compact output
        
        for action in actions {
            let data: Data
            var dict: [String: Any]
            
            switch action {
            case .schema(let schemaAction):
                data = try encoder.encode(schemaAction)
                dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
                dict["action"] = "schema"
            case .set(let setAction):
                data = try encoder.encode(setAction)
                dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
                dict["action"] = "set"
            case .delete(let deleteAction):
                data = try encoder.encode(deleteAction)
                dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
                dict["action"] = "delete"
            case .migrate(let migrateAction):
                data = try encoder.encode(migrateAction)
                dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
                dict["action"] = "migrate"
            }
            
            jsonArray.append(dict)
        }
        
        let outputData = try JSONSerialization.data(withJSONObject: jsonArray)
        guard let json = String(data: outputData, encoding: .utf8) else {
            throw DBLogError.serializationFailed
        }
        
        return json
    }
}

// MARK: - DBLog Errors

public enum DBLogError: Error, LocalizedError {
    case invalidJSON(String)
    case missingField(String, index: Int)
    case unknownAction(String, index: Int)
    case serializationFailed
    case tableNotFound(String)
    case columnNotFound(String, table: String)
    case invalidMigration(String)
    case sqlExecutionFailed(String)
    case snapshotFailed(String)
    case notInitialized
    
    public var errorDescription: String? {
        switch self {
        case .invalidJSON(let reason):
            return "Invalid JSON: \(reason)"
        case .missingField(let field, let index):
            return "Missing required field '\(field)' at index \(index)"
        case .unknownAction(let action, let index):
            return "Unknown action '\(action)' at index \(index)"
        case .serializationFailed:
            return "Failed to serialize DBLog actions"
        case .tableNotFound(let table):
            return "Table '\(table)' not found"
        case .columnNotFound(let column, let table):
            return "Column '\(column)' not found in table '\(table)'"
        case .invalidMigration(let reason):
            return "Invalid migration: \(reason)"
        case .sqlExecutionFailed(let reason):
            return "SQL execution failed: \(reason)"
        case .snapshotFailed(let reason):
            return "Snapshot operation failed: \(reason)"
        case .notInitialized:
            return "Service not initialized"
        }
    }
}
