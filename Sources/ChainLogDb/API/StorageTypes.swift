//
//  StorageTypes.swift
//  ChainLogDb
//
//  Types for encrypted KV Store and List Store API endpoints
//

import Foundation

// MARK: - KV Store Types (Encrypted)

/// Encrypted KV item metadata from server
public struct EncryptedKvItemMeta: Codable, Sendable {
    public let id: String
    public let name: String      // encrypted
    public let createdAt: Int
    public let updatedAt: Int
    
    public init(id: String, name: String, createdAt: Int, updatedAt: Int) {
        self.id = id
        self.name = name
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// Full encrypted KV item from server
public struct EncryptedKvItem: Codable, Sendable {
    public let id: String
    public let name: String      // encrypted
    public let value: String     // encrypted
    public let createdAt: Int
    public let updatedAt: Int
    
    public init(id: String, name: String, value: String, createdAt: Int, updatedAt: Int) {
        self.id = id
        self.name = name
        self.value = value
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// Response for listing KV items
public struct KvListResponse: Codable, Sendable {
    public let items: [EncryptedKvItemMeta]
    
    public init(items: [EncryptedKvItemMeta]) {
        self.items = items
    }
}

// MARK: - List Store Types (Encrypted)

/// Encrypted list metadata from server
public struct EncryptedListMeta: Codable, Sendable {
    public let id: String
    public let name: String      // encrypted
    public let createdAt: Int
    
    public init(id: String, name: String, createdAt: Int) {
        self.id = id
        self.name = name
        self.createdAt = createdAt
    }
}

/// Encrypted list item from server
public struct EncryptedListItem: Codable, Sendable {
    public let id: String
    public let value: String     // encrypted
    public let createdAt: Int
    
    public init(id: String, value: String, createdAt: Int) {
        self.id = id
        self.value = value
        self.createdAt = createdAt
    }
}

/// Response for listing all lists
public struct ListsResponse: Codable, Sendable {
    public let lists: [EncryptedListMeta]
    
    public init(lists: [EncryptedListMeta]) {
        self.lists = lists
    }
}

/// Response for listing items in a list
public struct ListItemsResponse: Codable, Sendable {
    public let items: [EncryptedListItem]
    public let page: Int
    public let pageSize: Int
    
    public init(items: [EncryptedListItem], page: Int, pageSize: Int) {
        self.items = items
        self.page = page
        self.pageSize = pageSize
    }
}
