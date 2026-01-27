//
//  Package.swift
//  ChainLogDb
//
//  Package model types for encrypted messaging API
//  These are the server-side/wire types - decryption is handled by the app
//

import Foundation

// MARK: - Direction

public enum PackageDirection: String, Codable, Sendable {
    case sent
    case received
}

// MARK: - Encrypted Package Types (Server/Wire Format)

/// Encrypted package with full content from server
public struct EncryptedPackage: Codable, Sendable {
    public let id: String
    public let pairId: String
    public let counterpartyAddress: String
    public let direction: String
    public let packageType: String  // encrypted
    public let content: String      // encrypted
    public let createdAt: Int
    public let readAt: Int?
    
    public init(
        id: String,
        pairId: String,
        counterpartyAddress: String,
        direction: String,
        packageType: String,
        content: String,
        createdAt: Int,
        readAt: Int?
    ) {
        self.id = id
        self.pairId = pairId
        self.counterpartyAddress = counterpartyAddress
        self.direction = direction
        self.packageType = packageType
        self.content = content
        self.createdAt = createdAt
        self.readAt = readAt
    }
}

/// Encrypted package metadata (without content) from server
public struct EncryptedPackageMeta: Codable, Sendable {
    public let id: String
    public let pairId: String
    public let counterpartyAddress: String
    public let direction: String
    public let packageType: String  // encrypted
    public let createdAt: Int
    public let readAt: Int?
    
    public init(
        id: String,
        pairId: String,
        counterpartyAddress: String,
        direction: String,
        packageType: String,
        createdAt: Int,
        readAt: Int?
    ) {
        self.id = id
        self.pairId = pairId
        self.counterpartyAddress = counterpartyAddress
        self.direction = direction
        self.packageType = packageType
        self.createdAt = createdAt
        self.readAt = readAt
    }
}

// MARK: - API Response Types

/// Response for GET /self/packages
public struct PackageListResponse: Codable, Sendable {
    public let packages: [EncryptedPackageMeta]
    public let hasMore: Bool
    
    public init(packages: [EncryptedPackageMeta], hasMore: Bool) {
        self.packages = packages
        self.hasMore = hasMore
    }
}

/// Response for POST /self/packages
public struct SendPackageResponse: Codable, Sendable {
    public let senderPackage: EncryptedPackage
    public let recipientPackageId: String
    
    public init(senderPackage: EncryptedPackage, recipientPackageId: String) {
        self.senderPackage = senderPackage
        self.recipientPackageId = recipientPackageId
    }
}

// MARK: - Request Types

/// Request body for POST /self/packages
public struct SendPackageRequest: Codable, Sendable {
    public let recipientAddress: String
    public let senderPackageType: String     // encrypted for sender
    public let senderContent: String         // encrypted for sender
    public let recipientPackageType: String  // encrypted for recipient
    public let recipientContent: String      // encrypted for recipient
    public let senderDeviceToken: String?    // Optional: exclude from WS notification
    
    public init(
        recipientAddress: String,
        senderPackageType: String,
        senderContent: String,
        recipientPackageType: String,
        recipientContent: String,
        senderDeviceToken: String? = nil
    ) {
        self.recipientAddress = recipientAddress
        self.senderPackageType = senderPackageType
        self.senderContent = senderContent
        self.recipientPackageType = recipientPackageType
        self.recipientContent = recipientContent
        self.senderDeviceToken = senderDeviceToken
    }
}
