//
//  ChainLogConfiguration.swift
//  ChainLogDb
//
//  Configuration for ChainLog services
//
//  Apps create a configuration and pass it to services, or use the global
//  ChainLogDb.configure() method to set up shared instances.
//
//  Note: Uses CredentialsProvider from API/APIConfiguration.swift
//

import Foundation

// MARK: - Configuration

/// Configuration for ChainLog services
public struct ChainLogServiceConfiguration: Sendable {
    
    /// Credentials provider for cryptographic operations
    /// Uses the CredentialsProvider protocol defined in APIConfiguration.swift
    public let credentials: any CredentialsProvider
    
    /// Network provider for personal chain log operations
    public let networkProvider: (any ChainLogNetworkProvider)?
    
    /// Network provider for group chain log operations
    public let groupNetworkProvider: (any GroupChainLogNetworkProvider)?
    
    /// Storage provider for MLS group state
    public let storageProvider: (any StorageProvider)?
    
    /// Base URL for API (optional, for reference)
    public let baseURL: String?
    
    /// Initialize configuration
    public init(
        credentials: any CredentialsProvider,
        networkProvider: (any ChainLogNetworkProvider)? = nil,
        groupNetworkProvider: (any GroupChainLogNetworkProvider)? = nil,
        storageProvider: (any StorageProvider)? = nil,
        baseURL: String? = nil
    ) {
        self.credentials = credentials
        self.networkProvider = networkProvider
        self.groupNetworkProvider = groupNetworkProvider
        self.storageProvider = storageProvider
        self.baseURL = baseURL
    }
}

// MARK: - Global Configuration

/// Global ChainLog service configuration and shared instances
public enum ChainLogServices {
    
    /// Thread-safe storage for configuration
    private static let configLock = NSLock()
    nonisolated(unsafe) private static var _configuration: ChainLogServiceConfiguration?
    
    /// Get the current configuration
    public static var configuration: ChainLogServiceConfiguration? {
        configLock.lock()
        defer { configLock.unlock() }
        return _configuration
    }
    
    /// Configure ChainLog services with the given configuration
    /// Call this at app startup before using any services
    public static func configure(_ config: ChainLogServiceConfiguration) {
        configLock.lock()
        defer { configLock.unlock() }
        _configuration = config
    }
    
    /// Check if services have been configured
    public static var isConfigured: Bool {
        configuration != nil
    }
    
    /// Reset configuration (useful for testing or logout)
    public static func reset() {
        configLock.lock()
        defer { configLock.unlock() }
        _configuration = nil
    }
    
    // MARK: - Convenience Accessors
    
    /// Get credentials from global configuration
    public static var credentials: (any CredentialsProvider)? {
        configuration?.credentials
    }
    
    /// Get network provider from global configuration
    public static var networkProvider: (any ChainLogNetworkProvider)? {
        configuration?.networkProvider
    }
    
    /// Get group network provider from global configuration
    public static var groupNetworkProvider: (any GroupChainLogNetworkProvider)? {
        configuration?.groupNetworkProvider
    }
    
    /// Get storage provider from global configuration
    public static var storageProvider: (any StorageProvider)? {
        configuration?.storageProvider
    }
}

// MARK: - Configuration Errors

public enum ChainLogConfigurationError: Error, LocalizedError {
    case notConfigured
    case missingCredentials
    case missingNetworkProvider
    case missingStorageProvider
    
    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "ChainLogDb has not been configured. Call ChainLogDb.configure() at app startup."
        case .missingCredentials:
            return "No credentials provider configured"
        case .missingNetworkProvider:
            return "No network provider configured"
        case .missingStorageProvider:
            return "No storage provider configured"
        }
    }
}
