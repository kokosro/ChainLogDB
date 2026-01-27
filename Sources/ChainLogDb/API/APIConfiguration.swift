//
//  APIConfiguration.swift
//  ChainLogDb
//
//  Configurable API settings for whitelabel support
//

import Foundation

// MARK: - API Configuration

/// Configuration for API endpoints
/// Allows whitelabel apps to specify their own server URLs
public struct APIConfiguration: Sendable {
    /// Base URL for REST API (e.g., "https://api.example.com")
    public let baseURL: String
    
    /// Base URL for WebSocket connections
    public let wsURL: String
    
    /// Request timeout interval
    public let requestTimeout: TimeInterval
    
    /// Resource timeout interval
    public let resourceTimeout: TimeInterval
    
    /// Initialize with base URL and optional WebSocket URL
    /// - Parameters:
    ///   - baseURL: Base URL for REST API
    ///   - wsURL: Optional WebSocket URL. If not provided, derived from baseURL
    ///   - requestTimeout: Request timeout (default 30s)
    ///   - resourceTimeout: Resource timeout (default 60s)
    public init(
        baseURL: String,
        wsURL: String? = nil,
        requestTimeout: TimeInterval = 30,
        resourceTimeout: TimeInterval = 60
    ) {
        self.baseURL = baseURL
        self.wsURL = wsURL ?? Self.deriveWebSocketURL(from: baseURL)
        self.requestTimeout = requestTimeout
        self.resourceTimeout = resourceTimeout
    }
    
    /// Derive WebSocket URL from HTTP URL
    private static func deriveWebSocketURL(from httpURL: String) -> String {
        httpURL
            .replacingOccurrences(of: "https://", with: "wss://")
            .replacingOccurrences(of: "http://", with: "ws://")
    }
}

// MARK: - API Errors

/// API client errors
public enum APIError: Error, LocalizedError {
    case noCredentials
    case invalidResponse
    case httpError(Int, String)
    case encodingError
    case decodingError(String)
    case notFound(String)
    case notConfigured
    
    public var errorDescription: String? {
        switch self {
        case .noCredentials: return "No credentials set"
        case .invalidResponse: return "Invalid server response"
        case .httpError(let code, let msg): return "HTTP \(code): \(msg)"
        case .encodingError: return "Failed to encode request"
        case .decodingError(let msg): return "Failed to decode response: \(msg)"
        case .notFound(let item): return "\(item) not found"
        case .notConfigured: return "API client not configured"
        }
    }
}

// MARK: - Credentials Protocol

/// Protocol for providing authentication credentials
/// Implement this to integrate with your app's key management
public protocol CredentialsProvider: Sendable {
    /// Get the public key (hex string with 0x prefix)
    var publicKey: String? { get }
    
    /// Get the private key (hex string with 0x prefix)
    var privateKey: String? { get }
    
    /// Check if credentials are available
    var hasCredentials: Bool { get }
}

// MARK: - Auth Token Provider Protocol

/// Protocol for creating authentication tokens
/// Implement this to integrate with your app's signing mechanism
public protocol AuthTokenProvider: Sendable {
    /// Create an authentication token for API requests
    /// - Returns: Token string for Authorization header
    func createAuthToken() async throws -> String
}
