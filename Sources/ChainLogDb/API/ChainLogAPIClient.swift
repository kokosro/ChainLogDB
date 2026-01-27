//
//  ChainLogAPIClient.swift
//  ChainLogDb
//
//  Minimal API client focused on chain log operations
//  Configurable for whitelabel support
//

import Foundation
import ChainKeys

// MARK: - Chain Log API Client

/// API client for chain log operations
/// Configurable with custom base URL for whitelabel support
public final class ChainLogAPIClient: @unchecked Sendable {
    
    // MARK: - Properties
    
    private let configuration: APIConfiguration
    private let authTokenProvider: AuthTokenProvider
    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    
    // MARK: - Initialization
    
    /// Initialize with configuration and auth token provider
    /// - Parameters:
    ///   - configuration: API configuration with URLs
    ///   - authTokenProvider: Provider for creating auth tokens
    public init(configuration: APIConfiguration, authTokenProvider: AuthTokenProvider) {
        self.configuration = configuration
        self.authTokenProvider = authTokenProvider
        
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = configuration.requestTimeout
        config.timeoutIntervalForResource = configuration.resourceTimeout
        self.session = URLSession(configuration: config)
        
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }
    
    // MARK: - HTTP Helpers
    
    /// Execute an authenticated request
    private func authRequest(_ endpoint: String, method: String = "GET", body: Data? = nil) async throws -> Data {
        guard let url = URL(string: "\(configuration.baseURL)\(endpoint)") else {
            throw APIError.invalidResponse
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        let token = try await authTokenProvider.createAuthToken()
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        if let body = body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            let message = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw APIError.httpError(httpResponse.statusCode, message)
        }
        
        return data
    }
    
    // MARK: - Personal Chain Logs
    
    /// List chain log entries starting from a specific index
    public func listChainLogs(startIndex: Int = 0, limit: Int = 100, dbName: String = "default") async throws -> (logs: [EncryptedChainLogEntry], hasMore: Bool) {
        let data = try await authRequest("/self/logs/\(dbName)?startIndex=\(startIndex)&limit=\(limit)")
        let response = try decoder.decode(ChainLogsResponse.self, from: data)
        return (response.logs, response.hasMore)
    }
    
    /// Get the current head (latest entry) of the chain
    public func getChainLogHead(dbName: String = "default") async throws -> EncryptedChainLogEntry? {
        let data = try await authRequest("/self/logs/\(dbName)/head")
        let response = try decoder.decode(ChainLogHeadResponse.self, from: data)
        return response.head
    }
    
    /// Get a specific chain log entry by index
    public func getChainLog(index: Int, dbName: String = "default") async throws -> EncryptedChainLogEntry {
        let data = try await authRequest("/self/logs/\(dbName)/\(index)")
        return try decoder.decode(EncryptedChainLogEntry.self, from: data)
    }
    
    /// Append a new entry to the chain log
    public func appendChainLog(_ request: AppendChainLogRequest, dbName: String = "default") async throws -> EncryptedChainLogEntry {
        let body = try encoder.encode(request)
        let data = try await authRequest("/self/logs/\(dbName)", method: "POST", body: body)
        return try decoder.decode(EncryptedChainLogEntry.self, from: data)
    }
    
    // MARK: - Group Management
    
    /// Create a new group with BBS+ public key and initial access key
    public func createGroup(
        groupId: String,
        groupPublicKey: String,
        initialAccessKey: String
    ) async throws -> GroupInfo {
        let request = CreateGroupRequest(
            groupId: groupId,
            groupPublicKey: groupPublicKey,
            initialAccessKey: initialAccessKey
        )
        
        let body = try encoder.encode(request)
        let data = try await authRequest("/groups", method: "POST", body: body)
        return try decoder.decode(GroupInfo.self, from: data)
    }
    
    /// Get group info
    public func getGroup(groupId: String) async throws -> GroupInfo {
        let data = try await authRequest("/groups/\(groupId)")
        return try decoder.decode(GroupInfo.self, from: data)
    }
    
    // MARK: - Group Chain Logs
    
    /// List group chain log entries starting from a specific index
    public func listGroupLogs(
        groupId: String,
        startIndex: Int = 0,
        limit: Int = 100,
        dbName: String = "default"
    ) async throws -> (logs: [ServerGroupLogEntry], hasMore: Bool) {
        let data = try await authRequest("/groups/\(groupId)/logs/\(dbName)?startIndex=\(startIndex)&limit=\(limit)")
        let response = try decoder.decode(GroupChainLogsResponse.self, from: data)
        return (response.logs, response.hasMore)
    }
    
    /// Get the current head (latest entry) of the group chain
    public func getGroupLogHead(
        groupId: String,
        dbName: String = "default"
    ) async throws -> ServerGroupLogEntry? {
        let data = try await authRequest("/groups/\(groupId)/logs/\(dbName)/head")
        let response = try decoder.decode(GroupChainLogHeadResponse.self, from: data)
        return response.head
    }
    
    /// Get a specific group chain log entry by index
    public func getGroupLog(
        groupId: String,
        index: Int,
        dbName: String = "default"
    ) async throws -> ServerGroupLogEntry {
        let data = try await authRequest("/groups/\(groupId)/logs/\(dbName)/\(index)")
        return try decoder.decode(ServerGroupLogEntry.self, from: data)
    }
    
    /// Append a new entry to the group chain log (privacy-preserving)
    public func appendGroupLog(
        groupId: String,
        request: AppendGroupChainLogRequest,
        dbName: String = "default"
    ) async throws -> ServerGroupLogEntry {
        let body = try encoder.encode(request)
        let data = try await authRequest("/groups/\(groupId)/logs/\(dbName)", method: "POST", body: body)
        return try decoder.decode(ServerGroupLogEntry.self, from: data)
    }
    
    // MARK: - Packages
    
    /// List packages with optional filters
    /// - Parameters:
    ///   - lastId: Pagination cursor (last package id from previous page)
    ///   - limit: Maximum number of packages to return
    ///   - contact: Filter by counterparty address
    ///   - direction: Filter by direction (sent/received)
    ///   - since: Only packages created after this date
    /// - Returns: Tuple of encrypted package metadata and hasMore flag
    public func listPackages(
        lastId: String? = nil,
        limit: Int = 50,
        contact: String? = nil,
        direction: PackageDirection? = nil,
        since: Date? = nil
    ) async throws -> (packages: [EncryptedPackageMeta], hasMore: Bool) {
        var params: [String] = []
        if let lastId = lastId { params.append("lastId=\(lastId)") }
        params.append("limit=\(limit)")
        if let contact = contact { params.append("contact=\(contact)") }
        if let direction = direction { params.append("direction=\(direction.rawValue)") }
        if let since = since {
            let timestamp = Int(since.timeIntervalSince1970 * 1000)
            params.append("since=\(timestamp)")
        }
        
        let query = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        let data = try await authRequest("/self/packages\(query)")
        let response = try decoder.decode(PackageListResponse.self, from: data)
        
        return (response.packages, response.hasMore)
    }
    
    /// Get a specific package by ID
    public func getPackage(_ id: String) async throws -> EncryptedPackage {
        let data = try await authRequest("/self/packages/\(id)")
        return try decoder.decode(EncryptedPackage.self, from: data)
    }
    
    /// Send a package (encrypted message)
    /// Note: Encryption should be done by the app before calling this
    public func sendPackage(_ request: SendPackageRequest) async throws -> SendPackageResponse {
        let body = try encoder.encode(request)
        let data = try await authRequest("/self/packages", method: "POST", body: body)
        return try decoder.decode(SendPackageResponse.self, from: data)
    }
    
    /// Mark a package as read
    public func markPackageRead(_ id: String) async throws {
        let _ = try await authRequest("/self/packages/\(id)/read", method: "PATCH")
    }
    
    /// Delete a package
    public func deletePackage(_ id: String) async throws {
        let _ = try await authRequest("/self/packages/\(id)", method: "DELETE")
    }
}
