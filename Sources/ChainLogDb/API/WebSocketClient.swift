//
//  WebSocketClient.swift
//  ChainLogDb
//
//  WebSocket client for real-time chain log updates
//  Configurable for whitelabel support
//

import Foundation
import Combine

// MARK: - WebSocket Event Types

public enum WebSocketEventType: String, Codable, Sendable {
    case newPackage = "new_package"
    case newLog = "new_log"
    case logStreamEnd = "log_stream_end"
    case connected = "connected"
    case newGroupLog = "new_group_log"
    case groupLogStreamEnd = "group_log_stream_end"
}

// MARK: - WebSocket Data Types

public struct WebSocketNewLogData: Codable, Sendable {
    public let index: Int
    public let prevHash: String
    public let content: String      // encrypted
    public let nonce: String
    public let hash: String
    public let signature: String
    public let createdAt: Int
}

public struct WebSocketLogStreamEndData: Codable, Sendable {
    public let lastIndex: Int
}

public struct WebSocketConnectedData: Codable, Sendable {
    public let address: String
}

/// WebSocket new group log data (privacy-preserving format)
public struct WebSocketNewGroupLogData: Codable, Sendable {
    public let index: Int
    public let prevHash: String
    public let ciphertext: String
    public let nonce: String
    public let hash: String
    public let groupSignature: String
    public let accessProof: String
    public let createdAt: Int
    public let groupId: String
}

public struct WebSocketGroupLogStreamEndData: Codable, Sendable {
    public let groupId: String
    public let lastIndex: Int?
}

public struct WebSocketMessage<T: Codable>: Codable {
    public let event: String
    public let data: T
}

// MARK: - WebSocket Client Delegate

/// Delegate protocol for handling WebSocket events
/// Implement this to receive real-time updates
public protocol WebSocketClientDelegate: AnyObject, Sendable {
    /// Called when a new personal log entry is received
    func webSocketClient(_ client: WebSocketClient, didReceiveLog data: WebSocketNewLogData)
    
    /// Called when log streaming ends
    func webSocketClient(_ client: WebSocketClient, didReceiveLogStreamEnd data: WebSocketLogStreamEndData)
    
    /// Called when connected to WebSocket
    func webSocketClient(_ client: WebSocketClient, didConnect data: WebSocketConnectedData)
    
    /// Called when a new group log entry is received
    func webSocketClient(_ client: WebSocketClient, didReceiveGroupLog data: WebSocketNewGroupLogData)
    
    /// Called when group log streaming ends
    func webSocketClient(_ client: WebSocketClient, didReceiveGroupLogStreamEnd data: WebSocketGroupLogStreamEndData)
    
    /// Called when connection state changes
    func webSocketClient(_ client: WebSocketClient, didChangeConnectionState isConnected: Bool)
    
    /// Called when an error occurs
    func webSocketClient(_ client: WebSocketClient, didReceiveError error: String)
}

// MARK: - WebSocket Client

/// WebSocket client for real-time chain log updates
/// Configurable with custom WebSocket URL for whitelabel support
@MainActor
public final class WebSocketClient: ObservableObject {
    
    // MARK: - Properties
    
    private let configuration: APIConfiguration
    private let authTokenProvider: AuthTokenProvider
    
    // Connection state
    @Published public private(set) var isConnected = false
    @Published public private(set) var connectionError: String?
    
    // Event publishers
    public let newLogPublisher = PassthroughSubject<WebSocketNewLogData, Never>()
    public let logStreamEndPublisher = PassthroughSubject<WebSocketLogStreamEndData, Never>()
    public let connectedPublisher = PassthroughSubject<WebSocketConnectedData, Never>()
    public let newGroupLogPublisher = PassthroughSubject<WebSocketNewGroupLogData, Never>()
    public let groupLogStreamEndPublisher = PassthroughSubject<WebSocketGroupLogStreamEndData, Never>()
    
    public weak var delegate: WebSocketClientDelegate?
    
    private var webSocketTask: URLSessionWebSocketTask?
    private var session: URLSession
    
    private var reconnectAttempts = 0
    private var shouldReconnect = true
    private var isConnecting = false
    private var reconnectTask: Task<Void, Never>?
    
    private let maxReconnectAttempts = 10
    private let reconnectBaseDelay: TimeInterval = 1.0
    
    private let decoder = JSONDecoder()
    
    // MARK: - Initialization
    
    /// Initialize with configuration and auth token provider
    public init(configuration: APIConfiguration, authTokenProvider: AuthTokenProvider) {
        self.configuration = configuration
        self.authTokenProvider = authTokenProvider
        
        let config = URLSessionConfiguration.default
        self.session = URLSession(configuration: config)
    }
    
    // MARK: - Connection Management
    
    public func connect() async {
        guard !isConnecting, webSocketTask == nil || webSocketTask?.state != .running else {
            return
        }
        
        isConnecting = true
        
        do {
            let token = try await authTokenProvider.createAuthToken()
            let encodedToken = token.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? token
            
            guard let url = URL(string: "\(configuration.wsURL)/ws?token=\(encodedToken)") else {
                throw APIError.invalidResponse
            }
            
            webSocketTask = session.webSocketTask(with: url)
            webSocketTask?.resume()
            
            isConnecting = false
            reconnectAttempts = 0
            isConnected = true
            connectionError = nil
            
            print("[WS] Connected to \(configuration.wsURL)")
            delegate?.webSocketClient(self, didChangeConnectionState: true)
            
            // Start receiving messages
            await receiveMessage()
            
        } catch {
            isConnecting = false
            print("[WS] Failed to connect: \(error)")
            connectionError = error.localizedDescription
            delegate?.webSocketClient(self, didReceiveError: error.localizedDescription)
            
            scheduleReconnect()
        }
    }
    
    public func disconnect() {
        shouldReconnect = false
        reconnectTask?.cancel()
        reconnectTask = nil
        
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        
        isConnected = false
        delegate?.webSocketClient(self, didChangeConnectionState: false)
        print("[WS] Disconnected")
    }
    
    public func reconnect() {
        disconnect()
        shouldReconnect = true
        reconnectAttempts = 0
        
        Task {
            try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
            await connect()
        }
    }
    
    private func scheduleReconnect() {
        guard shouldReconnect, reconnectAttempts < maxReconnectAttempts else {
            if reconnectAttempts >= maxReconnectAttempts {
                connectionError = "Failed to connect after multiple attempts"
            }
            return
        }
        
        let delay = reconnectBaseDelay * pow(2.0, min(Double(reconnectAttempts), 5.0))
        reconnectAttempts += 1
        
        print("[WS] Reconnecting in \(delay)s (attempt \(reconnectAttempts))")
        
        reconnectTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            if !Task.isCancelled {
                await connect()
            }
        }
    }
    
    // MARK: - Message Handling
    
    private func receiveMessage() async {
        guard let task = webSocketTask else { return }
        
        do {
            let message = try await task.receive()
            
            switch message {
            case .string(let text):
                await handleMessage(text)
            case .data(let data):
                if let text = String(data: data, encoding: .utf8) {
                    await handleMessage(text)
                }
            @unknown default:
                break
            }
            
            // Continue receiving
            await receiveMessage()
            
        } catch {
            print("[WS] Receive error: \(error)")
            isConnected = false
            webSocketTask = nil
            delegate?.webSocketClient(self, didChangeConnectionState: false)
            
            if shouldReconnect {
                scheduleReconnect()
            }
        }
    }
    
    private func handleMessage(_ text: String) async {
        guard let data = text.data(using: .utf8) else { return }
        
        struct EventWrapper: Codable {
            let event: String
        }
        
        guard let wrapper = try? decoder.decode(EventWrapper.self, from: data) else {
            print("[WS] Failed to parse message event")
            return
        }
        
        print("[WS] Received: \(wrapper.event)")
        
        switch wrapper.event {
        case "new_log":
            if let message = try? decoder.decode(WebSocketMessage<WebSocketNewLogData>.self, from: data) {
                newLogPublisher.send(message.data)
                delegate?.webSocketClient(self, didReceiveLog: message.data)
            }
            
        case "log_stream_end":
            if let message = try? decoder.decode(WebSocketMessage<WebSocketLogStreamEndData>.self, from: data) {
                logStreamEndPublisher.send(message.data)
                delegate?.webSocketClient(self, didReceiveLogStreamEnd: message.data)
            }
            
        case "connected":
            if let message = try? decoder.decode(WebSocketMessage<WebSocketConnectedData>.self, from: data) {
                connectedPublisher.send(message.data)
                delegate?.webSocketClient(self, didConnect: message.data)
            }
            
        case "new_group_log":
            if let message = try? decoder.decode(WebSocketMessage<WebSocketNewGroupLogData>.self, from: data) {
                newGroupLogPublisher.send(message.data)
                delegate?.webSocketClient(self, didReceiveGroupLog: message.data)
            }
            
        case "group_log_stream_end":
            if let message = try? decoder.decode(WebSocketMessage<WebSocketGroupLogStreamEndData>.self, from: data) {
                groupLogStreamEndPublisher.send(message.data)
                delegate?.webSocketClient(self, didReceiveGroupLogStreamEnd: message.data)
            }
            
        default:
            print("[WS] Unknown event: \(wrapper.event)")
        }
    }
    
    // MARK: - Chain Log Streaming
    
    /// Request historical chain logs from a specific index via WebSocket
    public func streamLogs(fromIndex: Int? = nil) {
        guard let task = webSocketTask, isConnected else {
            print("[WS] Not connected, cannot stream logs")
            return
        }
        
        var message: [String: Any] = ["type": "stream_logs"]
        if let fromIndex = fromIndex {
            message["fromIndex"] = fromIndex
        }
        
        guard let data = try? JSONSerialization.data(withJSONObject: message),
              let text = String(data: data, encoding: .utf8) else {
            print("[WS] Failed to serialize stream_logs message")
            return
        }
        
        task.send(.string(text)) { error in
            if let error = error {
                print("[WS] Failed to send stream_logs: \(error)")
            } else {
                print("[WS] Requested log stream from index: \(fromIndex ?? 0)")
            }
        }
    }
    
    // MARK: - Group Subscriptions
    
    /// Subscribe to real-time updates for a group
    public func subscribeToGroup(_ groupId: String) {
        guard let task = webSocketTask, isConnected else {
            print("[WS] Not connected, cannot subscribe to group")
            return
        }
        
        let message: [String: Any] = [
            "type": "subscribe_group",
            "groupId": groupId
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message),
              let text = String(data: data, encoding: .utf8) else {
            print("[WS] Failed to serialize subscribe_group message")
            return
        }
        
        task.send(.string(text)) { error in
            if let error = error {
                print("[WS] Failed to subscribe to group: \(error)")
            } else {
                print("[WS] Subscribed to group: \(groupId)")
            }
        }
    }
    
    /// Unsubscribe from real-time updates for a group
    public func unsubscribeFromGroup(_ groupId: String) {
        guard let task = webSocketTask, isConnected else {
            print("[WS] Not connected, cannot unsubscribe from group")
            return
        }
        
        let message: [String: Any] = [
            "type": "unsubscribe_group",
            "groupId": groupId
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message),
              let text = String(data: data, encoding: .utf8) else {
            print("[WS] Failed to serialize unsubscribe_group message")
            return
        }
        
        task.send(.string(text)) { error in
            if let error = error {
                print("[WS] Failed to unsubscribe from group: \(error)")
            } else {
                print("[WS] Unsubscribed from group: \(groupId)")
            }
        }
    }
    
    /// Request historical group chain logs from a specific index via WebSocket
    public func streamGroupLogs(groupId: String, fromIndex: Int? = nil) {
        guard let task = webSocketTask, isConnected else {
            print("[WS] Not connected, cannot stream group logs")
            return
        }
        
        var message: [String: Any] = [
            "type": "stream_group_logs",
            "groupId": groupId
        ]
        if let fromIndex = fromIndex {
            message["fromIndex"] = fromIndex
        }
        
        guard let data = try? JSONSerialization.data(withJSONObject: message),
              let text = String(data: data, encoding: .utf8) else {
            print("[WS] Failed to serialize stream_group_logs message")
            return
        }
        
        task.send(.string(text)) { error in
            if let error = error {
                print("[WS] Failed to send stream_group_logs: \(error)")
            } else {
                print("[WS] Requested group log stream for \(groupId) from index: \(fromIndex ?? 0)")
            }
        }
    }
    
    // MARK: - Cleanup
    
    public func cleanup() {
        disconnect()
        reconnectAttempts = 0
        connectionError = nil
    }
}

// MARK: - Default Delegate Implementation

public extension WebSocketClientDelegate {
    func webSocketClient(_ client: WebSocketClient, didReceiveLog data: WebSocketNewLogData) {}
    func webSocketClient(_ client: WebSocketClient, didReceiveLogStreamEnd data: WebSocketLogStreamEndData) {}
    func webSocketClient(_ client: WebSocketClient, didConnect data: WebSocketConnectedData) {}
    func webSocketClient(_ client: WebSocketClient, didReceiveGroupLog data: WebSocketNewGroupLogData) {}
    func webSocketClient(_ client: WebSocketClient, didReceiveGroupLogStreamEnd data: WebSocketGroupLogStreamEndData) {}
    func webSocketClient(_ client: WebSocketClient, didChangeConnectionState isConnected: Bool) {}
    func webSocketClient(_ client: WebSocketClient, didReceiveError error: String) {}
}
