# ChainLogDB

A unified Swift package providing cryptographically verifiable, hash-linked append-only logs with an event-driven local database. Designed for iOS 15+ and macOS 12+.

## Features

- **ChainLogs** - Hash-linked, cryptographically signed append-only logs with tamper detection
- **GroupChainLogs** - Privacy-preserving group logs with BBS+ anonymous membership proofs
- **DBLog** - Event-sourced local SQLite database that replays from ChainLogs
- **Cryptography** - Ethereum-compatible crypto (secp256k1, EIP-191 signing, ECIES encryption)
- **API Client** - Configurable REST client for chain log operations with whitelabel support
- **WebSocket** - Real-time updates via WebSocket with automatic reconnection
- **Encrypted Messaging** - Package-based encrypted messaging between users

## Installation

### Swift Package Manager

Add ChainLogDB to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/your-org/ChainLogDB.git", from: "1.0.0")
]
```

Or add via Xcode: File → Add Packages → enter the repository URL.

### Requirements

- iOS 15.0+ / macOS 12.0+
- Swift 6.2+

## Quick Start

```swift
import ChainLogDb

// 1. Generate or load keys
let keyPair = try Cryptograph.generateKeyPair()
print("Address: \(keyPair.address)")

// 2. Configure the package
let config = ChainLogServiceConfiguration(
    credentials: MyCredentialsProvider(keyPair: keyPair),
    networkProvider: MyNetworkProvider()
)
ChainLogServices.configure(config)

// 3. Use the database
let db = DBLogDatabase(path: "path/to/db.sqlite")
try await db.open()

// Create a table via DBLog
let schema = SchemaAction(
    dblogindex: 0,
    table: "todos",
    columns: ["id": "TEXT PRIMARY KEY", "title": "TEXT", "completed": "INTEGER"]
)
try await db.process(.schema(schema))

// Insert data
let setAction = SetAction(
    dblogindex: 1,
    table: "todos",
    id: "todo-1",
    data: ["title": .string("Learn ChainLogDB"), "completed": .bool(false)]
)
try await db.process(.set(setAction))

// Query
let todos = try await db.queryAll(table: "todos")
```

## Core Concepts

### ChainLogs

ChainLogs are append-only, hash-linked logs where each entry references the previous entry's hash, creating an immutable chain. Any tampering is immediately detectable.

```
Entry 0 (Genesis)          Entry 1                    Entry 2
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ prevHash: 0000.. │──────│ prevHash: abc123 │──────│ prevHash: def456 │
│ content: ...     │      │ content: ...     │      │ content: ...     │
│ hash: abc123     │      │ hash: def456     │      │ hash: 789xyz     │
│ signature: ...   │      │ signature: ...   │      │ signature: ...   │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

Each entry contains:
- `index` - Sequential position in the chain
- `prevHash` - SHA256 hash of the previous entry (genesis uses zero hash)
- `content` - Encrypted payload (only owner can decrypt)
- `nonce` - Random value for uniqueness
- `hash` - SHA256(index:prevHash:content:nonce)
- `signature` - EIP-191 signature proving authorship
- `createdAt` - Timestamp

### DBLog (Event-Driven Database)

DBLog entries are JSON arrays of database operations stored inside ChainLog content. When synced, the local SQLite database replays these operations to reconstruct state.

**Supported Actions:**

| Action | Description |
|--------|-------------|
| `schema` | Create a table with columns |
| `set` | Insert or update a row (upsert) |
| `delete` | Remove a row by id |
| `migrate` | Alter table schema (add/drop/rename columns) |

### Group ChainLogs (Privacy-Preserving)

Group ChainLogs provide end-to-end encrypted group communication where the server cannot see:
- Who sent a message (anonymous via BBS+ group signatures)
- What epoch/state the group is in
- The message content

The server only verifies membership proofs and maintains chain integrity.

## Configuration

### Implementing Protocols

To use ChainLogDB, implement these protocols:

```swift
// Provide cryptographic keys
struct MyCredentialsProvider: CredentialsProvider {
    let keyPair: KeyPair
    
    var publicKey: String? { keyPair.publicKey }
    var privateKey: String? { keyPair.privateKey }
    var hasCredentials: Bool { true }
}

// Provide authentication tokens
struct MyAuthTokenProvider: AuthTokenProvider {
    let privateKey: String
    
    func createAuthToken() async throws -> String {
        // Create a signed JWT or similar token
        let timestamp = Int(Date().timeIntervalSince1970)
        let message = "auth:\(timestamp)"
        let signed = try Cryptograph.signMessage(message, privateKey: privateKey)
        return "\(message):\(signed.signature)"
    }
}

// Provide network operations (optional - if using built-in API client)
struct MyNetworkProvider: ChainLogNetworkProvider {
    let apiClient: ChainLogAPIClient
    
    func getChainLogHead(dbName: String) async throws -> ChainLogHeadInfo? {
        guard let entry = try await apiClient.getChainLogHead(dbName: dbName) else {
            return nil
        }
        return ChainLogHeadInfo(from: entry)
    }
    
    func listChainLogs(startIndex: Int, limit: Int, dbName: String) async throws -> (entries: [EncryptedChainLogEntry], hasMore: Bool) {
        try await apiClient.listChainLogs(startIndex: startIndex, limit: limit, dbName: dbName)
    }
    
    func appendChainLog(_ request: AppendChainLogRequest, dbName: String) async throws -> EncryptedChainLogEntry {
        try await apiClient.appendChainLog(request, dbName: dbName)
    }
}
```

### API Configuration

```swift
let apiConfig = APIConfiguration(
    baseURL: "https://api.yourserver.com",
    wsURL: "wss://api.yourserver.com",  // Optional, derived from baseURL if not provided
    requestTimeout: 30,
    resourceTimeout: 60
)

let apiClient = ChainLogAPIClient(
    configuration: apiConfig,
    authTokenProvider: MyAuthTokenProvider(privateKey: keyPair.privateKey)
)
```

## Cryptography

ChainLogDB includes Ethereum-compatible cryptography compatible with `viem` (TypeScript) and `eciesjs`.

### Key Generation

```swift
// Generate new key pair
let keyPair = try Cryptograph.generateKeyPair()
print("Private Key: \(keyPair.privateKey)")  // 0x...
print("Public Key: \(keyPair.publicKey)")    // 0x04...
print("Address: \(keyPair.address)")         // 0x... (EIP-55 checksum)

// Derive from existing private key
let imported = try Cryptograph.privateKeyToKeys("0x...")
```

### Signing (EIP-191)

```swift
// Sign a message (compatible with viem's signMessage)
let signed = try Cryptograph.signMessage("Hello, World!", privateKey: keyPair.privateKey)
print("Signature: \(signed.signature)")

// Verify signature
let isValid = try Cryptograph.verifySignature(
    message: "Hello, World!",
    signature: signed.signature,
    address: keyPair.address
)
```

### Encryption (ECIES)

```swift
// Encrypt for a recipient's public key (compatible with eciesjs)
let encrypted = try Cryptograph.encryptForPublicKey(
    "Secret message",
    recipientPublicKey: recipientKeyPair.publicKey
)

// Decrypt with private key
let decrypted = try Cryptograph.decryptWithPrivateKey(
    encrypted,
    privateKey: recipientKeyPair.privateKey
)

// Sign and encrypt (proves authorship + confidentiality)
let signedEncrypted = try Cryptograph.signAndEncrypt(
    "Authenticated secret",
    senderPrivateKey: senderKeyPair.privateKey,
    recipientPublicKey: recipientKeyPair.publicKey
)

// Decrypt and verify sender
let (verified, message) = try Cryptograph.decryptAndVerify(
    signedEncrypted,
    recipientPrivateKey: recipientKeyPair.privateKey,
    senderAddress: senderKeyPair.address
)
```

### Hashing

```swift
// SHA256 (used for chain log hashes)
let hash = Cryptograph.sha256Hash("data")

// Keccak256 checksum (Ethereum-style)
let checksum = Cryptograph.createChecksum("data")

// Generate random nonce
let nonce = Cryptograph.generateNonce(length: 32)
```

## Database Operations

### Opening the Database

```swift
// With custom path
let db = DBLogDatabase(path: "/path/to/mydb.sqlite")
try await db.open()

// With default path (Documents/dblog.sqlite)
let db = DBLogDatabase()
try await db.open()

// In-memory for testing
let db = DBLogDatabase(path: ":memory:")
try await db.open()

// Don't forget to close when done
await db.close()
```

### Creating Tables

```swift
let schemaAction = SchemaAction(
    dblogindex: 0,
    table: "users",
    columns: [
        "id": "TEXT PRIMARY KEY",
        "name": "TEXT NOT NULL",
        "email": "TEXT",
        "created_at": "INTEGER"
    ]
)
try await db.process(.schema(schemaAction))
```

### Inserting/Updating Data

```swift
// Set (upsert) a row
let setAction = SetAction(
    dblogindex: 1,
    table: "users",
    id: "user-123",
    data: [
        "name": .string("Alice"),
        "email": .string("alice@example.com"),
        "created_at": .int(Int(Date().timeIntervalSince1970))
    ]
)
try await db.process(.set(setAction))
```

### Deleting Data

```swift
let deleteAction = DeleteAction(
    dblogindex: 2,
    table: "users",
    id: "user-123"
)
try await db.process(.delete(deleteAction))
```

### Schema Migrations

```swift
let migrateAction = MigrateAction(
    dblogindex: 3,
    table: "users",
    migration: Migration(
        version: 2,
        operations: [
            .addColumn(column: "avatar_url", columnType: "TEXT"),
            .renameColumn(from: "created_at", to: "createdAt")
        ]
    )
)
try await db.process(.migrate(migrateAction))
```

### Querying Data

```swift
// Get all rows
let users = try await db.queryAll(table: "users")

// Get single row by id
if let user = try await db.queryRow(table: "users", id: "user-123") {
    print("Found: \(user["name"] ?? "unknown")")
}

// Query with condition
let activeUsers = try await db.queryWhere(table: "users", condition: "active = 1")

// Raw SQL query (SELECT only)
let results = try await db.query("SELECT name, email FROM users WHERE name LIKE 'A%'")

// Count rows
let count = try await db.queryCount(table: "users")

// Check table existence
let exists = try await db.tableExists("users")

// Get schema version
let version = try await db.schemaVersion(for: "users")
```

### Batch Processing

```swift
// Process multiple actions in a transaction
let actions: [DBLogAction] = [
    .schema(schemaAction),
    .set(setAction1),
    .set(setAction2)
]
try await db.process(actions)

// Process with chain index tracking
try await db.processAndTrack(actions, chainIndex: 5)
```

## DBLog Value Types

The `DBLogValue` enum represents type-safe JSON values:

```swift
let data: [String: DBLogValue] = [
    "name": .string("Alice"),
    "age": .int(30),
    "balance": .double(100.50),
    "active": .bool(true),
    "tags": .array([.string("admin"), .string("verified")]),
    "metadata": .object(["key": .string("value")]),
    "nullable": .null
]
```

## API Client

### Personal Chain Logs

```swift
let apiClient = ChainLogAPIClient(
    configuration: apiConfig,
    authTokenProvider: authProvider
)

// List chain logs
let (logs, hasMore) = try await apiClient.listChainLogs(startIndex: 0, limit: 100)

// Get head (latest entry)
if let head = try await apiClient.getChainLogHead() {
    print("Latest index: \(head.index)")
}

// Get specific entry
let entry = try await apiClient.getChainLog(index: 5)

// Append new entry
let request = AppendChainLogRequest(
    index: 10,
    prevHash: previousHash,
    content: encryptedContent,
    nonce: nonce,
    hash: computedHash,
    signature: signature
)
let newEntry = try await apiClient.appendChainLog(request)
```

### Group Chain Logs

```swift
// Create a group
let groupInfo = try await apiClient.createGroup(
    groupId: "group-uuid",
    groupPublicKey: bbsPlusPublicKeyJSON,
    initialAccessKey: epochAccessKeyHex
)

// List group logs
let (groupLogs, hasMore) = try await apiClient.listGroupLogs(
    groupId: "group-uuid",
    startIndex: 0,
    limit: 100
)

// Append to group (privacy-preserving)
let groupRequest = AppendGroupChainLogRequest(
    index: 5,
    prevHash: prevHash,
    ciphertext: encryptedPayload,
    nonce: nonce,
    hash: hash,
    groupSignature: bbsPlusSignature,
    accessProof: hmacProof
)
let newGroupEntry = try await apiClient.appendGroupLog(groupId: "group-uuid", request: groupRequest)
```

### Packages (Encrypted Messaging)

```swift
// List packages
let (packages, hasMore) = try await apiClient.listPackages(
    contact: "0x...",           // Optional: filter by contact
    direction: .received,       // Optional: sent or received
    since: Date().addingTimeInterval(-86400)  // Optional: since timestamp
)

// Get package content
let package = try await apiClient.getPackage("package-id")

// Send a package
let sendRequest = SendPackageRequest(
    recipientAddress: "0x...",
    senderPackageType: encryptedTypeForSender,
    senderContent: encryptedContentForSender,
    recipientPackageType: encryptedTypeForRecipient,
    recipientContent: encryptedContentForRecipient
)
let response = try await apiClient.sendPackage(sendRequest)

// Mark as read
try await apiClient.markPackageRead("package-id")

// Delete
try await apiClient.deletePackage("package-id")
```

### KV Store

```swift
// List all KV items
let items = try await apiClient.listKvItems()

// Get specific item
let item = try await apiClient.getKvItem("item-id")

// Create/update
let newItem = try await apiClient.createKvItem(name: encryptedName, value: encryptedValue)
try await apiClient.updateKvItem("item-id", value: newEncryptedValue)

// Delete
try await apiClient.deleteKvItem("item-id")
```

### List Store

```swift
// Create a list
let list = try await apiClient.createList(name: encryptedListName)

// Get lists
let lists = try await apiClient.getLists()

// Add item to list
let item = try await apiClient.pushListItem(list.id, value: encryptedValue)

// Get items
let items = try await apiClient.getListItems(list.id)

// Delete item
try await apiClient.deleteListItem(list.id, itemId: item.id)

// Delete list
try await apiClient.deleteList(list.id)
```

## WebSocket Real-Time Updates

```swift
@MainActor
class MyService: WebSocketClientDelegate {
    let wsClient: WebSocketClient
    
    init() {
        wsClient = WebSocketClient(
            configuration: apiConfig,
            authTokenProvider: authProvider
        )
        wsClient.delegate = self
    }
    
    func connect() async {
        await wsClient.connect()
    }
    
    // Delegate methods
    func webSocketClient(_ client: WebSocketClient, didConnect data: WebSocketConnectedData) {
        print("Connected as: \(data.address)")
        
        // Start streaming logs from index 0
        client.streamLogs(fromIndex: 0)
        
        // Subscribe to a group
        client.subscribeToGroup("group-uuid")
    }
    
    func webSocketClient(_ client: WebSocketClient, didReceiveLog data: WebSocketNewLogData) {
        print("New log at index: \(data.index)")
        // Process the new log entry
    }
    
    func webSocketClient(_ client: WebSocketClient, didReceiveGroupLog data: WebSocketNewGroupLogData) {
        print("New group log for \(data.groupId) at index: \(data.index)")
    }
    
    func webSocketClient(_ client: WebSocketClient, didReceivePackage data: WebSocketNewPackageData) {
        print("New package from: \(data.counterpartyAddress)")
    }
    
    func webSocketClient(_ client: WebSocketClient, didChangeConnectionState isConnected: Bool) {
        print("Connection state: \(isConnected)")
    }
}
```

### Using Combine Publishers

```swift
import Combine

var cancellables = Set<AnyCancellable>()

// Subscribe to new logs
wsClient.newLogPublisher
    .sink { logData in
        print("Received log: \(logData.index)")
    }
    .store(in: &cancellables)

// Subscribe to new packages
wsClient.newPackagePublisher
    .sink { packageData in
        print("New package: \(packageData.id)")
    }
    .store(in: &cancellables)

// Subscribe to group logs
wsClient.newGroupLogPublisher
    .sink { groupLogData in
        print("Group \(groupLogData.groupId): \(groupLogData.index)")
    }
    .store(in: &cancellables)
```

### Device Registration

```swift
// Register for push notifications
wsClient.registerDevice(
    token: deviceToken,
    platform: "ios",
    environment: "production"  // or "sandbox" for development
)

// Unregister
wsClient.unregisterDevice(token: deviceToken)
```

## Architecture

```
ChainLogDb/
├── API/
│   ├── APIConfiguration.swift      # Configuration and protocols
│   ├── ChainLogAPIClient.swift     # REST API client
│   ├── StorageTypes.swift          # KV and List store types
│   └── WebSocketClient.swift       # Real-time WebSocket client
├── Core/
│   ├── ChainLogCore.swift          # ChainLog protocol abstractions
│   └── DBLogCore.swift             # DBLog protocol abstractions
├── Crypto/
│   ├── Cryptograph.swift           # Ethereum-compatible crypto
│   ├── HexUtils.swift              # Hex encoding utilities
│   ├── GroupSig/                   # BBS+ group signatures
│   │   ├── BBSPlus.swift
│   │   ├── BLS12381.swift
│   │   └── AccessProof.swift
│   └── MLS/                        # MLS key management
│       ├── MLSGroup.swift
│       ├── MLSHKDF.swift
│       └── MLSTree.swift
├── Database/
│   ├── DBLogDatabase.swift         # SQLite database actor
│   └── DBLogProcessor.swift        # SQL generation (pure functions)
├── Models/
│   ├── ChainLog.swift              # Personal chain log types
│   ├── DBLog.swift                 # Database action types
│   ├── GroupChainLog.swift         # Group chain log types
│   └── Package.swift               # Encrypted messaging types
├── Services/
│   ├── ChainLogConfiguration.swift # Global configuration
│   └── ServiceProtocols.swift      # Network provider protocols
└── Storage/
    ├── FileStorageProvider.swift   # File-based state storage
    └── StorageProvider.swift       # Storage protocol
```

## Security Considerations

### Chain Integrity

- Every entry's hash includes the previous hash, creating a tamper-evident chain
- Signatures prove authorship and prevent forgery
- The genesis hash (`0000...`) anchors the chain

### Encryption

- Content is encrypted with the owner's public key
- Only the private key holder can decrypt
- ECIES provides forward secrecy via ephemeral keys

### Group Privacy

- Server cannot identify message senders (BBS+ zero-knowledge proofs)
- Server cannot read message content (end-to-end encrypted)
- Server only verifies membership proofs and access tokens

### Key Management

- Never store private keys in plain text
- Use iOS Keychain or Secure Enclave for key storage
- Implement proper key derivation for multiple accounts

## Error Handling

The package defines specific error types:

```swift
// Cryptographic errors
enum CryptoError: Error {
    case invalidPrivateKey
    case invalidPublicKey
    case invalidSignature
    case encryptionFailed(String)
    case decryptionFailed(String)
}

// Chain log errors
enum ChainLogError: Error {
    case invalidHash
    case invalidSignature
    case chainBroken(expected: String, got: String)
    case conflictDetected(serverHead: EncryptedChainLogEntry)
}

// Database errors
enum DBLogError: Error {
    case invalidJSON(String)
    case tableNotFound(String)
    case sqlExecutionFailed(String)
    case notInitialized
}

// API errors
enum APIError: Error {
    case noCredentials
    case httpError(Int, String)
    case invalidResponse
}
```

## Testing

```swift
import XCTest
@testable import ChainLogDb

class ChainLogTests: XCTestCase {
    
    func testKeyGeneration() throws {
        let keyPair = try Cryptograph.generateKeyPair()
        XCTAssertTrue(keyPair.privateKey.hasPrefix("0x"))
        XCTAssertTrue(keyPair.publicKey.hasPrefix("0x04"))
        XCTAssertTrue(keyPair.address.hasPrefix("0x"))
        XCTAssertEqual(keyPair.address.count, 42)
    }
    
    func testSignAndVerify() throws {
        let keyPair = try Cryptograph.generateKeyPair()
        let signed = try Cryptograph.signMessage("test", privateKey: keyPair.privateKey)
        let verified = try Cryptograph.verifySignedMessage(signed)
        XCTAssertTrue(verified)
    }
    
    func testEncryptDecrypt() throws {
        let keyPair = try Cryptograph.generateKeyPair()
        let original = "Secret message"
        let encrypted = try Cryptograph.encryptForPublicKey(original, recipientPublicKey: keyPair.publicKey)
        let decrypted = try Cryptograph.decryptWithPrivateKey(encrypted, privateKey: keyPair.privateKey)
        XCTAssertEqual(original, decrypted)
    }
    
    func testDBLogProcessor() async throws {
        let db = DBLogDatabase(path: ":memory:")
        try await db.open()
        
        let schema = SchemaAction(dblogindex: 0, table: "test", columns: ["id": "TEXT PRIMARY KEY", "value": "TEXT"])
        try await db.process(.schema(schema))
        
        let set = SetAction(dblogindex: 1, table: "test", id: "1", data: ["value": .string("hello")])
        try await db.process(.set(set))
        
        let results = try await db.queryAll(table: "test")
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?["value"] as? String, "hello")
        
        await db.close()
    }
}
```

## License

MIT License - see LICENSE file for details.

## Dependencies

- [K1](https://github.com/Sajjon/K1) - secp256k1 elliptic curve operations
- [SwiftKeccak](https://github.com/bitflying/SwiftKeccak) - Keccak hashing
- [BigInt](https://github.com/attaswift/BigInt) - Arbitrary precision integers
- [bls-eth-swift](https://github.com/MyEtherWallet/bls-eth-swift) - BLS12-381 curve for group signatures
