//
//  MLSTypes.swift
//  ChainKeys
//
//  MLS (Messaging Layer Security) types for group encryption
//

import Foundation

// MARK: - Tree Node Types

/// A leaf node in the MLS tree represents a group member
public struct LeafNode: Equatable, Sendable {
    public let index: Int
    public let publicKey: Hex
    
    public init(index: Int, publicKey: Hex) {
        self.index = index
        self.publicKey = publicKey
    }
}

extension LeafNode: Codable {
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.index = try container.decode(Int.self, forKey: .index)
        self.publicKey = try container.decode(Hex.self, forKey: .publicKey)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(index, forKey: .index)
        try container.encode(publicKey, forKey: .publicKey)
    }
    
    private enum CodingKeys: String, CodingKey {
        case index, publicKey
    }
}

/// An intermediate node in the binary tree
public struct ParentNode: Equatable, Sendable {
    public let publicKey: Hex?        // nil if blank
    public let unmergedLeaves: [Int]  // indices of unmerged leaves below
    
    public init(publicKey: Hex? = nil, unmergedLeaves: [Int] = []) {
        self.publicKey = publicKey
        self.unmergedLeaves = unmergedLeaves
    }
}

extension ParentNode: Codable {
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.publicKey = try container.decodeIfPresent(Hex.self, forKey: .publicKey)
        self.unmergedLeaves = try container.decode([Int].self, forKey: .unmergedLeaves)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(publicKey, forKey: .publicKey)
        try container.encode(unmergedLeaves, forKey: .unmergedLeaves)
    }
    
    private enum CodingKeys: String, CodingKey {
        case publicKey, unmergedLeaves
    }
}

/// Union type for tree nodes
public enum TreeNode: Equatable, Sendable {
    case leaf(node: LeafNode?)
    case parent(node: ParentNode)
}

extension TreeNode: Codable {
    // Custom Codable conformance to match TypeScript format
    private enum CodingKeys: String, CodingKey {
        case type
        case node
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        
        switch type {
        case "leaf":
            let node = try container.decodeIfPresent(LeafNode.self, forKey: .node)
            self = .leaf(node: node)
        case "parent":
            let node = try container.decode(ParentNode.self, forKey: .node)
            self = .parent(node: node)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Unknown tree node type: \(type)"
            )
        }
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .leaf(let node):
            try container.encode("leaf", forKey: .type)
            try container.encode(node, forKey: .node)
        case .parent(let node):
            try container.encode("parent", forKey: .type)
            try container.encode(node, forKey: .node)
        }
    }
}

// MARK: - Group State

/// Group state holds all information about an MLS group
public struct GroupState: Equatable, Sendable {
    public let groupId: String
    public var epoch: Int                    // increments on each tree change
    public var tree: [TreeNode]              // binary heap representation (left-balanced)
    public let myLeafIndex: Int              // this client's position in the tree
    public var myPrivateKey: Hex             // this client's current leaf private key
    public var pathSecrets: [Hex]            // derived secrets for path from leaf to root
    public var groupKey: Hex                 // current encryption key (derived from root)
    
    public init(
        groupId: String,
        epoch: Int,
        tree: [TreeNode],
        myLeafIndex: Int,
        myPrivateKey: Hex,
        pathSecrets: [Hex],
        groupKey: Hex
    ) {
        self.groupId = groupId
        self.epoch = epoch
        self.tree = tree
        self.myLeafIndex = myLeafIndex
        self.myPrivateKey = myPrivateKey
        self.pathSecrets = pathSecrets
        self.groupKey = groupKey
    }
}

extension GroupState: Codable {
    private enum CodingKeys: String, CodingKey {
        case groupId, epoch, tree, myLeafIndex, myPrivateKey, pathSecrets, groupKey
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.groupId = try container.decode(String.self, forKey: .groupId)
        self.epoch = try container.decode(Int.self, forKey: .epoch)
        self.tree = try container.decode([TreeNode].self, forKey: .tree)
        self.myLeafIndex = try container.decode(Int.self, forKey: .myLeafIndex)
        self.myPrivateKey = try container.decode(Hex.self, forKey: .myPrivateKey)
        self.pathSecrets = try container.decode([Hex].self, forKey: .pathSecrets)
        self.groupKey = try container.decode(Hex.self, forKey: .groupKey)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(groupId, forKey: .groupId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(tree, forKey: .tree)
        try container.encode(myLeafIndex, forKey: .myLeafIndex)
        try container.encode(myPrivateKey, forKey: .myPrivateKey)
        try container.encode(pathSecrets, forKey: .pathSecrets)
        try container.encode(groupKey, forKey: .groupKey)
    }
}

// MARK: - Encrypted Types

/// Encrypted group state for Welcome messages
public struct EncryptedGroupState: Equatable, Sendable {
    public let ciphertext: String  // base64 encoded
    
    public init(ciphertext: String) {
        self.ciphertext = ciphertext
    }
}

extension EncryptedGroupState: Codable {
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let dict = try container.decode([String: String].self)
        guard let ciphertext = dict["ciphertext"] else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Missing ciphertext")
        }
        self.ciphertext = ciphertext
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(["ciphertext": ciphertext])
    }
}

/// Encrypted path secrets for Welcome messages
public struct EncryptedPathSecrets: Equatable, Sendable {
    public let ciphertext: String  // base64 encoded, encrypted for new member
    
    public init(ciphertext: String) {
        self.ciphertext = ciphertext
    }
}

extension EncryptedPathSecrets: Codable {
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let dict = try container.decode([String: String].self)
        guard let ciphertext = dict["ciphertext"] else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Missing ciphertext")
        }
        self.ciphertext = ciphertext
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(["ciphertext": ciphertext])
    }
}

// MARK: - Update Path Types

/// Update path node contains new public key and encrypted secrets for the node
public struct UpdatePathNode: Equatable, Sendable {
    public let publicKey: Hex
    public let encryptedPathSecret: [String]  // one for each resolution node
    
    public init(publicKey: Hex, encryptedPathSecret: [String]) {
        self.publicKey = publicKey
        self.encryptedPathSecret = encryptedPathSecret
    }
}

extension UpdatePathNode: Codable {
    private enum CodingKeys: String, CodingKey {
        case publicKey, encryptedPathSecret
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.publicKey = try container.decode(Hex.self, forKey: .publicKey)
        self.encryptedPathSecret = try container.decode([String].self, forKey: .encryptedPathSecret)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(publicKey, forKey: .publicKey)
        try container.encode(encryptedPathSecret, forKey: .encryptedPathSecret)
    }
}

/// Update path contains new public keys and encrypted secrets for each node on the path
public struct UpdatePath: Equatable, Sendable {
    public let leafNode: LeafNode
    public let nodes: [UpdatePathNode]  // from leaf to root (exclusive of root)
    
    public init(leafNode: LeafNode, nodes: [UpdatePathNode]) {
        self.leafNode = leafNode
        self.nodes = nodes
    }
}

extension UpdatePath: Codable {
    private enum CodingKeys: String, CodingKey {
        case leafNode, nodes
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.leafNode = try container.decode(LeafNode.self, forKey: .leafNode)
        self.nodes = try container.decode([UpdatePathNode].self, forKey: .nodes)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(leafNode, forKey: .leafNode)
        try container.encode(nodes, forKey: .nodes)
    }
}

// MARK: - MLS Message Types

/// Welcome message sent to new members joining a group
public struct WelcomeMessage: Equatable, Sendable {
    public let type: String  // "welcome"
    public let groupId: String
    public let epoch: Int
    public let groupState: EncryptedGroupState
    public let pathSecrets: EncryptedPathSecrets
    
    public init(groupId: String, epoch: Int, groupState: EncryptedGroupState, pathSecrets: EncryptedPathSecrets) {
        self.type = "welcome"
        self.groupId = groupId
        self.epoch = epoch
        self.groupState = groupState
        self.pathSecrets = pathSecrets
    }
}

extension WelcomeMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, groupId, epoch, groupState, pathSecrets
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(String.self, forKey: .type)
        self.groupId = try container.decode(String.self, forKey: .groupId)
        self.epoch = try container.decode(Int.self, forKey: .epoch)
        self.groupState = try container.decode(EncryptedGroupState.self, forKey: .groupState)
        self.pathSecrets = try container.decode(EncryptedPathSecrets.self, forKey: .pathSecrets)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(groupId, forKey: .groupId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(groupState, forKey: .groupState)
        try container.encode(pathSecrets, forKey: .pathSecrets)
    }
}

/// Add message for adding a new member to the group
public struct AddMessage: Equatable, Sendable {
    public let type: String  // "add"
    public let groupId: String
    public let epoch: Int
    public let leafIndex: Int
    public let publicKey: Hex
    public let updatePath: UpdatePath
    
    public init(groupId: String, epoch: Int, leafIndex: Int, publicKey: Hex, updatePath: UpdatePath) {
        self.type = "add"
        self.groupId = groupId
        self.epoch = epoch
        self.leafIndex = leafIndex
        self.publicKey = publicKey
        self.updatePath = updatePath
    }
}

extension AddMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, groupId, epoch, leafIndex, publicKey, updatePath
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(String.self, forKey: .type)
        self.groupId = try container.decode(String.self, forKey: .groupId)
        self.epoch = try container.decode(Int.self, forKey: .epoch)
        self.leafIndex = try container.decode(Int.self, forKey: .leafIndex)
        self.publicKey = try container.decode(Hex.self, forKey: .publicKey)
        self.updatePath = try container.decode(UpdatePath.self, forKey: .updatePath)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(groupId, forKey: .groupId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(leafIndex, forKey: .leafIndex)
        try container.encode(publicKey, forKey: .publicKey)
        try container.encode(updatePath, forKey: .updatePath)
    }
}

/// Remove message for removing a member from the group
public struct RemoveMessage: Equatable, Sendable {
    public let type: String  // "remove"
    public let groupId: String
    public let epoch: Int
    public let leafIndex: Int
    public let updatePath: UpdatePath
    
    public init(groupId: String, epoch: Int, leafIndex: Int, updatePath: UpdatePath) {
        self.type = "remove"
        self.groupId = groupId
        self.epoch = epoch
        self.leafIndex = leafIndex
        self.updatePath = updatePath
    }
}

extension RemoveMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, groupId, epoch, leafIndex, updatePath
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(String.self, forKey: .type)
        self.groupId = try container.decode(String.self, forKey: .groupId)
        self.epoch = try container.decode(Int.self, forKey: .epoch)
        self.leafIndex = try container.decode(Int.self, forKey: .leafIndex)
        self.updatePath = try container.decode(UpdatePath.self, forKey: .updatePath)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(groupId, forKey: .groupId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(leafIndex, forKey: .leafIndex)
        try container.encode(updatePath, forKey: .updatePath)
    }
}

/// Update message for updating own key (forward secrecy)
public struct UpdateMessage: Equatable, Sendable {
    public let type: String  // "update"
    public let groupId: String
    public let epoch: Int
    public let leafIndex: Int
    public let updatePath: UpdatePath
    
    public init(groupId: String, epoch: Int, leafIndex: Int, updatePath: UpdatePath) {
        self.type = "update"
        self.groupId = groupId
        self.epoch = epoch
        self.leafIndex = leafIndex
        self.updatePath = updatePath
    }
}

extension UpdateMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, groupId, epoch, leafIndex, updatePath
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(String.self, forKey: .type)
        self.groupId = try container.decode(String.self, forKey: .groupId)
        self.epoch = try container.decode(Int.self, forKey: .epoch)
        self.leafIndex = try container.decode(Int.self, forKey: .leafIndex)
        self.updatePath = try container.decode(UpdatePath.self, forKey: .updatePath)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(groupId, forKey: .groupId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(leafIndex, forKey: .leafIndex)
        try container.encode(updatePath, forKey: .updatePath)
    }
}

/// Application message (encrypted with group key)
public struct ApplicationMessage: Equatable, Sendable {
    public let type: String  // "application"
    public let groupId: String
    public let epoch: Int
    public let ciphertext: String  // encrypted with group key
    public let senderLeafIndex: Int
    
    public init(groupId: String, epoch: Int, ciphertext: String, senderLeafIndex: Int) {
        self.type = "application"
        self.groupId = groupId
        self.epoch = epoch
        self.ciphertext = ciphertext
        self.senderLeafIndex = senderLeafIndex
    }
}

extension ApplicationMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, groupId, epoch, ciphertext, senderLeafIndex
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(String.self, forKey: .type)
        self.groupId = try container.decode(String.self, forKey: .groupId)
        self.epoch = try container.decode(Int.self, forKey: .epoch)
        self.ciphertext = try container.decode(String.self, forKey: .ciphertext)
        self.senderLeafIndex = try container.decode(Int.self, forKey: .senderLeafIndex)
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(groupId, forKey: .groupId)
        try container.encode(epoch, forKey: .epoch)
        try container.encode(ciphertext, forKey: .ciphertext)
        try container.encode(senderLeafIndex, forKey: .senderLeafIndex)
    }
}

/// Union type for all MLS messages
public enum MLSMessage: Equatable, Sendable {
    case welcome(WelcomeMessage)
    case add(AddMessage)
    case remove(RemoveMessage)
    case update(UpdateMessage)
    case application(ApplicationMessage)
}

extension MLSMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type
    }
    
    public nonisolated init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        
        let singleValueContainer = try decoder.singleValueContainer()
        
        switch type {
        case "welcome":
            self = .welcome(try singleValueContainer.decode(WelcomeMessage.self))
        case "add":
            self = .add(try singleValueContainer.decode(AddMessage.self))
        case "remove":
            self = .remove(try singleValueContainer.decode(RemoveMessage.self))
        case "update":
            self = .update(try singleValueContainer.decode(UpdateMessage.self))
        case "application":
            self = .application(try singleValueContainer.decode(ApplicationMessage.self))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Unknown MLS message type: \(type)"
            )
        }
    }
    
    public nonisolated func encode(to encoder: Encoder) throws {
        var singleValueContainer = encoder.singleValueContainer()
        
        switch self {
        case .welcome(let msg):
            try singleValueContainer.encode(msg)
        case .add(let msg):
            try singleValueContainer.encode(msg)
        case .remove(let msg):
            try singleValueContainer.encode(msg)
        case .update(let msg):
            try singleValueContainer.encode(msg)
        case .application(let msg):
            try singleValueContainer.encode(msg)
        }
    }
}

// MARK: - MLS Errors

public enum MLSError: Error, LocalizedError {
    case invalidTree(String)
    case invalidMessage(String)
    case invalidEpoch(String)
    case memberNotFound(String)
    case notAMember(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case keyDerivationFailed(String)
    case invalidSignature(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidTree(let msg): return "Invalid tree: \(msg)"
        case .invalidMessage(let msg): return "Invalid message: \(msg)"
        case .invalidEpoch(let msg): return "Invalid epoch: \(msg)"
        case .memberNotFound(let msg): return "Member not found: \(msg)"
        case .notAMember(let msg): return "Not a member: \(msg)"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        case .keyDerivationFailed(let msg): return "Key derivation failed: \(msg)"
        case .invalidSignature(let msg): return "Invalid signature: \(msg)"
        }
    }
}

// MARK: - Serialized Format

/// Serialized format for storing/transmitting group state
public typealias SerializedGroupState = GroupState
