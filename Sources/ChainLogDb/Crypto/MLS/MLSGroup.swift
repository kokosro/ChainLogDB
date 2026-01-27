//
//  MLSGroup.swift
//  ChainKeys
//
//  MLS Group State Management
//
//  Handles group lifecycle, member management, and application message encryption.
//  AES-256-GCM format must match TypeScript: iv (12 bytes) + tag (16 bytes) + ciphertext
//

import Foundation
import CryptoKit

// MARK: - Group Management

public enum MLSGroup {
    
    // MARK: - Group ID Generation
    
    /// Generate a unique group ID (32 char hex string)
    public static func generateGroupId() -> String {
        let randomBytes = MLSHKDF.generateRandomSecret(length: 16)
        return randomBytes.hexStringNoPrefix
    }
    
    // MARK: - Group Creation
    
    /// Create a new group with the creator as the first member
    public static func createGroup(
        creatorPrivateKey: Hex,
        initialMembers: [Hex] = []
    ) throws -> (groupState: GroupState, welcomeMessages: [Hex: WelcomeMessage]) {
        let creatorPublicKey = try MLSTree.getPublicKey(creatorPrivateKey)
        let allMembers = [creatorPublicKey] + initialMembers
        let numMembersNeeded = allMembers.count
        
        // Create tree with enough leaves
        var tree = MLSTree.createEmptyTree(max(numMembersNeeded, 2))
        
        // Set creator at position 0
        tree = MLSTree.setLeaf(tree, position: 0, publicKey: creatorPublicKey)
        
        // Add initial members
        for i in 0..<initialMembers.count {
            tree = MLSTree.setLeaf(tree, position: i + 1, publicKey: initialMembers[i])
        }
        
        // Update path from creator
        let (updatedTree, pathSecrets, groupKey) = try MLSTree.updatePath(
            tree,
            myLeafPosition: 0,
            myPrivateKey: creatorPrivateKey
        )
        
        let groupId = generateGroupId()
        
        let groupState = GroupState(
            groupId: groupId,
            epoch: 0,
            tree: updatedTree,
            myLeafIndex: 0,
            myPrivateKey: creatorPrivateKey,
            pathSecrets: pathSecrets,
            groupKey: groupKey
        )
        
        // Generate welcome messages for initial members
        var welcomeMessages: [Hex: WelcomeMessage] = [:]
        
        for memberPubKey in initialMembers {
            let welcome = try createWelcomeMessage(groupState, newMemberPublicKey: memberPubKey)
            welcomeMessages[memberPubKey] = welcome
        }
        
        return (groupState: groupState, welcomeMessages: welcomeMessages)
    }
    
    // MARK: - Welcome Messages
    
    /// Create a welcome message for a new member
    public static func createWelcomeMessage(
        _ groupState: GroupState,
        newMemberPublicKey: Hex
    ) throws -> WelcomeMessage {
        // Find the leaf index for the new member
        let leafIndex = MLSTree.findLeafByPublicKey(groupState.tree, publicKey: newMemberPublicKey)
        
        // Create a Codable state struct for proper serialization
        struct WelcomeGroupState: Codable {
            let groupId: String
            let epoch: Int
            let tree: [TreeNode]
            let myLeafIndex: Int
        }
        
        let welcomeState = WelcomeGroupState(
            groupId: groupState.groupId,
            epoch: groupState.epoch,
            tree: groupState.tree,
            myLeafIndex: leafIndex ?? -1
        )
        
        let encoder = JSONEncoder()
        let stateJson = try encoder.encode(welcomeState)
        guard let stateString = String(data: stateJson, encoding: .utf8) else {
            throw MLSError.encryptionFailed("Failed to serialize group state")
        }
        
        // Encrypt with new member's public key using ECIES
        let encryptedState = try Cryptograph.encryptForPublicKey(stateString, recipientPublicKey: newMemberPublicKey)
        
        // Encrypt path secrets
        let pathSecretsJson = try encoder.encode(groupState.pathSecrets)
        guard let pathSecretsString = String(data: pathSecretsJson, encoding: .utf8) else {
            throw MLSError.encryptionFailed("Failed to serialize path secrets")
        }
        
        let encryptedPathSecrets = try Cryptograph.encryptForPublicKey(pathSecretsString, recipientPublicKey: newMemberPublicKey)
        
        return WelcomeMessage(
            groupId: groupState.groupId,
            epoch: groupState.epoch,
            groupState: EncryptedGroupState(ciphertext: encryptedState.ciphertext),
            pathSecrets: EncryptedPathSecrets(ciphertext: encryptedPathSecrets.ciphertext)
        )
    }
    
    /// Process a welcome message to join a group
    public static func processWelcomeMessage(
        _ welcome: WelcomeMessage,
        myPrivateKey: Hex
    ) throws -> GroupState {
        // Decrypt group state
        let decryptedState = try Cryptograph.decryptWithPrivateKey(
            EncryptedPayload(ciphertext: welcome.groupState.ciphertext),
            privateKey: myPrivateKey
        )
        
        // Use Codable struct for proper deserialization
        struct WelcomeGroupState: Codable {
            let groupId: String
            let epoch: Int
            let tree: [TreeNode]
            let myLeafIndex: Int
        }
        
        let decoder = JSONDecoder()
        guard let stateData = decryptedState.data(using: .utf8) else {
            throw MLSError.decryptionFailed("Failed to parse group state")
        }
        
        let parsedState = try decoder.decode(WelcomeGroupState.self, from: stateData)
        
        // Decrypt path secrets
        let decryptedPathSecrets = try Cryptograph.decryptWithPrivateKey(
            EncryptedPayload(ciphertext: welcome.pathSecrets.ciphertext),
            privateKey: myPrivateKey
        )
        
        guard let pathSecretsData = decryptedPathSecrets.data(using: .utf8) else {
            throw MLSError.decryptionFailed("Failed to parse path secrets")
        }
        let pathSecrets: [Hex] = try decoder.decode([Hex].self, from: pathSecretsData)
        
        // Derive group key from root path secret
        guard let rootSecret = Data(hex: pathSecrets[pathSecrets.count - 1]) else {
            throw MLSError.keyDerivationFailed("Invalid root secret")
        }
        let groupKey = MLSHKDF.deriveGroupKey(rootSecret)
        
        let groupId = parsedState.groupId
        let epoch = parsedState.epoch
        let tree = parsedState.tree
        let myLeafIndex = parsedState.myLeafIndex
        
        return GroupState(
            groupId: groupId,
            epoch: epoch,
            tree: tree,
            myLeafIndex: myLeafIndex,
            myPrivateKey: myPrivateKey,
            pathSecrets: pathSecrets,
            groupKey: groupKey
        )
    }
    
    // MARK: - Member Management
    
    /// Add a member to the group
    public static func addMember(
        _ groupState: GroupState,
        newMemberPublicKey: Hex
    ) throws -> (groupState: GroupState, addMessage: AddMessage, welcomeMessage: WelcomeMessage) {
        // Find available slot
        var newTree = groupState.tree
        var newLeafPosition = MLSTree.findAvailableSlot(newTree)
        
        // If no available slot, extend the tree
        if newLeafPosition == nil {
            let currentLeaves = MLSTree.numLeaves(newTree)
            let newNumLeaves = currentLeaves + 1
            let newSize = MLSTree.treeSize(newNumLeaves)
            
            // Extend tree
            while newTree.count < newSize {
                if (newTree.count % 2) == 0 {
                    newTree.append(.leaf(node: nil))
                } else {
                    newTree.append(.parent(node: ParentNode(publicKey: nil, unmergedLeaves: [])))
                }
            }
            
            newLeafPosition = currentLeaves
        }
        
        guard let leafPosition = newLeafPosition else {
            throw MLSError.invalidTree("Could not find slot for new member")
        }
        
        // Set the new member's leaf
        newTree = MLSTree.setLeaf(newTree, position: leafPosition, publicKey: newMemberPublicKey)
        
        // Generate new private key and update path
        let newKeyPair = try MLSTree.generateKeyPair()
        let (updatePathMsg, updatedTree, pathSecrets, groupKey) = try MLSTree.generateUpdatePath(
            newTree,
            myLeafPosition: groupState.myLeafIndex,
            newPrivateKey: newKeyPair.privateKey
        )
        
        let newEpoch = groupState.epoch + 1
        
        var newGroupState = groupState
        newGroupState.epoch = newEpoch
        newGroupState.tree = updatedTree
        newGroupState.myPrivateKey = newKeyPair.privateKey
        newGroupState.pathSecrets = pathSecrets
        newGroupState.groupKey = groupKey
        
        let addMessage = AddMessage(
            groupId: groupState.groupId,
            epoch: newEpoch,
            leafIndex: leafPosition,
            publicKey: newMemberPublicKey,
            updatePath: updatePathMsg
        )
        
        let welcomeMessage = try createWelcomeMessage(newGroupState, newMemberPublicKey: newMemberPublicKey)
        
        return (groupState: newGroupState, addMessage: addMessage, welcomeMessage: welcomeMessage)
    }
    
    /// Process an add message from another member
    public static func processAddMessage(
        _ groupState: GroupState,
        addMessage: AddMessage
    ) throws -> GroupState {
        guard addMessage.epoch == groupState.epoch + 1 else {
            throw MLSError.invalidEpoch("Expected epoch \(groupState.epoch + 1), got \(addMessage.epoch)")
        }
        
        // Add the new member to the tree
        var newTree = groupState.tree
        
        // Extend tree if needed
        let neededSize = MLSTree.treeSize(addMessage.leafIndex + 1)
        while newTree.count < neededSize {
            if (newTree.count % 2) == 0 {
                newTree.append(.leaf(node: nil))
            } else {
                newTree.append(.parent(node: ParentNode(publicKey: nil, unmergedLeaves: [])))
            }
        }
        
        newTree = MLSTree.setLeaf(newTree, position: addMessage.leafIndex, publicKey: addMessage.publicKey)
        
        // Process the update path
        let senderPosition = addMessage.updatePath.leafNode.index
        let (updatedTree, groupKey) = try MLSTree.processUpdatePath(
            newTree,
            senderLeafPosition: senderPosition,
            updatePathMsg: addMessage.updatePath,
            myLeafPosition: groupState.myLeafIndex,
            myPrivateKey: groupState.myPrivateKey
        )
        
        var newGroupState = groupState
        newGroupState.epoch = addMessage.epoch
        newGroupState.tree = updatedTree
        newGroupState.groupKey = groupKey
        
        return newGroupState
    }
    
    /// Remove a member from the group
    public static func removeMember(
        _ groupState: GroupState,
        memberPublicKey: Hex
    ) throws -> (groupState: GroupState, removeMessage: RemoveMessage) {
        guard let leafPosition = MLSTree.findLeafByPublicKey(groupState.tree, publicKey: memberPublicKey) else {
            throw MLSError.memberNotFound("Member not found in group")
        }
        
        guard leafPosition != groupState.myLeafIndex else {
            throw MLSError.invalidMessage("Cannot remove yourself")
        }
        
        // Remove the member
        let newTree = MLSTree.removeLeaf(groupState.tree, position: leafPosition)
        
        // Generate new private key and update path
        let newKeyPair = try MLSTree.generateKeyPair()
        let (updatePathMsg, updatedTree, pathSecrets, groupKey) = try MLSTree.generateUpdatePath(
            newTree,
            myLeafPosition: groupState.myLeafIndex,
            newPrivateKey: newKeyPair.privateKey
        )
        
        let newEpoch = groupState.epoch + 1
        
        var newGroupState = groupState
        newGroupState.epoch = newEpoch
        newGroupState.tree = updatedTree
        newGroupState.myPrivateKey = newKeyPair.privateKey
        newGroupState.pathSecrets = pathSecrets
        newGroupState.groupKey = groupKey
        
        let removeMessage = RemoveMessage(
            groupId: groupState.groupId,
            epoch: newEpoch,
            leafIndex: leafPosition,
            updatePath: updatePathMsg
        )
        
        return (groupState: newGroupState, removeMessage: removeMessage)
    }
    
    /// Process a remove message
    public static func processRemoveMessage(
        _ groupState: GroupState,
        removeMessage: RemoveMessage
    ) throws -> GroupState {
        guard removeMessage.epoch == groupState.epoch + 1 else {
            throw MLSError.invalidEpoch("Expected epoch \(groupState.epoch + 1), got \(removeMessage.epoch)")
        }
        
        // Check if we're the one being removed
        guard removeMessage.leafIndex != groupState.myLeafIndex else {
            throw MLSError.notAMember("You have been removed from the group")
        }
        
        // Remove the member
        let newTree = MLSTree.removeLeaf(groupState.tree, position: removeMessage.leafIndex)
        
        // Process the update path
        let senderPosition = removeMessage.updatePath.leafNode.index
        let (updatedTree, groupKey) = try MLSTree.processUpdatePath(
            newTree,
            senderLeafPosition: senderPosition,
            updatePathMsg: removeMessage.updatePath,
            myLeafPosition: groupState.myLeafIndex,
            myPrivateKey: groupState.myPrivateKey
        )
        
        var newGroupState = groupState
        newGroupState.epoch = removeMessage.epoch
        newGroupState.tree = updatedTree
        newGroupState.groupKey = groupKey
        
        return newGroupState
    }
    
    // MARK: - Key Updates
    
    /// Update own key (for forward secrecy)
    public static func updateOwnKey(
        _ groupState: GroupState
    ) throws -> (groupState: GroupState, updateMessage: UpdateMessage) {
        // Generate new private key and update path
        let newKeyPair = try MLSTree.generateKeyPair()
        let (updatePathMsg, updatedTree, pathSecrets, groupKey) = try MLSTree.generateUpdatePath(
            groupState.tree,
            myLeafPosition: groupState.myLeafIndex,
            newPrivateKey: newKeyPair.privateKey
        )
        
        let newEpoch = groupState.epoch + 1
        
        var newGroupState = groupState
        newGroupState.epoch = newEpoch
        newGroupState.tree = updatedTree
        newGroupState.myPrivateKey = newKeyPair.privateKey
        newGroupState.pathSecrets = pathSecrets
        newGroupState.groupKey = groupKey
        
        let updateMessage = UpdateMessage(
            groupId: groupState.groupId,
            epoch: newEpoch,
            leafIndex: groupState.myLeafIndex,
            updatePath: updatePathMsg
        )
        
        return (groupState: newGroupState, updateMessage: updateMessage)
    }
    
    /// Process an update message
    public static func processUpdateMessage(
        _ groupState: GroupState,
        updateMessage: UpdateMessage
    ) throws -> GroupState {
        guard updateMessage.epoch == groupState.epoch + 1 else {
            throw MLSError.invalidEpoch("Expected epoch \(groupState.epoch + 1), got \(updateMessage.epoch)")
        }
        
        let senderPosition = updateMessage.leafIndex
        let (updatedTree, groupKey) = try MLSTree.processUpdatePath(
            groupState.tree,
            senderLeafPosition: senderPosition,
            updatePathMsg: updateMessage.updatePath,
            myLeafPosition: groupState.myLeafIndex,
            myPrivateKey: groupState.myPrivateKey
        )
        
        var newGroupState = groupState
        newGroupState.epoch = updateMessage.epoch
        newGroupState.tree = updatedTree
        newGroupState.groupKey = groupKey
        
        return newGroupState
    }
    
    // MARK: - Application Messages (AES-256-GCM)
    
    /// Encrypt an application message
    /// Format: iv (12 bytes) + tag (16 bytes) + ciphertext
    public static func encryptApplicationMessage(
        _ groupState: GroupState,
        plaintext: String
    ) throws -> ApplicationMessage {
        guard let keyData = Data(hex: groupState.groupKey) else {
            throw MLSError.encryptionFailed("Invalid group key")
        }
        
        let symmetricKey = SymmetricKey(data: keyData)
        let iv = MLSHKDF.generateRandomSecret(length: 12)
        
        guard let plaintextData = plaintext.data(using: .utf8) else {
            throw MLSError.encryptionFailed("Failed to encode plaintext")
        }
        
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.seal(plaintextData, using: symmetricKey, nonce: nonce)
        
        // Combine iv + authTag + ciphertext (must match TypeScript format)
        var combined = Data()
        combined.append(iv)              // 12 bytes
        combined.append(sealedBox.tag)   // 16 bytes
        combined.append(sealedBox.ciphertext)
        
        return ApplicationMessage(
            groupId: groupState.groupId,
            epoch: groupState.epoch,
            ciphertext: combined.base64EncodedString(),
            senderLeafIndex: groupState.myLeafIndex
        )
    }
    
    /// Decrypt an application message
    public static func decryptApplicationMessage(
        _ groupState: GroupState,
        message: ApplicationMessage
    ) throws -> (plaintext: String, senderPublicKey: Hex) {
        guard message.epoch == groupState.epoch else {
            throw MLSError.invalidEpoch("Message epoch \(message.epoch) doesn't match group epoch \(groupState.epoch)")
        }
        
        // Verify sender is a member
        let senderLeafIndex = message.senderLeafIndex * 2  // Convert position to tree index
        guard senderLeafIndex < groupState.tree.count else {
            throw MLSError.memberNotFound("Sender leaf index out of bounds")
        }
        
        let senderLeaf = groupState.tree[senderLeafIndex]
        guard case .leaf(let node) = senderLeaf, let leafNode = node else {
            throw MLSError.memberNotFound("Sender not found in group")
        }
        
        guard let combined = Data(base64Encoded: message.ciphertext),
              combined.count >= 28 else {  // 12 + 16 + at least 0 bytes
            throw MLSError.decryptionFailed("Invalid ciphertext format")
        }
        
        let iv = combined.prefix(12)
        let tag = combined.dropFirst(12).prefix(16)
        let ciphertext = combined.dropFirst(28)
        
        guard let keyData = Data(hex: groupState.groupKey) else {
            throw MLSError.decryptionFailed("Invalid group key")
        }
        
        let symmetricKey = SymmetricKey(data: keyData)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
        
        guard let plaintext = String(data: decrypted, encoding: .utf8) else {
            throw MLSError.decryptionFailed("Invalid UTF-8 in decrypted data")
        }
        
        return (plaintext: plaintext, senderPublicKey: leafNode.publicKey)
    }
    
    // MARK: - Message Processing
    
    /// Process any MLS message
    public static func processMessage(
        _ groupState: GroupState,
        message: MLSMessage
    ) throws -> GroupState {
        switch message {
        case .add(let addMessage):
            guard addMessage.groupId == groupState.groupId else {
                throw MLSError.invalidMessage("Message is for a different group")
            }
            return try processAddMessage(groupState, addMessage: addMessage)
            
        case .remove(let removeMessage):
            guard removeMessage.groupId == groupState.groupId else {
                throw MLSError.invalidMessage("Message is for a different group")
            }
            return try processRemoveMessage(groupState, removeMessage: removeMessage)
            
        case .update(let updateMessage):
            guard updateMessage.groupId == groupState.groupId else {
                throw MLSError.invalidMessage("Message is for a different group")
            }
            return try processUpdateMessage(groupState, updateMessage: updateMessage)
            
        case .application:
            // Application messages don't change state
            return groupState
            
        case .welcome:
            throw MLSError.invalidMessage("Use processWelcomeMessage for welcome messages")
        }
    }
    
    // MARK: - Utilities
    
    /// Get group members
    public static func getGroupMembers(_ groupState: GroupState) -> [(position: Int, publicKey: Hex)] {
        MLSTree.getMembers(groupState.tree)
    }
    
    /// Check if a public key is in the group
    public static func isGroupMember(_ groupState: GroupState, publicKey: Hex) -> Bool {
        MLSTree.isMember(groupState.tree, publicKey: publicKey)
    }
    
    /// Check if an address is in the group
    public static func isGroupMemberByAddress(_ groupState: GroupState, address: Hex) -> Bool {
        MLSTree.isMemberByAddress(groupState.tree, address: address)
    }
    
    /// Serialize group state for storage
    public static func serializeGroupState(_ groupState: GroupState) throws -> String {
        let encoder = JSONEncoder()
        let data = try encoder.encode(groupState)
        guard let string = String(data: data, encoding: .utf8) else {
            throw MLSError.encryptionFailed("Failed to serialize group state")
        }
        return string
    }
    
    /// Deserialize group state
    public static func deserializeGroupState(_ serialized: String) throws -> GroupState {
        guard let data = serialized.data(using: .utf8) else {
            throw MLSError.decryptionFailed("Invalid serialized state")
        }
        let decoder = JSONDecoder()
        return try decoder.decode(GroupState.self, from: data)
    }
    
    // MARK: - Low-Level Encryption (for compatibility testing)
    
    /// Encrypt plaintext with a group key, returning hex-encoded ciphertext
    /// Format: iv (12 bytes) + tag (16 bytes) + ciphertext
    /// This matches the server's AES-256-GCM format
    public static func encryptWithGroupKey(_ plaintext: String, groupKey: Hex) throws -> Hex {
        guard let keyData = Data(hex: groupKey) else {
            throw MLSError.encryptionFailed("Invalid group key")
        }
        
        let symmetricKey = SymmetricKey(data: keyData)
        let iv = MLSHKDF.generateRandomSecret(length: 12)
        
        guard let plaintextData = plaintext.data(using: .utf8) else {
            throw MLSError.encryptionFailed("Failed to encode plaintext")
        }
        
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.seal(plaintextData, using: symmetricKey, nonce: nonce)
        
        // Combine iv + authTag + ciphertext (must match server format)
        var combined = Data()
        combined.append(iv)                // 12 bytes
        combined.append(sealedBox.tag)     // 16 bytes
        combined.append(sealedBox.ciphertext)
        
        return MLSHKDF.dataToHex(combined)
    }
    
    /// Decrypt hex-encoded ciphertext with a group key
    /// Expects format: iv (12 bytes) + tag (16 bytes) + ciphertext
    public static func decryptWithGroupKey(_ ciphertext: Hex, groupKey: Hex) throws -> String {
        guard let combined = Data(hex: ciphertext),
              combined.count >= 28 else {  // 12 + 16 + at least 0 bytes
            throw MLSError.decryptionFailed("Invalid ciphertext format")
        }
        
        let iv = combined.prefix(12)
        let tag = combined.dropFirst(12).prefix(16)
        let encryptedData = combined.dropFirst(28)
        
        guard let keyData = Data(hex: groupKey) else {
            throw MLSError.decryptionFailed("Invalid group key")
        }
        
        let symmetricKey = SymmetricKey(data: keyData)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedData, tag: tag)
        
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
        
        guard let plaintext = String(data: decrypted, encoding: .utf8) else {
            throw MLSError.decryptionFailed("Invalid UTF-8 in decrypted data")
        }
        
        return plaintext
    }
}
