//
//  MLSTree.swift
//  ChainKeys
//
//  MLS Binary Tree Operations
//  Uses left-balanced binary tree represented as an array (heap-style)
//
//  Index calculations must match TypeScript exactly:
//  - Leaves are at even indices (0, 2, 4...)
//  - Parents are at odd indices (1, 3, 5...)
//

import Foundation
import CryptoKit
import K1

// MARK: - Tree Index Calculations

public enum MLSTree {
    
    // MARK: - Index Calculations
    
    /// Check if an index is a leaf node (even index)
    public static func isLeaf(_ index: Int) -> Bool {
        index % 2 == 0
    }
    
    /// Convert leaf position (0, 1, 2...) to tree index (0, 2, 4...)
    public static func leafIndex(_ leafPosition: Int) -> Int {
        leafPosition * 2
    }
    
    /// Convert tree index to leaf position
    public static func leafPosition(_ index: Int) -> Int {
        index / 2
    }
    
    /// Calculate level of a node (0 for leaves)
    public static func nodeLevel(_ index: Int) -> Int {
        guard index >= 0 else { return 0 }
        var level = 0
        var i = index
        while (i & 1) == 1 {
            i >>= 1
            level += 1
        }
        return level
    }
    
    /// Calculate position of node at its level
    public static func nodePosition(_ index: Int, level: Int) -> Int {
        guard level >= 0, level < 62 else { return 0 }  // Prevent overflow
        return index >> (level + 1)
    }
    
    /// Get parent index
    /// For a left-balanced binary tree:
    /// - Leaves 0,2 -> parent 1
    /// - Leaves 4,6 -> parent 5  
    /// - Parents 1,5 -> parent 3
    public static func parent(_ index: Int) -> Int {
        guard index >= 0 else { return 0 }
        
        let level = nodeLevel(index)
        
        // Prevent overflow for very deep trees
        guard level < 60 else { return index }
        
        // At level L, nodes are at positions: (2k+1) * 2^L - 1 for k = 0, 1, 2, ...
        // Parent at level L+1 groups pairs of children
        
        // Calculate using safer arithmetic
        let levelPlus1 = level + 1
        let levelPlus2 = level + 2
        
        // Position at current level
        let pos = index >> levelPlus1
        
        // Parent position at parent level
        let parentPos = pos >> 1
        
        // Parent index = parentPos * 2^(level+2) + 2^(level+1) - 1
        //              = (parentPos << (level+2)) + (1 << (level+1)) - 1
        //              = (parentPos << (level+2)) | ((1 << (level+1)) - 1) when parentPos is 0
        
        // Use overflow-safe multiplication where possible
        let parentOffset = 1 << levelPlus1
        let parentSpacing = 1 << levelPlus2
        
        return parentPos * parentSpacing + parentOffset - 1
    }
    
    /// Get left child index
    public static func leftChild(_ index: Int) -> Int {
        if isLeaf(index) { return index } // leaves have no children
        let level = nodeLevel(index)
        if level == 0 { return index } // safety check
        return index - (1 << (level - 1))
    }
    
    /// Get right child index
    public static func rightChild(_ index: Int) -> Int {
        if isLeaf(index) { return index }
        let level = nodeLevel(index)
        if level == 0 { return index } // safety check
        return index + (1 << (level - 1))
    }
    
    /// Get right child index, bounded by tree size
    /// Returns -1 if right child would be out of bounds
    public static func rightChildBounded(_ index: Int, treeSize: Int) -> Int {
        let rc = rightChild(index)
        if rc >= treeSize {
            return -1
        }
        return rc
    }
    
    /// Get sibling index
    public static func sibling(_ index: Int) -> Int {
        let p = parent(index)
        if leftChild(p) == index {
            return rightChild(p)
        }
        return leftChild(p)
    }
    
    /// Get sibling index bounded by tree size (returns -1 if no sibling)
    public static func siblingBounded(_ index: Int, treeSize: Int) -> Int {
        let p = parent(index)
        if p >= treeSize { return -1 }
        
        let lc = leftChild(p)
        let rc = rightChild(p)
        
        if lc == index {
            return rc < treeSize ? rc : -1
        }
        return lc < treeSize ? lc : -1
    }
    
    /// Calculate tree size (total nodes) for n leaves
    public static func treeSize(_ numLeaves: Int) -> Int {
        if numLeaves == 0 { return 0 }
        return 2 * numLeaves - 1
    }
    
    /// Calculate root index for a tree with n leaves
    /// For n leaves, the root is at index (2^ceil(log2(n))) - 1
    /// For a balanced tree: n=2 -> root=1, n=4 -> root=3, n=8 -> root=7
    public static func root(_ numLeaves: Int) -> Int {
        guard numLeaves > 0 else { return 0 }
        
        // Find the smallest power of 2 >= numLeaves
        var power = 1
        while power < numLeaves {
            power *= 2
        }
        
        // Root is at index power - 1
        return power - 1
    }
    
    /// Get the number of leaves in a tree
    public static func numLeaves(_ tree: [TreeNode]) -> Int {
        (tree.count + 1) / 2
    }
    
    // MARK: - Path Calculations
    
    /// Get direct path from a leaf to the root (inclusive)
    public static func directPath(_ leafIdx: Int, treeNumLeaves: Int) -> [Int] {
        guard treeNumLeaves > 0, leafIdx >= 0 else { return [] }
        
        var path = [leafIdx]
        var current = leafIdx
        let size = treeSize(treeNumLeaves)
        let rootIdx = root(treeNumLeaves)
        
        // Safety limit to prevent infinite loop
        var iterations = 0
        let maxIterations = 64  // log2(max tree size)
        
        while current != rootIdx && iterations < maxIterations {
            let p = parent(current)
            
            // If parent is same as current or out of bounds, we've reached the top
            if p == current || p >= size {
                break
            }
            
            current = p
            path.append(current)
            iterations += 1
        }
        
        return path
    }
    
    /// Get copath (siblings of nodes on direct path)
    /// Returns -1 for invalid/out-of-bounds siblings
    public static func coPath(_ leafIdx: Int, treeNumLeaves: Int) -> [Int] {
        let path = directPath(leafIdx, treeNumLeaves: treeNumLeaves)
        let size = treeSize(treeNumLeaves)
        // Exclude the root from direct path, get siblings with bounds checking
        // Note: returns -1 for invalid siblings - callers must handle this
        return path.dropLast().map { siblingBounded($0, treeSize: size) }
    }
    
    /// Get resolution of a node (leftmost non-blank descendant or the node itself if populated)
    public static func resolution(_ tree: [TreeNode], index: Int) -> [Int] {
        guard index >= 0, index < tree.count else { return [] }
        let node = tree[index]
        
        switch node {
        case .leaf(let leafNode):
            return leafNode != nil ? [index] : []
            
        case .parent(let parentNode):
            if parentNode.publicKey != nil {
                return [index]
            }
            
            // Blank parent - return resolution of children
            let left = leftChild(index)
            let right = rightChild(index)
            
            return resolution(tree, index: left) + resolution(tree, index: right)
        }
    }
    
    // MARK: - Tree Operations
    
    /// Create an empty tree with specified number of leaves
    public static func createEmptyTree(_ numLeaves: Int) -> [TreeNode] {
        let size = treeSize(numLeaves)
        var tree: [TreeNode] = []
        
        for i in 0..<size {
            if isLeaf(i) {
                tree.append(.leaf(node: nil))
            } else {
                tree.append(.parent(node: ParentNode(publicKey: nil, unmergedLeaves: [])))
            }
        }
        
        return tree
    }
    
    /// Set a leaf in the tree
    public static func setLeaf(_ tree: [TreeNode], position: Int, publicKey: Hex) -> [TreeNode] {
        var newTree = tree
        let idx = leafIndex(position)
        
        guard idx < newTree.count else { return newTree }
        
        newTree[idx] = .leaf(node: LeafNode(index: position, publicKey: publicKey))
        return newTree
    }
    
    /// Remove a leaf (blank it)
    public static func removeLeaf(_ tree: [TreeNode], position: Int) -> [TreeNode] {
        var newTree = tree
        let idx = leafIndex(position)
        
        guard idx < newTree.count else { return newTree }
        
        newTree[idx] = .leaf(node: nil)
        
        // Blank parent nodes up to root that have both children blank
        let nLeaves = numLeaves(tree)
        let path = directPath(idx, treeNumLeaves: nLeaves)
        
        for i in 1..<path.count {
            let parentIdx = path[i]
            let leftIdx = leftChild(parentIdx)
            let rightIdx = rightChild(parentIdx)
            
            // Skip if child indices are out of bounds
            guard leftIdx < newTree.count, rightIdx < newTree.count else { continue }
            
            let leftNode = newTree[leftIdx]
            let rightNode = newTree[rightIdx]
            
            let leftBlank: Bool
            let rightBlank: Bool
            
            switch leftNode {
            case .leaf(let node): leftBlank = node == nil
            case .parent(let node): leftBlank = node.publicKey == nil
            }
            
            switch rightNode {
            case .leaf(let node): rightBlank = node == nil
            case .parent(let node): rightBlank = node.publicKey == nil
            }
            
            if leftBlank && rightBlank {
                newTree[parentIdx] = .parent(node: ParentNode(publicKey: nil, unmergedLeaves: []))
            }
        }
        
        return newTree
    }
    
    // MARK: - Key Operations
    
    /// Generate a new key pair for MLS
    public static func generateKeyPair() throws -> (privateKey: Hex, publicKey: Hex) {
        let privateKey = K1.KeyAgreement.PrivateKey()
        let privateKeyHex = "0x" + privateKey.rawRepresentation.hexStringNoPrefix
        let publicKeyHex = "0x" + privateKey.publicKey.x963Representation.hexStringNoPrefix
        return (privateKey: privateKeyHex, publicKey: publicKeyHex)
    }
    
    /// Get public key from private key
    public static func getPublicKey(_ privateKey: Hex) throws -> Hex {
        guard let privateKeyData = Data(hex: privateKey) else {
            throw MLSError.keyDerivationFailed("Invalid private key hex")
        }
        let k1PrivateKey = try K1.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        return "0x" + k1PrivateKey.publicKey.x963Representation.hexStringNoPrefix
    }
    
    /// Compute ECDH shared secret
    public static func computeSharedSecret(_ myPrivateKey: Hex, theirPublicKey: Hex) throws -> Data {
        guard let privateKeyData = Data(hex: myPrivateKey),
              let publicKeyData = Data(hex: theirPublicKey) else {
            throw MLSError.keyDerivationFailed("Invalid key hex")
        }
        
        let k1PrivateKey = try K1.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        let k1PublicKey = try K1.KeyAgreement.PublicKey(x963Representation: publicKeyData)
        
        // Compute ECDH point (shared secret)
        let sharedPoint = try k1PrivateKey.ecdhPoint(with: k1PublicKey)
        return sharedPoint
    }
    
    // MARK: - Path Update Operations
    
    /// Calculate path secrets and update tree for a member
    public static func updatePath(
        _ tree: [TreeNode],
        myLeafPosition: Int,
        myPrivateKey: Hex
    ) throws -> (tree: [TreeNode], pathSecrets: [Hex], groupKey: Hex) {
        var newTree = tree
        let nLeaves = numLeaves(tree)
        let path = directPath(leafIndex(myLeafPosition), treeNumLeaves: nLeaves)
        let copath = coPath(leafIndex(myLeafPosition), treeNumLeaves: nLeaves)
        
        // Start with a random path secret at the leaf
        var currentSecret = MLSHKDF.generateRandomSecret()
        var pathSecrets: [Hex] = [MLSHKDF.dataToHex(currentSecret)]
        
        // Update each node on the path (skip the leaf itself)
        for i in 0..<(path.count - 1) {
            let nodeIdx = path[i + 1] // skip leaf, start at first parent
            guard nodeIdx >= 0, nodeIdx < newTree.count else { continue }
            
            // Get sibling index safely (may be -1 or copath may be shorter)
            let siblingIdx = i < copath.count ? copath[i] : -1
            
            // Derive new private key for this node
            let nodePrivKey = MLSHKDF.deriveNodePrivateKey(currentSecret)
            let nodePubKey = try getPublicKey(nodePrivKey)
            
            // Get sibling's public key for ECDH (if sibling exists and is populated)
            var siblingPubKey: Hex? = nil
            
            if siblingIdx >= 0, siblingIdx < newTree.count {
                let siblingNode = newTree[siblingIdx]
                switch siblingNode {
                case .leaf(let node):
                    siblingPubKey = node?.publicKey
                case .parent(let node):
                    siblingPubKey = node.publicKey
                }
            }
            
            if let sibPubKey = siblingPubKey {
                // Compute shared secret with sibling
                let sharedSecret = try computeSharedSecret(nodePrivKey, theirPublicKey: sibPubKey)
                let derivedKey = MLSHKDF.deriveNodeKey(sharedSecret)
                if let keyData = Data(hex: derivedKey) {
                    currentSecret = keyData
                }
            } else {
                // No sibling or sibling is blank, just derive from current secret
                currentSecret = MLSHKDF.derivePathSecret(currentSecret, nodeIndex: nodeIdx)
            }
            
            pathSecrets.append(MLSHKDF.dataToHex(currentSecret))
            
            // Update tree node
            newTree[nodeIdx] = .parent(node: ParentNode(publicKey: nodePubKey, unmergedLeaves: []))
        }
        
        // Derive group key from root secret
        let groupKey = MLSHKDF.deriveGroupKey(currentSecret)
        
        return (tree: newTree, pathSecrets: pathSecrets, groupKey: groupKey)
    }
    
    /// Generate update path message for distribution
    public static func generateUpdatePath(
        _ tree: [TreeNode],
        myLeafPosition: Int,
        newPrivateKey: Hex
    ) throws -> (updatePath: UpdatePath, tree: [TreeNode], pathSecrets: [Hex], groupKey: Hex) {
        let newPublicKey = try getPublicKey(newPrivateKey)
        let nLeaves = numLeaves(tree)
        let path = directPath(leafIndex(myLeafPosition), treeNumLeaves: nLeaves)
        let copath = coPath(leafIndex(myLeafPosition), treeNumLeaves: nLeaves)
        
        // Update tree and get path secrets
        let newTree = setLeaf(tree, position: myLeafPosition, publicKey: newPublicKey)
        let (updatedTree, pathSecrets, groupKey) = try updatePath(newTree, myLeafPosition: myLeafPosition, myPrivateKey: newPrivateKey)
        
        // Build update path nodes
        var nodes: [UpdatePathNode] = []
        
        for i in 1..<path.count {
            let nodeIdx = path[i]
            guard nodeIdx >= 0, nodeIdx < updatedTree.count else { continue }
            
            let node = updatedTree[nodeIdx]
            
            guard case .parent(let parentNode) = node, let publicKey = parentNode.publicKey else {
                throw MLSError.invalidTree("Node at index \(nodeIdx) is not a valid parent")
            }
            
            // Get resolution of copath node for encrypted secrets
            // Skip if copath index is invalid (-1) or out of bounds
            let copathIdx = (i - 1) < copath.count ? copath[i - 1] : -1
            let copathResolution = copathIdx >= 0 ? resolution(updatedTree, index: copathIdx) : []
            var encryptedPathSecret: [String] = []
            
            // Encrypt path secret for each resolution node
            for resNodeIdx in copathResolution {
                guard resNodeIdx >= 0, resNodeIdx < updatedTree.count else { continue }
                
                let resNode = updatedTree[resNodeIdx]
                var targetPubKey: Hex? = nil
                
                switch resNode {
                case .leaf(let leafNode):
                    targetPubKey = leafNode?.publicKey
                case .parent(let parentNode):
                    targetPubKey = parentNode.publicKey
                }
                
                if let pubKey = targetPubKey {
                    // Encrypt path secret for this node using ECIES
                    let encrypted = try encryptForPublicKey(pathSecrets[i], recipientPublicKey: pubKey)
                    encryptedPathSecret.append(encrypted)
                }
            }
            
            nodes.append(UpdatePathNode(publicKey: publicKey, encryptedPathSecret: encryptedPathSecret))
        }
        
        let updatePathMsg = UpdatePath(
            leafNode: LeafNode(index: myLeafPosition, publicKey: newPublicKey),
            nodes: nodes
        )
        
        return (updatePath: updatePathMsg, tree: updatedTree, pathSecrets: pathSecrets, groupKey: groupKey)
    }
    
    /// Process an update path from another member
    public static func processUpdatePath(
        _ tree: [TreeNode],
        senderLeafPosition: Int,
        updatePathMsg: UpdatePath,
        myLeafPosition: Int,
        myPrivateKey: Hex
    ) throws -> (tree: [TreeNode], groupKey: Hex) {
        var newTree = setLeaf(tree, position: senderLeafPosition, publicKey: updatePathMsg.leafNode.publicKey)
        let nLeaves = numLeaves(newTree)
        let senderPath = directPath(leafIndex(senderLeafPosition), treeNumLeaves: nLeaves)
        
        // Find where our path intersects with sender's path
        let myPath = directPath(leafIndex(myLeafPosition), treeNumLeaves: nLeaves)
        let myLeafIdx = leafIndex(myLeafPosition)
        let intersection = senderPath.first { idx in myPath.contains(idx) && idx != myLeafIdx }
        
        guard intersection != nil else {
            throw MLSError.invalidTree("No intersection found between paths")
        }
        
        // Update tree with new public keys from update path
        for i in 0..<updatePathMsg.nodes.count {
            // Check bounds for senderPath access
            guard (i + 1) < senderPath.count else { continue }
            let nodeIdx = senderPath[i + 1]
            
            // Check bounds for tree access
            guard nodeIdx >= 0, nodeIdx < newTree.count else { continue }
            
            newTree[nodeIdx] = .parent(node: ParentNode(
                publicKey: updatePathMsg.nodes[i].publicKey,
                unmergedLeaves: []
            ))
        }
        
        // Derive group key by computing up from our leaf
        let (_, _, groupKey) = try updatePath(newTree, myLeafPosition: myLeafPosition, myPrivateKey: myPrivateKey)
        
        return (tree: newTree, groupKey: groupKey)
    }
    
    // MARK: - Member Operations
    
    /// Get all non-blank leaf public keys
    public static func getMembers(_ tree: [TreeNode]) -> [(position: Int, publicKey: Hex)] {
        var members: [(position: Int, publicKey: Hex)] = []
        
        for i in 0..<tree.count {
            if isLeaf(i) {
                if case .leaf(let node) = tree[i], let leafNode = node {
                    members.append((position: leafNode.index, publicKey: leafNode.publicKey))
                }
            }
        }
        
        return members
    }
    
    /// Check if a public key is a member of the group
    public static func isMember(_ tree: [TreeNode], publicKey: Hex) -> Bool {
        let members = getMembers(tree)
        return members.contains { $0.publicKey.lowercased() == publicKey.lowercased() }
    }
    
    /// Find leaf position by public key
    public static func findLeafByPublicKey(_ tree: [TreeNode], publicKey: Hex) -> Int? {
        for i in 0..<tree.count {
            if isLeaf(i) {
                if case .leaf(let node) = tree[i], let leafNode = node {
                    if leafNode.publicKey.lowercased() == publicKey.lowercased() {
                        return leafNode.index
                    }
                }
            }
        }
        return nil
    }
    
    /// Find first available (blank) leaf slot
    public static func findAvailableSlot(_ tree: [TreeNode]) -> Int? {
        for i in 0..<tree.count {
            if isLeaf(i) {
                if case .leaf(let node) = tree[i], node == nil {
                    return leafPosition(i)
                }
            }
        }
        return nil
    }
    
    /// Find a member's public key by their Ethereum address
    public static func findPublicKeyByAddress(_ tree: [TreeNode], address: Hex) -> Hex? {
        let members = getMembers(tree)
        
        for member in members {
            // Derive address from public key and compare
            let memberAddress = Cryptograph.publicKeyToAddress(member.publicKey)
            if memberAddress.lowercased() == address.lowercased() {
                return member.publicKey
            }
        }
        return nil
    }
    
    /// Check if an address is a member of the group
    public static func isMemberByAddress(_ tree: [TreeNode], address: Hex) -> Bool {
        findPublicKeyByAddress(tree, address: address) != nil
    }
    
    // MARK: - Private Helper for ECIES encryption
    
    private static func encryptForPublicKey(_ data: Hex, recipientPublicKey: Hex) throws -> String {
        guard let dataBytes = Data(hex: data) else {
            throw MLSError.encryptionFailed("Invalid data hex")
        }
        
        // Use existing Cryptograph ECIES encryption
        let encrypted = try Cryptograph.encryptForPublicKey(
            dataBytes.base64EncodedString(),
            recipientPublicKey: recipientPublicKey
        )
        return encrypted.ciphertext
    }
}
