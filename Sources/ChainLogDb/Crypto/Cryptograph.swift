//
//  Cryptograph.swift
//  ChainKeys
//
//  Ethereum-compatible cryptography
//  - Key generation compatible with viem
//  - EIP-191 signing compatible with viem
//  - ECIES encryption compatible with eciesjs
//

import Foundation
import CryptoKit
import K1
import SwiftKeccak

// MARK: - Types

public struct KeyPair: Codable, Equatable, Sendable {
    public let privateKey: Hex
    public let publicKey: Hex
    public let address: Hex
    
    public init(privateKey: Hex, publicKey: Hex, address: Hex) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.address = address
    }
}

public struct SignedMessage: Codable, Equatable, Sendable {
    public let message: String
    public let signature: Hex
    public let address: Hex
    
    public init(message: String, signature: Hex, address: Hex) {
        self.message = message
        self.signature = signature
        self.address = address
    }
}

public struct EncryptedPayload: Codable, Equatable, Sendable {
    public let ciphertext: String // base64 encoded
    
    public init(ciphertext: String) {
        self.ciphertext = ciphertext
    }
}

// MARK: - Errors

public enum CryptoError: Error, LocalizedError {
    case invalidPrivateKey
    case invalidPublicKey
    case invalidSignature
    case encryptionFailed(String)
    case decryptionFailed(String)
    case keyDerivationFailed
    case invalidHex
    
    public var errorDescription: String? {
        switch self {
        case .invalidPrivateKey: return "Invalid private key"
        case .invalidPublicKey: return "Invalid public key"
        case .invalidSignature: return "Invalid signature"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        case .keyDerivationFailed: return "Key derivation failed"
        case .invalidHex: return "Invalid hex string"
        }
    }
}

// MARK: - Cryptograph

public enum Cryptograph {
    
    // MARK: - Key Generation
    
    /// Generate a new random key pair
    public static func generateKeyPair() throws -> KeyPair {
        let privateKey = K1.ECDSAWithKeyRecovery.PrivateKey()
        return try keyPairFromK1PrivateKey(privateKey)
    }
    
    /// Derive key pair from existing private key hex
    public static func privateKeyToKeys(_ privateKeyHex: Hex) throws -> KeyPair {
        var cleanHex = privateKeyHex
        if cleanHex.hasPrefix("0x") {
            cleanHex = String(cleanHex.dropFirst(2))
        }
        
        guard cleanHex.count == 64 else {
            throw CryptoError.invalidPrivateKey
        }
        
        guard let privateKeyData = Data(hex: cleanHex) else {
            throw CryptoError.invalidPrivateKey
        }
        
        let privateKey = try K1.ECDSAWithKeyRecovery.PrivateKey(rawRepresentation: privateKeyData)
        return try keyPairFromK1PrivateKey(privateKey)
    }
    
    private static func keyPairFromK1PrivateKey(_ privateKey: K1.ECDSAWithKeyRecovery.PrivateKey) throws -> KeyPair {
        let privateKeyHex = "0x" + privateKey.rawRepresentation.hexStringNoPrefix.lowercased()
        
        // Get uncompressed public key (65 bytes: 04 + x + y)
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.x963Representation // This is the uncompressed format
        let publicKeyHex = "0x" + publicKeyData.hexStringNoPrefix.lowercased()
        
        // Derive address: keccak256Hash(pubkey without 04 prefix)[12:]
        let pubKeyBytes = publicKeyData.dropFirst() // Remove 04 prefix
        let hash = keccak256Hash(Data(pubKeyBytes))
        let addressBytes = hash.suffix(20)
        let address = checksumAddress(addressBytes.hexStringNoPrefix)
        
        return KeyPair(
            privateKey: privateKeyHex,
            publicKey: publicKeyHex,
            address: address
        )
    }
    
    // MARK: - Signing (EIP-191)
    
    /// Sign a message using EIP-191 personal sign (identical to viem's signMessage)
    public static func signMessage(_ message: String, privateKey: Hex) throws -> SignedMessage {
        var cleanKey = privateKey
        if cleanKey.hasPrefix("0x") {
            cleanKey = String(cleanKey.dropFirst(2))
        }
        
        guard let privateKeyData = Data(hex: cleanKey) else {
            throw CryptoError.invalidPrivateKey
        }
        
        let k1PrivateKey = try K1.ECDSAWithKeyRecovery.PrivateKey(rawRepresentation: privateKeyData)
        
        // EIP-191 message prefix
        let prefix = "\u{19}Ethereum Signed Message:\n\(message.utf8.count)"
        let prefixedMessage = prefix + message
        
        // Hash the prefixed message with keccak256
        let messageHash = keccak256Hash(Data(prefixedMessage.utf8))
        
        // Sign with recoverable ECDSA (K1 will use the hashed data directly)
        let signature = try k1PrivateKey.signature(for: messageHash)
        
        // Get the compact representation which includes recovery ID
        let compactSig = try signature.compact()
        
        // Serialize as R || S || V format (Ethereum standard)
        var signatureData = compactSig.serialize(format: .rsv)
        // Add 27 to the last byte (recovery ID) for Ethereum compatibility
        signatureData[64] = signatureData[64] + 27
        
        let keyPair = try keyPairFromK1PrivateKey(k1PrivateKey)
        
        return SignedMessage(
            message: message,
            signature: "0x" + signatureData.hexStringNoPrefix.lowercased(),
            address: keyPair.address
        )
    }
    
    /// Verify a signed message
    public static func verifySignedMessage(_ signed: SignedMessage) throws -> Bool {
        try verifySignature(
            message: signed.message,
            signature: signed.signature,
            address: signed.address
        )
    }
    
    /// Verify signature against an address
    public static func verifySignature(message: String, signature: Hex, address: Hex) throws -> Bool {
        guard let signatureData = Data(hex: signature), signatureData.count == 65 else {
            throw CryptoError.invalidSignature
        }
        
        // EIP-191 message prefix
        let prefix = "\u{19}Ethereum Signed Message:\n\(message.utf8.count)"
        let prefixedMessage = prefix + message
        let messageHash = keccak256Hash(Data(prefixedMessage.utf8))
        
        // Normalize v value (Ethereum uses 27/28, K1 uses 0/1/2/3)
        var normalizedSignature = signatureData
        if normalizedSignature[64] >= 27 {
            normalizedSignature[64] = normalizedSignature[64] - 27
        }
        
        // Reconstruct recoverable signature using rsv format
        let compactSignature = try K1.ECDSAWithKeyRecovery.Signature.Compact(
            rawRepresentation: normalizedSignature,
            format: .rsv
        )
        let recoverableSignature = try K1.ECDSAWithKeyRecovery.Signature(compact: compactSignature)
        
        // Recover public key
        let recoveredPublicKey = try recoverableSignature.recoverPublicKey(message: messageHash)
        
        // Derive address from recovered public key
        let pubKeyBytes = recoveredPublicKey.x963Representation.dropFirst()
        let hash = keccak256Hash(Data(pubKeyBytes))
        let recoveredAddressBytes = hash.suffix(20)
        let recoveredAddress = checksumAddress(recoveredAddressBytes.hexStringNoPrefix)
        
        return recoveredAddress.lowercased() == address.lowercased()
    }
    
    // MARK: - ECIES Encryption (eciesjs compatible)
    
    /// Encrypt data for recipient's public key using ECIES (eciesjs compatible format)
    public static func encryptForPublicKey(_ data: String, recipientPublicKey: Hex) throws -> EncryptedPayload {
        guard let publicKeyData = Data(hex: recipientPublicKey), publicKeyData.count == 65 else {
            throw CryptoError.invalidPublicKey
        }
        
        let dataBytes = Data(data.utf8)
        
        // Parse recipient's public key
        let recipientPubKey = try K1.KeyAgreement.PublicKey(x963Representation: publicKeyData)
        
        // Generate ephemeral key pair
        let ephemeralPrivateKey = K1.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey
        let ephemeralPublicKeyData = ephemeralPublicKey.x963Representation
        
        // ECDH to derive shared point (full uncompressed point for eciesjs compatibility)
        let sharedPoint = try ephemeralPrivateKey.ecdhPoint(with: recipientPubKey)
        
        // eciesjs derives key from: ephemeralPublicKey || sharedPoint (both uncompressed)
        let derivedKey = deriveKeyForECIES(senderPoint: ephemeralPublicKeyData, sharedPoint: sharedPoint)
        
        // Generate random IV (16 bytes for AES-GCM)
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        
        // Encrypt with AES-256-GCM
        let symmetricKey = SymmetricKey(data: derivedKey.prefix(32))
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.seal(dataBytes, using: symmetricKey, nonce: nonce)
        
        // eciesjs format: ephemeralPublicKey (65) + iv (16) + tag (16) + ciphertext
        var encrypted = Data()
        encrypted.append(ephemeralPublicKeyData) // 65 bytes uncompressed
        encrypted.append(iv) // 16 bytes
        encrypted.append(sealedBox.tag) // 16 bytes
        encrypted.append(sealedBox.ciphertext) // variable
        
        return EncryptedPayload(ciphertext: encrypted.base64EncodedString())
    }
    
    /// Decrypt data with private key (eciesjs compatible format)
    public static func decryptWithPrivateKey(_ payload: EncryptedPayload, privateKey: Hex) throws -> String {
        guard let encrypted = Data(base64Encoded: payload.ciphertext) else {
            throw CryptoError.decryptionFailed("Invalid base64")
        }
        
        // Minimum size: 65 (pubkey) + 16 (iv) + 16 (tag) + 1 (min ciphertext)
        guard encrypted.count >= 98 else {
            throw CryptoError.decryptionFailed("Ciphertext too short")
        }
        
        guard let privateKeyData = Data(hex: privateKey) else {
            throw CryptoError.invalidPrivateKey
        }
        
        let k1PrivateKey = try K1.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        
        // Parse eciesjs format
        let ephemeralPublicKeyData = encrypted.prefix(65)
        let iv = encrypted.dropFirst(65).prefix(16)
        let tag = encrypted.dropFirst(81).prefix(16)
        let ciphertext = encrypted.dropFirst(97)
        
        // Parse ephemeral public key
        let ephemeralPubKey = try K1.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyData)
        
        // ECDH to derive shared point (full uncompressed point for eciesjs compatibility)
        let sharedPoint = try k1PrivateKey.ecdhPoint(with: ephemeralPubKey)
        
        // eciesjs derives key from: ephemeralPublicKey || sharedPoint (both uncompressed)
        let derivedKey = deriveKeyForECIES(senderPoint: Data(ephemeralPublicKeyData), sharedPoint: sharedPoint)
        
        // Decrypt with AES-256-GCM
        let symmetricKey = SymmetricKey(data: derivedKey.prefix(32))
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
        
        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw CryptoError.decryptionFailed("Invalid UTF-8")
        }
        
        return result
    }
    
    // MARK: - Combined Operations
    
    /// Sign then encrypt (proves authorship + confidentiality)
    public static func signAndEncrypt(
        _ data: String,
        senderPrivateKey: Hex,
        recipientPublicKey: Hex
    ) throws -> EncryptedPayload {
        let signed = try signMessage(data, privateKey: senderPrivateKey)
        let jsonData = try JSONEncoder().encode(signed)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw CryptoError.encryptionFailed("JSON encoding failed")
        }
        return try encryptForPublicKey(jsonString, recipientPublicKey: recipientPublicKey)
    }
    
    /// Decrypt then verify
    public static func decryptAndVerify(
        _ payload: EncryptedPayload,
        recipientPrivateKey: Hex,
        senderAddress: Hex
    ) throws -> (verified: Bool, data: String) {
        let decrypted = try decryptWithPrivateKey(payload, privateKey: recipientPrivateKey)
        
        guard let jsonData = decrypted.data(using: .utf8) else {
            throw CryptoError.decryptionFailed("Invalid UTF-8 in decrypted data")
        }
        
        let signed = try JSONDecoder().decode(SignedMessage.self, from: jsonData)
        
        guard signed.address.lowercased() == senderAddress.lowercased() else {
            return (false, signed.message)
        }
        
        let verified = try verifySignedMessage(signed)
        return (verified, signed.message)
    }
    
    // MARK: - Utilities
    
    /// Derive Ethereum address from public key
    /// Public key must be in uncompressed format (65 bytes with 04 prefix)
    public static func publicKeyToAddress(_ publicKey: Hex) -> Hex {
        var cleanKey = publicKey
        if cleanKey.hasPrefix("0x") {
            cleanKey = String(cleanKey.dropFirst(2))
        }
        
        guard let publicKeyData = Data(hex: cleanKey), publicKeyData.count == 65 else {
            // Return empty if invalid
            return "0x0000000000000000000000000000000000000000"
        }
        
        // Derive address: keccak256Hash(pubkey without 04 prefix)[12:]
        let pubKeyBytes = publicKeyData.dropFirst() // Remove 04 prefix
        let hash = keccak256Hash(Data(pubKeyBytes))
        let addressBytes = hash.suffix(20)
        return checksumAddress(addressBytes.hexStringNoPrefix)
    }
    
    /// Create keccak256 checksum hash
    public static func createChecksum(_ data: String) -> Hex {
        let hash = keccak256Hash(Data(data.utf8))
        return "0x" + hash.hexStringNoPrefix.lowercased()
    }
    
    /// Compute SHA256 hash of a string, returning hex without 0x prefix
    /// Used for chain log hash computation: SHA256(index:prevHash:content:nonce)
    public static func sha256Hash(_ data: String) -> String {
        let inputData = Data(data.utf8)
        let hash = SHA256.hash(data: inputData)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate random nonce for chain log entries
    public static func generateNonce(length: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Serialize key pair to JSON string
    public static func serializeKeyPair(_ keyPair: KeyPair) throws -> String {
        let data = try JSONEncoder().encode(keyPair)
        guard let string = String(data: data, encoding: .utf8) else {
            throw CryptoError.encryptionFailed("Failed to serialize")
        }
        return string
    }
    
    /// Deserialize key pair from JSON string
    public static func deserializeKeyPair(_ serialized: String) throws -> KeyPair {
        guard let data = serialized.data(using: .utf8) else {
            throw CryptoError.decryptionFailed("Invalid string")
        }
        return try JSONDecoder().decode(KeyPair.self, from: data)
    }
    
    // MARK: - Private Helpers
    
    /// Keccak256 hash using SwiftKeccak
    private static func keccak256Hash(_ data: Data) -> Data {
        return SwiftKeccak.keccak256(data)
    }
    
    /// Derive encryption key for ECIES using HKDF (eciesjs compatible)
    /// eciesjs uses: HKDF-SHA256(ephemeralPublicKey || sharedPoint) with no salt and no info
    private static func deriveKeyForECIES(senderPoint: Data, sharedPoint: Data) -> Data {
        // Concatenate sender point and shared point (eciesjs format)
        var master = Data()
        master.append(senderPoint)
        master.append(sharedPoint)
        
        // HKDF with SHA256, no salt, no info, 32 bytes output
        let inputKey = SymmetricKey(data: master)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: Data(),
            info: Data(),
            outputByteCount: 32
        )
        
        return derivedKey.withUnsafeBytes { Data($0) }
    }
    
    /// Apply EIP-55 checksum to address
    private static func checksumAddress(_ address: String) -> Hex {
        let lowercased = address.lowercased()
        let hash = keccak256Hash(Data(lowercased.utf8)).hexStringNoPrefix
        
        var result = "0x"
        for (i, char) in lowercased.enumerated() {
            if char.isHexDigit && char.isLetter {
                let hashChar = hash[hash.index(hash.startIndex, offsetBy: i)]
                if let hashValue = Int(String(hashChar), radix: 16), hashValue >= 8 {
                    result.append(char.uppercased())
                } else {
                    result.append(char)
                }
            } else {
                result.append(char)
            }
        }
        
        return result
    }
}
