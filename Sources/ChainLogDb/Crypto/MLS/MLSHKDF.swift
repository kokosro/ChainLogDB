//
//  MLSHKDF.swift
//  ChainKeys
//
//  HKDF (HMAC-based Key Derivation Function) for MLS key derivation
//
//  Must produce byte-identical outputs to TypeScript implementation:
//  - Context strings: "mls-node-key", "mls-node-private-key", "mls-group-key", "mls-path-secret"
//

import Foundation
import CryptoKit

// MARK: - HKDF Operations

public enum MLSHKDF {
    
    // MARK: - Core HKDF Functions
    
    /// Full HKDF: Extract and Expand
    /// Matches Node.js crypto HKDF behavior
    public static func hkdf(
        inputKeyMaterial ikm: Data,
        length: Int,
        salt: Data = Data(),
        info: Data = Data()
    ) -> Data {
        let inputKey = SymmetricKey(data: ikm)
        let derivedKey = CryptoKit.HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: info,
            outputByteCount: length
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }
    
    /// Derive a key from a shared secret with a specific context
    public static func deriveKey(
        sharedSecret: Data,
        context: String,
        length: Int = 32
    ) -> Data {
        let info = Data(context.utf8)
        return hkdf(inputKeyMaterial: sharedSecret, length: length, salt: Data(), info: info)
    }
    
    // MARK: - MLS-specific Key Derivation
    
    /// Derive node key from shared secret between siblings
    /// Context: "mls-node-key"
    public static func deriveNodeKey(_ sharedSecret: Data) -> Hex {
        let key = deriveKey(sharedSecret: sharedSecret, context: "mls-node-key", length: 32)
        return "0x" + key.hexStringNoPrefix
    }
    
    /// Derive node private key for updating path
    /// Context: "mls-node-private-key"
    public static func deriveNodePrivateKey(_ pathSecret: Data) -> Hex {
        let key = deriveKey(sharedSecret: pathSecret, context: "mls-node-private-key", length: 32)
        return "0x" + key.hexStringNoPrefix
    }
    
    /// Derive group encryption key from root secret
    /// Context: "mls-group-key"
    public static func deriveGroupKey(_ rootSecret: Data) -> Hex {
        let key = deriveKey(sharedSecret: rootSecret, context: "mls-group-key", length: 32)
        return "0x" + key.hexStringNoPrefix
    }
    
    /// Derive welcome key for encrypting welcome messages
    /// Context: "mls-welcome-key" + newMemberPubKey
    public static func deriveWelcomeKey(groupKey: Data, newMemberPubKey: Hex) -> Hex {
        var info = Data("mls-welcome-key".utf8)
        if let pubKeyData = hexToData(newMemberPubKey) {
            info.append(pubKeyData)
        }
        let key = hkdf(inputKeyMaterial: groupKey, length: 32, salt: Data(), info: info)
        return "0x" + key.hexStringNoPrefix
    }
    
    /// Derive path secret for a node from parent path secret
    /// Context: "mls-path-secret" + nodeIndex (4 bytes, little-endian)
    public static func derivePathSecret(_ parentSecret: Data, nodeIndex: Int) -> Data {
        var info = Data("mls-path-secret".utf8)
        // Append node index as 4 bytes little-endian (matching TypeScript)
        let index = UInt32(nodeIndex)
        info.append(UInt8(index & 0xff))
        info.append(UInt8((index >> 8) & 0xff))
        info.append(UInt8((index >> 16) & 0xff))
        info.append(UInt8((index >> 24) & 0xff))
        
        return hkdf(inputKeyMaterial: parentSecret, length: 32, salt: Data(), info: info)
    }
    
    // MARK: - Random Generation
    
    /// Generate random bytes for secrets
    public static func generateRandomSecret(length: Int = 32) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        guard status == errSecSuccess else {
            // Fallback if secure random fails
            for i in 0..<length {
                bytes[i] = UInt8.random(in: 0...255)
            }
            return Data(bytes)
        }
        return Data(bytes)
    }
    
    // MARK: - Hex Conversion Utilities
    
    /// Convert hex string to Data
    public static func hexToData(_ hex: Hex) -> Data? {
        Data(hex: hex)
    }
    
    /// Convert Data to hex string with 0x prefix
    public static func dataToHex(_ data: Data) -> Hex {
        "0x" + data.hexStringNoPrefix
    }
}
