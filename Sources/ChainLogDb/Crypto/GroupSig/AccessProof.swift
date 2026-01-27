//
//  AccessProof.swift
//  ChainKeys
//
//  HMAC-based Epoch Access Proofs
//  Uses CryptoKit for HMAC-SHA256 and HKDF
//
//  Access proofs provide:
//  - Fast verification (HMAC is cheaper than full ZK proof)
//  - Epoch binding (proofs only valid for specific epoch)
//  - Forward secrecy (old keys don't help with new epochs)
//

import Foundation
import CryptoKit

// MARK: - Access Proof Functions

public enum AccessProofUtils {
    
    // MARK: - Epoch Access Key Derivation
    
    /// Derive epoch access key from MLS group key
    /// Formula: HKDF(groupKey + "server-access" + groupId + epoch)
    public static func deriveEpochAccessKey(
        groupKey: Hex,
        groupId: String,
        epoch: Int
    ) -> EpochAccessKey {
        guard let groupKeyData = Data(hex: groupKey) else {
            // Return empty key on invalid input
            return EpochAccessKey(key: "0x" + String(repeating: "0", count: 64), epoch: epoch)
        }
        
        // Build input: groupKey + "server-access" + groupId + epoch (4 bytes little-endian)
        var input = Data()
        input.append(groupKeyData)
        input.append(Data("server-access".utf8))
        input.append(Data(groupId.utf8))
        
        // Epoch as 4 bytes little-endian (matching TypeScript)
        let epochUInt = UInt32(epoch)
        input.append(UInt8(epochUInt & 0xff))
        input.append(UInt8((epochUInt >> 8) & 0xff))
        input.append(UInt8((epochUInt >> 16) & 0xff))
        input.append(UInt8((epochUInt >> 24) & 0xff))
        
        // HKDF with empty salt and info
        let derivedKey = hkdf(input: input, length: 32)
        
        return EpochAccessKey(key: derivedKey.hexString, epoch: epoch)
    }
    
    // MARK: - Access Proof Creation
    
    /// Create HMAC-based access proof for server verification
    /// Formula: HMAC-SHA256(accessKey, entryHash)
    public static func createAccessProof(
        accessKey: EpochAccessKey,
        entryHash: String
    ) -> AccessProof {
        guard let keyData = Data(hex: accessKey.key) else {
            return AccessProof(proof: "0x" + String(repeating: "0", count: 64), epoch: accessKey.epoch)
        }
        
        let symmetricKey = SymmetricKey(data: keyData)
        let hashData = Data(entryHash.utf8)
        
        let hmac = HMAC<SHA256>.authenticationCode(for: hashData, using: symmetricKey)
        let proofData = Data(hmac)
        
        return AccessProof(proof: proofData.hexString, epoch: accessKey.epoch)
    }
    
    // MARK: - Access Proof Verification
    
    /// Verify an access proof (server-side verification)
    public static func verifyAccessProof(
        accessProof: AccessProof,
        entryHash: String,
        epochAccessKey: Hex
    ) -> Bool {
        guard let keyData = Data(hex: epochAccessKey) else {
            return false
        }
        
        let symmetricKey = SymmetricKey(data: keyData)
        let hashData = Data(entryHash.utf8)
        
        let expectedHmac = HMAC<SHA256>.authenticationCode(for: hashData, using: symmetricKey)
        let expectedProof = Data(expectedHmac).hexString
        
        return expectedProof.lowercased() == accessProof.proof.lowercased()
    }
    
    // MARK: - Epoch Transition Proof
    
    /// Create epoch transition proof
    /// Proves knowledge of old key when transitioning to new key
    /// Formula: HMAC(oldAccessKey, newAccessKey)
    public static func createEpochTransitionProof(
        oldAccessKey: EpochAccessKey,
        newAccessKey: EpochAccessKey
    ) -> EpochTransitionProof {
        guard let oldKeyData = Data(hex: oldAccessKey.key),
              let newKeyData = Data(hex: newAccessKey.key) else {
            return EpochTransitionProof(
                oldEpoch: oldAccessKey.epoch,
                newEpoch: newAccessKey.epoch,
                newAccessKey: newAccessKey.key,
                transitionProof: "0x" + String(repeating: "0", count: 64)
            )
        }
        
        let symmetricKey = SymmetricKey(data: oldKeyData)
        let hmac = HMAC<SHA256>.authenticationCode(for: newKeyData, using: symmetricKey)
        let proofData = Data(hmac)
        
        return EpochTransitionProof(
            oldEpoch: oldAccessKey.epoch,
            newEpoch: newAccessKey.epoch,
            newAccessKey: newAccessKey.key,
            transitionProof: proofData.hexString
        )
    }
    
    /// Verify epoch transition proof (server-side)
    public static func verifyEpochTransitionProof(
        transitionProof: EpochTransitionProof,
        currentEpochAccessKey: Hex
    ) -> Bool {
        guard let currentKeyData = Data(hex: currentEpochAccessKey),
              let newKeyData = Data(hex: transitionProof.newAccessKey) else {
            return false
        }
        
        let symmetricKey = SymmetricKey(data: currentKeyData)
        let expectedHmac = HMAC<SHA256>.authenticationCode(for: newKeyData, using: symmetricKey)
        let expectedProof = Data(expectedHmac).hexString
        
        return expectedProof.lowercased() == transitionProof.transitionProof.lowercased()
    }
    
    // MARK: - Private Helpers
    
    /// HKDF (HMAC-based Key Derivation Function)
    private static func hkdf(input: Data, length: Int) -> Data {
        let inputKey = SymmetricKey(data: input)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: Data(),
            info: Data(),
            outputByteCount: length
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }
}
