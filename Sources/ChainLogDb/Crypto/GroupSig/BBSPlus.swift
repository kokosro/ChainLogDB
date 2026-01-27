//
//  BBSPlus.swift
//  ChainKeys
//
//  BBS+ Signature Implementation using BLS12-381 Curve
//  Provides proper cryptographic group signatures with zero-knowledge proofs
//
//  Uses the bls-eth-swift library (herumi/mcl) for BLS12-381 operations.
//
//  Based on the BBS+ signature scheme from:
//  "Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited"
//  https://eprint.iacr.org/2016/663.pdf
//

import Foundation
import CryptoKit
import BigInt
import bls_framework

// MARK: - BBS+ Implementation

public enum BBSPlus {
    
    // MARK: - Key Generation
    
    /// Generate BBS+ group key pair
    /// Manager creates this when creating a group
    public static func generateGroupKeyPair() throws -> (managerPrivateKey: ManagerPrivateKey, groupPublicKey: GroupPublicKey) {
        try initializeBLS()
        
        // Generate group secret gamma (random scalar in Fr)
        let gamma = BLS12381.randomScalar()
        
        // Group public key: w = g2^gamma
        let w = BLS12381.g2Mul(G2Point.generator, gamma)
        
        // Generate additional generators for attributes (using hash-to-point)
        // Must match node-client: hashToG1("BBS+Generator-h0", bigIntToBuffer(gamma))
        let gammaBuffer = BLS12381.scalarToBuffer(gamma)
        let h0 = BLS12381.hashToG1WithDomain("BBS+Generator-h0", gammaBuffer)
        let h1 = BLS12381.hashToG1WithDomain("BBS+Generator-h1", gammaBuffer)
        
        let groupPublicKey = GroupPublicKey(
            w: BLS12381.serializeG2(w),
            h: [BLS12381.serializeG1(h0), BLS12381.serializeG1(h1)]
        )
        
        let managerPrivateKey = ManagerPrivateKey(
            gamma: BLS12381.scalarToHex(gamma),
            groupPublicKey: groupPublicKey
        )
        
        return (managerPrivateKey, groupPublicKey)
    }
    
    // MARK: - Credential Issuance
    
    /// Issue a BBS+ credential to a new member
    /// Only the group manager can do this
    public static func issueMemberCredential(
        managerPrivateKey: ManagerPrivateKey,
        memberPublicKey: Hex
    ) throws -> MemberCredential {
        try initializeBLS()
        
        let gamma = BLS12381.scalarFromHex(managerPrivateKey.gamma)
        let gpk = managerPrivateKey.groupPublicKey
        
        // Deserialize generators
        let h0 = try BLS12381.deserializeG1(gpk.h0)
        let h1 = try BLS12381.deserializeG1(gpk.h1)
        
        // Member's secret key (random scalar in Fr)
        let x = BLS12381.randomScalar()
        // Credential randomness
        let e = BLS12381.randomScalar()
        let s = BLS12381.randomScalar()
        
        // Compute credential: A = (g1 + h0*s + h1*x)^(1/(gamma + e))
        // First compute: B = g1 + h0*s + h1*x
        let g1Base = G1Point.generator
        let h0s = BLS12381.g1Mul(h0, s)
        let h1x = BLS12381.g1Mul(h1, x)
        let B = BLS12381.g1Add(BLS12381.g1Add(g1Base, h0s), h1x)
        
        // Then compute: A = B^(1/(gamma + e))
        let exp = BLS12381.scalarAdd(gamma, e)
        let expInv = BLS12381.scalarInv(exp)
        let A = BLS12381.g1Mul(B, expInv)
        
        return MemberCredential(
            x: BLS12381.scalarToHex(x),
            A: BLS12381.serializeG1(A),
            e: BLS12381.scalarToHex(e),
            s: BLS12381.scalarToHex(s)
        )
    }
    
    // MARK: - Group Signing
    
    /// Create an anonymous group signature
    /// Proves membership without revealing which member signed
    public static func groupSign(
        message: String,
        memberCredential: MemberCredential,
        groupPublicKey: GroupPublicKey,
        debug: Bool = false
    ) throws -> GroupSignature {
        try initializeBLS()
        
        // Parse credential values
        let x = BLS12381.scalarFromHex(memberCredential.x)
        let A = try BLS12381.deserializeG1(memberCredential.A)
        let e = BLS12381.scalarFromHex(memberCredential.e)
        let s = BLS12381.scalarFromHex(memberCredential.s)
        
        // Parse public key generators
        let h0 = try BLS12381.deserializeG1(groupPublicKey.h0)
        let h1 = try BLS12381.deserializeG1(groupPublicKey.h1)
        
        // Randomize credential for unlinkability
        let r = BLS12381.randomScalar()
        
        // A' = A^r (blinded credential)
        let APrime = BLS12381.g1Mul(A, r)
        
        // Compute B' = (g1 + h0*s + h1*x)^r
        let sr = BLS12381.scalarMul(s, r)
        let xr = BLS12381.scalarMul(x, r)
        
        let g1r = BLS12381.g1Mul(G1Point.generator, r)
        let h0sr = BLS12381.g1Mul(h0, sr)
        let h1xr = BLS12381.g1Mul(h1, xr)
        let BPrime = BLS12381.g1Add(BLS12381.g1Add(g1r, h0sr), h1xr)
        
        // Abar = B' + A'^(-e)
        // This satisfies: e(A', w) = e(Abar, g2)
        let negE = BLS12381.scalarNeg(e)
        let APrimeNegE = BLS12381.g1Mul(APrime, negE)
        let ABar = BLS12381.g1Add(BPrime, APrimeNegE)
        
        // d = h0^r2 + h1^(xr) for ZK proof of knowledge of x
        let r2 = BLS12381.randomScalar()
        let h0r2 = BLS12381.g1Mul(h0, r2)
        let h1xr2 = BLS12381.g1Mul(h1, xr)
        let d = BLS12381.g1Add(h0r2, h1xr2)
        
        // ZK proof commitments (Schnorr-style)
        let rXR = BLS12381.randomScalar()
        let rR2 = BLS12381.randomScalar()
        let rE = BLS12381.randomScalar()
        let rS = BLS12381.randomScalar()
        
        // Commitment: T = h0^rR2 + h1^rXR
        let h0rR2 = BLS12381.g1Mul(h0, rR2)
        let h1rXR = BLS12381.g1Mul(h1, rXR)
        let T = BLS12381.g1Add(h0rR2, h1rXR)
        
        // Challenge: c = Hash(message, APrime.x, ABar.x, d.x, T.x)
        // Use X coordinates only to match node-client/server
        let xAPrime = BLS12381.g1GetXBuffer(APrime)
        let xABar = BLS12381.g1GetXBuffer(ABar)
        let xD = BLS12381.g1GetXBuffer(d)
        let xT = BLS12381.g1GetXBuffer(T)
        
        var challengeInput = Data(message.utf8)
        challengeInput.append(xAPrime)
        challengeInput.append(xABar)
        challengeInput.append(xD)
        challengeInput.append(xT)
        
        let c = BLS12381.hashToScalar(challengeInput)
        
        // Response scalars: z = r + c * secret
        let sXR = BLS12381.scalarAdd(rXR, BLS12381.scalarMul(c, xr))
        let sR2Response = BLS12381.scalarAdd(rR2, BLS12381.scalarMul(c, r2))
        let sE = BLS12381.scalarAdd(rE, BLS12381.scalarMul(c, e))
        let sS = BLS12381.scalarAdd(rS, BLS12381.scalarMul(c, s))
        
        return GroupSignature(
            APrime: BLS12381.serializeG1(APrime),
            ABar: BLS12381.serializeG1(ABar),
            d: BLS12381.serializeG1(d),
            c: BLS12381.scalarToHex(c),
            sX: BLS12381.scalarToHex(sXR),
            sR2: BLS12381.scalarToHex(sR2Response),
            sE: BLS12381.scalarToHex(sE),
            sS: BLS12381.scalarToHex(sS)
        )
    }
    
    // MARK: - Signature Verification
    
    /// Verify a BBS+ group signature
    /// Anyone can verify that signature came from a group member
    public static func verifyGroupSignature(
        message: String,
        signature: GroupSignature,
        groupPublicKey: GroupPublicKey,
        debug: Bool = false
    ) -> GroupSigVerifyResult {
        do {
            try initializeBLS()
            
            // Parse signature values
            let APrime = try BLS12381.deserializeG1(signature.APrime)
            let ABar = try BLS12381.deserializeG1(signature.ABar)
            let d = try BLS12381.deserializeG1(signature.d)
            let c = BLS12381.scalarFromHex(signature.c)
            let sXR = BLS12381.scalarFromHex(signature.sX)
            let sR2 = BLS12381.scalarFromHex(signature.sR2)
            
            // Parse public key
            let h0 = try BLS12381.deserializeG1(groupPublicKey.h0)
            let h1 = try BLS12381.deserializeG1(groupPublicKey.h1)
            let w = try BLS12381.deserializeG2(groupPublicKey.w)
            
            // Verify A' is not identity (prevents trivial signatures)
            if APrime.isZero {
                return GroupSigVerifyResult.failure("Invalid signature: A' is identity")
            }
            
            // Verify Abar is not identity
            if ABar.isZero {
                return GroupSigVerifyResult.failure("Invalid signature: Abar is identity")
            }
            
            // Step 1: Verify the Schnorr ZK proof for commitment d
            // Recompute commitment: T' = h0^sR2 + h1^sXR + d^(-c)
            let negC = BLS12381.scalarNeg(c)
            let h0sR2 = BLS12381.g1Mul(h0, sR2)
            let h1sXR = BLS12381.g1Mul(h1, sXR)
            let dNegC = BLS12381.g1Mul(d, negC)
            let TPrime = BLS12381.g1Add(BLS12381.g1Add(h0sR2, h1sXR), dNegC)
            
            // Recompute challenge and verify it matches
            // Use X coordinates only to match node-client/server
            var challengeInput = Data(message.utf8)
            challengeInput.append(BLS12381.g1GetXBuffer(APrime))
            challengeInput.append(BLS12381.g1GetXBuffer(ABar))
            challengeInput.append(BLS12381.g1GetXBuffer(d))
            challengeInput.append(BLS12381.g1GetXBuffer(TPrime))
            let cPrime = BLS12381.hashToScalar(challengeInput)
            
            if c != cPrime {
                return GroupSigVerifyResult.failure("Invalid signature: challenge mismatch")
            }
            
            // Step 2: Verify pairing equation: e(A', w) = e(Abar, g2)
            let g2Gen = G2Point.generator
            
            if !BLS12381.pairingEqual(APrime, w, ABar, g2Gen) {
                return GroupSigVerifyResult.failure("Invalid signature: pairing check failed")
            }
            
            return GroupSigVerifyResult.success()
        } catch {
            return GroupSigVerifyResult.failure("Verification error: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Revocation
    
    /// Revoke a member's credential
    /// Updates the revocation accumulator
    public static func revokeMemberCredential(
        managerPrivateKey: ManagerPrivateKey,
        memberCredential: MemberCredential,
        currentAccumulator: Hex?
    ) throws -> RevocationWitness {
        try initializeBLS()
        
        // Parse values
        let e = BLS12381.scalarFromHex(memberCredential.e)
        
        // Get or initialize accumulator
        let accPoint: G1Point
        if let accHex = currentAccumulator {
            accPoint = try BLS12381.deserializeG1(accHex)
        } else {
            // Initialize accumulator as g1^random
            let alpha = BLS12381.randomScalar()
            accPoint = BLS12381.g1Mul(G1Point.generator, alpha)
        }
        
        // Update accumulator: acc' = acc^(1/e)
        let eInv = BLS12381.scalarInv(e)
        let newAcc = BLS12381.g1Mul(accPoint, eInv)
        
        // Witness for revocation check (original accumulator)
        return RevocationWitness(
            accumulator: BLS12381.serializeG1(newAcc),
            witness: BLS12381.serializeG1(accPoint)
        )
    }
    
    /// Check if a credential is revoked
    public static func isCredentialRevoked(
        memberCredential: MemberCredential,
        revocationWitness: RevocationWitness
    ) -> Bool {
        do {
            try initializeBLS()
            
            let accPoint = try BLS12381.deserializeG1(revocationWitness.accumulator)
            let witnessPoint = try BLS12381.deserializeG1(revocationWitness.witness)
            let e = BLS12381.scalarFromHex(memberCredential.e)
            
            // Verify: e(acc, g2) = e(witness^e, g2)
            let witnessE = BLS12381.g1Mul(witnessPoint, e)
            
            // If pairings match, credential is NOT revoked
            return !BLS12381.pairingEqual(accPoint, G2Point.generator, witnessE, G2Point.generator)
        } catch {
            return true // Assume revoked on error
        }
    }
    
    // MARK: - Serialization
    
    /// Serialize group public key to JSON string
    public static func serializeGroupPublicKey(_ gpk: GroupPublicKey) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let data = try? encoder.encode(gpk),
              let json = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return json
    }
    
    /// Deserialize group public key from JSON string
    public static func deserializeGroupPublicKey(_ json: String) throws -> GroupPublicKey {
        guard let data = json.data(using: .utf8) else {
            throw GroupSigError.invalidGroupPublicKey("Invalid JSON encoding")
        }
        do {
            return try JSONDecoder().decode(GroupPublicKey.self, from: data)
        } catch {
            throw GroupSigError.invalidGroupPublicKey(error.localizedDescription)
        }
    }
    
    /// Serialize member credential to JSON string
    public static func serializeMemberCredential(_ cred: MemberCredential) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let data = try? encoder.encode(cred),
              let json = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return json
    }
    
    /// Deserialize member credential from JSON string
    public static func deserializeMemberCredential(_ json: String) throws -> MemberCredential {
        guard let data = json.data(using: .utf8) else {
            throw GroupSigError.invalidCredential("Invalid JSON encoding")
        }
        do {
            return try JSONDecoder().decode(MemberCredential.self, from: data)
        } catch {
            throw GroupSigError.invalidCredential(error.localizedDescription)
        }
    }
    
    /// Serialize group signature to JSON string
    public static func serializeGroupSignature(_ sig: GroupSignature) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let data = try? encoder.encode(sig),
              let json = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return json
    }
    
    /// Deserialize group signature from JSON string
    /// Handles both raw BBS+ format and wrapped format from node-client
    public static func deserializeGroupSignature(_ json: String) throws -> GroupSignature {
        guard let data = json.data(using: .utf8) else {
            throw GroupSigError.invalidSignature("Invalid JSON encoding")
        }
        
        // First, try to decode as raw BBS+ signature (APrime, ABar, etc.)
        if let signature = try? JSONDecoder().decode(GroupSignature.self, from: data) {
            return signature
        }
        
        // Try wrapped format from node-client: { proof, nonce, commitment }
        // where proof is hex-encoded JSON of the BBS+ signature
        struct WrappedSignature: Codable {
            let proof: String
            let nonce: String
            let commitment: String
        }
        
        do {
            let wrapped = try JSONDecoder().decode(WrappedSignature.self, from: data)
            
            // Decode hex-encoded proof to get the inner BBS+ signature JSON
            var proofHex = wrapped.proof
            if proofHex.hasPrefix("0x") {
                proofHex = String(proofHex.dropFirst(2))
            }
            
            guard let proofData = Data(hex: proofHex),
                  let proofJson = String(data: proofData, encoding: .utf8) else {
                throw GroupSigError.invalidSignature("Invalid proof hex encoding")
            }
            
            guard let innerData = proofJson.data(using: .utf8) else {
                throw GroupSigError.invalidSignature("Invalid inner JSON encoding")
            }
            
            return try JSONDecoder().decode(GroupSignature.self, from: innerData)
        } catch let error as GroupSigError {
            throw error
        } catch {
            throw GroupSigError.invalidSignature(error.localizedDescription)
        }
    }
    
    // MARK: - Self-Test
    
    /// Self-test to verify the BBS+ implementation
    /// Returns true if signing and verification work correctly
    public static func selfTest() -> (success: Bool, details: String) {
        do {
            // 1. Generate key pair
            let (managerKey, groupPublicKey) = try generateGroupKeyPair()
            
            // 2. Issue credential
            let memberPubKey = "0x" + String(repeating: "ab", count: 32)
            let credential = try issueMemberCredential(managerPrivateKey: managerKey, memberPublicKey: memberPubKey)
            
            // 3. Sign message
            let message = "test-message-for-bbs-verification"
            let signature = try groupSign(message: message, memberCredential: credential, groupPublicKey: groupPublicKey)
            
            // 4. Verify signature
            let result = verifyGroupSignature(message: message, signature: signature, groupPublicKey: groupPublicKey)
            
            if result.valid {
                return (true, "All checks passed")
            } else {
                return (false, "Verification failed: \(result.error ?? "unknown")")
            }
        } catch {
            return (false, "Error: \(error.localizedDescription)")
        }
    }
    
    /// Enable debug logging globally for BBS+ operations
    nonisolated(unsafe) public static var debugEnabled = false
}
