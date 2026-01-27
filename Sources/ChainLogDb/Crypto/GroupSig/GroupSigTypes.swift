//
//  GroupSigTypes.swift
//  ChainKeys
//
//  Group Signature Types for BBS+ and Access Proofs
//  Provides anonymous membership proofs using BBS+ signatures on BLS12-381 curve
//
//  Key properties:
//  - Verifiability: Anyone can verify a signature came from a group member
//  - Anonymity: Verifier cannot determine which member signed
//  - Unlinkability: Multiple signatures by same member appear unrelated
//

import Foundation

// MARK: - BBS+ Group Public Key

/// Group public key for BBS+ signatures
/// Published when creating a group, anyone can verify signatures
public struct GroupPublicKey: Codable, Sendable {
    /// Group public key in G2: w = g2^gamma (compressed, 192 bytes hex)
    public let w: Hex
    /// Generator points in G1: [h0, h1] (each 96 bytes compressed hex)
    public let h: [Hex]
    
    public init(w: Hex, h: [Hex]) {
        self.w = w
        self.h = h
    }
    
    /// h0 generator - used for credential blinding
    public var h0: Hex { h[0] }
    
    /// h1 generator - used for member secret
    public var h1: Hex { h[1] }
}

// MARK: - Manager Private Key

/// Group manager's private key
/// Only the group creator has this, used to issue and revoke credentials
public struct ManagerPrivateKey: Codable, Sendable {
    /// Group secret (gamma) - 32 bytes scalar
    public let gamma: Hex
    /// Associated group public key
    public let groupPublicKey: GroupPublicKey
    
    public init(gamma: Hex, groupPublicKey: GroupPublicKey) {
        self.gamma = gamma
        self.groupPublicKey = groupPublicKey
    }
}

// MARK: - Member Credential

/// BBS+ credential issued by group manager to each member
/// Proves the manager authorized this member to sign on behalf of the group
public struct MemberCredential: Codable, Sendable {
    /// Member's secret key (x) - 32 bytes scalar
    public let x: Hex
    /// Credential signature (A) in G1 - 96 bytes compressed
    /// A = (g1 + h0*s + h1*x)^(1/(gamma + e))
    public let A: Hex
    /// Credential exponent (e) - 32 bytes scalar
    public let e: Hex
    /// Credential blinding factor (s) - 32 bytes scalar
    public let s: Hex
    
    public init(x: Hex, A: Hex, e: Hex, s: Hex) {
        self.x = x
        self.A = A
        self.e = e
        self.s = s
    }
}

// MARK: - Group Signature

/// BBS+ group signature - zero-knowledge proof of membership
/// Proves the signer possesses a valid credential without revealing which one
public struct GroupSignature: Codable, Sendable {
    /// Randomized credential: A' = A^r (G1 point)
    public let APrime: Hex
    /// Blinded commitment (G1 point)
    public let ABar: Hex
    /// Commitment for ZK proof (G1 point)
    public let d: Hex
    /// Challenge scalar
    public let c: Hex
    /// Response for blinded x
    public let sX: Hex
    /// Response for r2
    public let sR2: Hex
    /// Response for e
    public let sE: Hex
    /// Response for s
    public let sS: Hex
    
    public init(APrime: Hex, ABar: Hex, d: Hex, c: Hex, sX: Hex, sR2: Hex, sE: Hex, sS: Hex) {
        self.APrime = APrime
        self.ABar = ABar
        self.d = d
        self.c = c
        self.sX = sX
        self.sR2 = sR2
        self.sE = sE
        self.sS = sS
    }
}

// MARK: - Revocation

/// Revocation witness for a revoked credential
public struct RevocationWitness: Codable, Sendable {
    /// Updated accumulator value
    public let accumulator: Hex
    /// Non-membership witness
    public let witness: Hex
    
    public init(accumulator: Hex, witness: Hex) {
        self.accumulator = accumulator
        self.witness = witness
    }
}

// MARK: - Epoch Access Keys

/// Epoch access key derived from MLS group key
public struct EpochAccessKey: Codable, Sendable {
    /// HKDF-derived key (32 bytes)
    public let key: Hex
    /// MLS epoch number
    public let epoch: Int
    
    public init(key: Hex, epoch: Int) {
        self.key = key
        self.epoch = epoch
    }
}

/// Access proof for server verification (HMAC-based)
public struct AccessProof: Codable, Sendable {
    /// HMAC(accessKey, hash) - 32 bytes
    public let proof: Hex
    /// Epoch this proof is valid for
    public let epoch: Int
    
    public init(proof: Hex, epoch: Int) {
        self.proof = proof
        self.epoch = epoch
    }
}

/// Epoch transition proof - proves knowledge of old key when transitioning
public struct EpochTransitionProof: Codable, Sendable {
    public let oldEpoch: Int
    public let newEpoch: Int
    public let newAccessKey: Hex
    /// HMAC(oldAccessKey, newAccessKey)
    public let transitionProof: Hex
    
    public init(oldEpoch: Int, newEpoch: Int, newAccessKey: Hex, transitionProof: Hex) {
        self.oldEpoch = oldEpoch
        self.newEpoch = newEpoch
        self.newAccessKey = newAccessKey
        self.transitionProof = transitionProof
    }
}

// MARK: - Verification Result

/// Result of signature or proof verification
public struct GroupSigVerifyResult: Sendable {
    public let valid: Bool
    public let error: String?
    
    public init(valid: Bool, error: String? = nil) {
        self.valid = valid
        self.error = error
    }
    
    public static func success() -> GroupSigVerifyResult {
        GroupSigVerifyResult(valid: true)
    }
    
    public static func failure(_ error: String) -> GroupSigVerifyResult {
        GroupSigVerifyResult(valid: false, error: error)
    }
}

// MARK: - Errors

public enum GroupSigError: Error, LocalizedError {
    case invalidGroupPublicKey(String)
    case invalidCredential(String)
    case invalidSignature(String)
    case signingFailed(String)
    case verificationFailed(String)
    case revocationFailed(String)
    case accessProofFailed(String)
    case missingBLS12381Library
    
    public var errorDescription: String? {
        switch self {
        case .invalidGroupPublicKey(let msg):
            return "Invalid group public key: \(msg)"
        case .invalidCredential(let msg):
            return "Invalid member credential: \(msg)"
        case .invalidSignature(let msg):
            return "Invalid group signature: \(msg)"
        case .signingFailed(let msg):
            return "Signing failed: \(msg)"
        case .verificationFailed(let msg):
            return "Verification failed: \(msg)"
        case .revocationFailed(let msg):
            return "Revocation failed: \(msg)"
        case .accessProofFailed(let msg):
            return "Access proof failed: \(msg)"
        case .missingBLS12381Library:
            return "BLS12-381 library not available"
        }
    }
}
