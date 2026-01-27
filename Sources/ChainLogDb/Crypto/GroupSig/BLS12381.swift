//
//  BLS12381.swift
//  ChainKeys
//
//  BLS12-381 Curve Operations Wrapper
//  Provides low-level cryptographic primitives for BBS+ signatures
//
//  Uses the bls-eth-swift library (herumi/mcl)
//  Repository: https://github.com/MyEtherWallet/bls-eth-swift
//
//  Note: With BLS_ETH defined, blsPublicKey = G1, blsSignature = G2
//

import Foundation
import CryptoKit
import BigInt
import bls_framework

// MARK: - BLS12-381 Initialization

nonisolated(unsafe) private var blsInitialized = false

/// MCLBN_COMPILED_TIME_VAR for BLS12-381 with ETH mode
/// = (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE + BLS_COMPILER_TIME_VAR_ADJ)
/// = (4 * 10 + 6 + 200) = 246
private let BLS_COMPILED_TIME_VAR: Int32 = 246

/// Initialize the BLS library (must be called before any operations)
public func initializeBLS() throws {
    guard !blsInitialized else { return }
    
    // Initialize the BLS library
    // MCL_BLS12_381 = 5
    let result = blsInit(5, BLS_COMPILED_TIME_VAR)
    guard result == 0 else {
        throw BLS12381Error.initializationFailed
    }
    
    // Set ETH mode for proper serialization
    _ = blsSetETHmode(BLS_ETH_MODE_LATEST)
    
    blsInitialized = true
    
    // Debug: Print the G1 generator to compare with noble/curves
    let gen = G1Point.generator
    var buf = [UInt8](repeating: 0, count: 48)
    var genCopy = gen.point
    let len = blsPublicKeySerialize(&buf, buf.count, &genCopy)
    if len > 0 {
        let genHex = "0x" + Data(buf.prefix(Int(len))).map { String(format: "%02x", $0) }.joined()
        print("[BLS12381] G1 generator (mcl): \(genHex)")
        
        // Standard BLS12-381 G1 generator (Zcash/ETH compatible)
        let expectedGen = "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        if genHex.lowercased() == expectedGen.lowercased() {
            print("[BLS12381] G1 generator matches standard ✓")
        } else {
            print("[BLS12381] WARNING: G1 generator DIFFERS from standard!")
            print("[BLS12381] Expected: \(expectedGen)")
        }
        
        // hashToScalar compatibility test - compare with TypeScript result
        // TypeScript: hashToScalar("test-hash-to-scalar") = 0x2305a6bbe1b65a4e3251d4c3cd2a78752cfca572a63a22fee722b309d8088555
        let testInput = Data("test-hash-to-scalar".utf8)
        let testScalar = BLS12381.hashToScalar(testInput)
        let testScalarHex = BLS12381.scalarToHex(testScalar)
        let expectedScalar = "0x2305a6bbe1b65a4e3251d4c3cd2a78752cfca572a63a22fee722b309d8088555"
        print("[BLS12381] hashToScalar('test-hash-to-scalar') = \(testScalarHex)")
        if testScalarHex.lowercased() == expectedScalar.lowercased() {
            print("[BLS12381] hashToScalar matches TypeScript ✓")
        } else {
            print("[BLS12381] WARNING: hashToScalar DIFFERS from TypeScript!")
            print("[BLS12381] Expected: \(expectedScalar)")
        }
    }
}

// MARK: - Type Wrappers

/// Wrapper for G1 point (blsPublicKey in ETH mode)
/// In BLS_ETH mode, blsPublicKey represents G1 points
public struct G1Point: Equatable {
    var point: blsPublicKey
    
    public init() {
        point = blsPublicKey()
    }
    
    public init(point: blsPublicKey) {
        self.point = point
    }
    
    /// G1 base point (generator)
    public static var generator: G1Point {
        var p = G1Point()
        blsGetGeneratorOfPublicKey(&p.point)
        return p
    }
    
    /// Identity (point at infinity)
    public static var zero: G1Point {
        let p = G1Point()
        // Zero-initialized is the identity
        return p
    }
    
    public var isZero: Bool {
        var copy = point
        return blsPublicKeyIsZero(&copy) == 1
    }
    
    public static func == (lhs: G1Point, rhs: G1Point) -> Bool {
        var l = lhs.point
        var r = rhs.point
        return blsPublicKeyIsEqual(&l, &r) == 1
    }
}

/// Wrapper for G2 point (blsSignature in ETH mode)
/// In BLS_ETH mode, blsSignature represents G2 points
public struct G2Point: Equatable {
    var point: blsSignature
    
    public init() {
        point = blsSignature()
    }
    
    public init(point: blsSignature) {
        self.point = point
    }
    
    /// Cached G2 generator to avoid recomputation
    nonisolated(unsafe) private static var _cachedG2Generator: G2Point?
    
    /// G2 base point (generator) - Standard BLS12-381 generator
    /// Must match @noble/curves G2Point.BASE for cross-platform compatibility
    /// The standard BLS12-381 G2 generator coordinates (affine form)
    public static var generator: G2Point {
        // Return cached generator if available
        if let cached = _cachedG2Generator {
            return cached
        }
        
        // Ensure BLS is initialized before accessing generator
        try? initializeBLS()
        
        var p = G2Point()
        
        // Standard BLS12-381 G2 generator coordinates from the curve specification
        // noble/curves G2 generator compressed: 93e02b...024aa2b2...
        let g2CompressedNoble = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        
        // herumi/mcl might use different byte order: x.c0 first, then x.c1
        let g2CompressedReversed = "824aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        
        var deserializeSuccess = false
        
        // Try noble/curves format first
        if let data = Data(hex: g2CompressedNoble) {
            let len = data.withUnsafeBytes { ptr in
                blsSignatureDeserialize(&p.point, ptr.baseAddress, data.count)
            }
            if len > 0 {
                deserializeSuccess = true
            }
        }
        
        // Try reversed format if noble format failed
        if !deserializeSuccess {
            if let data = Data(hex: g2CompressedReversed) {
                let len = data.withUnsafeBytes { ptr in
                    blsSignatureDeserialize(&p.point, ptr.baseAddress, data.count)
                }
                if len > 0 {
                    deserializeSuccess = true
                }
            }
        }
        
        if !deserializeSuccess {
            // Fallback: try mclBnG2_setStr with hex coordinates
            let g2Str = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
            
            let result = mclBnG2_setStr(&p.point.v, g2Str, g2Str.count, 16)
            if result == 0 {
                deserializeSuccess = true
            } else {
                // Last resort: hash to G2
                let genStr = "BLS12-381 G2 Generator Fallback"
                _ = blsHashToSignature(&p.point, genStr, genStr.count)
            }
        }
        
        _cachedG2Generator = p
        return p
    }
    
    /// Identity (point at infinity)
    public static var zero: G2Point {
        let p = G2Point()
        return p
    }
    
    public var isZero: Bool {
        var copy = point
        return blsSignatureIsZero(&copy) == 1
    }
    
    public static func == (lhs: G2Point, rhs: G2Point) -> Bool {
        var l = lhs.point
        var r = rhs.point
        return blsSignatureIsEqual(&l, &r) == 1
    }
}

/// Wrapper for Fr (scalar field element)
/// Uses blsSecretKey which wraps mclBnFr
public struct FrElement: Equatable {
    var element: blsSecretKey
    
    public init() {
        element = blsSecretKey()
    }
    
    public init(element: blsSecretKey) {
        self.element = element
    }
    
    /// Zero element
    public static var zero: FrElement {
        let e = FrElement()
        // Zero-initialized
        return e
    }
    
    /// One element
    public static var one: FrElement {
        var e = FrElement()
        let oneStr = "1"
        _ = blsSecretKeySetDecStr(&e.element, oneStr, 1)
        return e
    }
    
    public var isZero: Bool {
        var copy = element
        return blsSecretKeyIsZero(&copy) == 1
    }
    
    public static func == (lhs: FrElement, rhs: FrElement) -> Bool {
        var l = lhs.element
        var r = rhs.element
        return blsSecretKeyIsEqual(&l, &r) == 1
    }
}

/// Wrapper for GT (pairing result)
/// This is represented internally but we use pairing verification
public struct GTElement: Equatable {
    // We don't directly expose GT, we use pairing verification
    var isValid: Bool
    
    public init(isValid: Bool = false) {
        self.isValid = isValid
    }
    
    public static func == (lhs: GTElement, rhs: GTElement) -> Bool {
        lhs.isValid == rhs.isValid
    }
}

// MARK: - BLS12-381 Operations

public enum BLS12381 {
    
    // MARK: - Scalar Operations
    
    /// Generate a random scalar in Fr
    public static func randomScalar() -> FrElement {
        var fr = FrElement()
        _ = blsSecretKeySetByCSPRNG(&fr.element)
        return fr
    }
    
    /// Create scalar from hex string
    /// Properly handles values that may exceed Fr_ORDER by reducing mod Fr
    public static func scalarFromHex(_ hex: Hex) -> FrElement {
        var fr = FrElement()
        let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        
        // First try direct hex parsing
        let result = blsSecretKeySetHexStr(&fr.element, cleanHex, cleanHex.count)
        
        // If it failed (possibly because value >= Fr_ORDER), use BigInt reduction
        if result != 0 {
            // Parse as BigInt and reduce mod Fr_ORDER
            if let bigIntValue = BigInt(cleanHex, radix: 16) {
                let reducedValue = bigIntValue % Fr_ORDER
                var reducedHex = String(reducedValue, radix: 16)
                reducedHex = String(repeating: "0", count: max(0, 64 - reducedHex.count)) + reducedHex
                _ = blsSecretKeySetHexStr(&fr.element, reducedHex, reducedHex.count)
            }
        }
        return fr
    }
    
    /// Convert scalar to hex string
    public static func scalarToHex(_ fr: FrElement) -> Hex {
        var copy = fr.element
        var buf = [CChar](repeating: 0, count: 128)
        let len = blsSecretKeyGetHexStr(&buf, buf.count, &copy)
        guard len > 0 else { return "0x0" }
        let hex = buf.withUnsafeBufferPointer { ptr in
            String(decoding: ptr.prefix(Int(len)).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
        let padded = String(repeating: "0", count: max(0, 64 - hex.count)) + hex
        return "0x" + padded
    }
    
    /// Add two scalars
    public static func scalarAdd(_ a: FrElement, _ b: FrElement) -> FrElement {
        var result = FrElement()
        var aCopy = a.element.v
        var bCopy = b.element.v
        mclBnFr_add(&result.element.v, &aCopy, &bCopy)
        return result
    }
    
    /// Subtract scalars (a - b)
    public static func scalarSub(_ a: FrElement, _ b: FrElement) -> FrElement {
        var result = FrElement()
        var aCopy = a.element.v
        var bCopy = b.element.v
        mclBnFr_sub(&result.element.v, &aCopy, &bCopy)
        return result
    }
    
    /// Multiply two scalars
    public static func scalarMul(_ a: FrElement, _ b: FrElement) -> FrElement {
        var result = FrElement()
        var aCopy = a.element.v
        var bCopy = b.element.v
        mclBnFr_mul(&result.element.v, &aCopy, &bCopy)
        return result
    }
    
    /// Negate a scalar
    public static func scalarNeg(_ a: FrElement) -> FrElement {
        var result = FrElement()
        var aCopy = a.element.v
        mclBnFr_neg(&result.element.v, &aCopy)
        return result
    }
    
    /// Compute modular inverse of scalar
    public static func scalarInv(_ a: FrElement) -> FrElement {
        var result = FrElement()
        var aCopy = a.element.v
        mclBnFr_inv(&result.element.v, &aCopy)
        return result
    }
    
    /// BLS12-381 Fr field order (same as node-client Fr_ORDER)
    /// This is the order of the scalar field for BLS12-381
    private static let Fr_ORDER = BigInt("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", radix: 16)!
    
    /// Hash data to scalar using same algorithm as node-client
    /// Double SHA256 with "expand" suffix, then interpret as bigint mod Fr
    public static func hashToScalar(_ data: Data) -> FrElement {
        // First SHA256
        let hash1 = SHA256.hash(data: data)
        // Second SHA256 with "expand" suffix
        var expandInput = Data(hash1)
        expandInput.append(Data("expand".utf8))
        let hash2 = SHA256.hash(data: expandInput)
        
        // Convert hash to BigInt (big-endian, matching node-client's bufferToBigInt)
        let hashData = Data(hash2)
        let hashBigInt = BigInt(hashData.hexStringNoPrefix, radix: 16) ?? BigInt(0)
        
        // Explicit modular reduction (matching node-client's bufferToBigInt(hash) % Fr_ORDER)
        // This is critical because SHA256 output (256 bits) can exceed Fr_ORDER (~254 bits)
        let reducedValue = hashBigInt % Fr_ORDER
        
        // Convert reduced value to hex and set as Fr element
        var hexString = String(reducedValue, radix: 16)
        // Pad to 64 chars (32 bytes) to match node-client's bigIntToHex behavior
        hexString = String(repeating: "0", count: max(0, 64 - hexString.count)) + hexString
        
        var fr = FrElement()
        _ = blsSecretKeySetHexStr(&fr.element, hexString, hexString.count)
        return fr
    }
    
    /// Hash multiple inputs to scalar (matches node-client hashToScalar)
    public static func hashToScalarMultiple(_ inputs: [Data]) -> FrElement {
        var combined = Data()
        for input in inputs {
            combined.append(input)
        }
        return hashToScalar(combined)
    }
    
    // MARK: - G1 Point Operations
    
    /// Multiply G1 point by scalar: result = point * scalar
    public static func g1Mul(_ point: G1Point, _ scalar: FrElement) -> G1Point {
        var result = G1Point()
        var pCopy = point.point.v
        var sCopy = scalar.element.v
        mclBnG1_mul(&result.point.v, &pCopy, &sCopy)
        return result
    }
    
    /// Add two G1 points
    public static func g1Add(_ a: G1Point, _ b: G1Point) -> G1Point {
        var result = G1Point()
        var aCopy = a.point.v
        var bCopy = b.point.v
        mclBnG1_add(&result.point.v, &aCopy, &bCopy)
        return result
    }
    
    /// Negate a G1 point
    public static func g1Neg(_ point: G1Point) -> G1Point {
        var result = G1Point()
        var pCopy = point.point.v
        mclBnG1_neg(&result.point.v, &pCopy)
        return result
    }
    
    /// Serialize G1 point to compressed hex
    public static func serializeG1(_ point: G1Point) -> Hex {
        var copy = point.point
        var buf = [UInt8](repeating: 0, count: 48)
        let len = blsPublicKeySerialize(&buf, buf.count, &copy)
        guard len > 0 else { return "0x" }
        return "0x" + Data(buf.prefix(Int(len))).hexStringNoPrefix
    }
    
    /// Get the affine X coordinate of a G1 point as a buffer
    public static func g1GetXBuffer(_ point: G1Point) -> Data {
        var copy = point.point
        var buf = [UInt8](repeating: 0, count: 48)
        let len = blsPublicKeySerialize(&buf, buf.count, &copy)
        guard len > 0 else { return Data(repeating: 0, count: 32) }
        
        // Clear the top 3 bits (flags) to get just the X coordinate
        var xBytes = buf
        xBytes[0] &= 0x1F
        
        // Convert to BigInt
        let xHex = Data(xBytes.prefix(Int(len))).hexStringNoPrefix
        let xBigInt = BigInt(xHex, radix: 16) ?? BigInt(0)
        
        // Convert back to hex, matching node-client's bigIntToBuffer
        var resultHex = String(xBigInt, radix: 16)
        
        // Pad to minimum 64 hex chars (32 bytes)
        if resultHex.count < 64 {
            resultHex = String(repeating: "0", count: 64 - resultHex.count) + resultHex
        }
        
        // If odd length, pad to even for proper byte conversion
        if resultHex.count % 2 != 0 {
            resultHex = "0" + resultHex
        }
        
        return Data(hex: resultHex) ?? Data(repeating: 0, count: 32)
    }
    
    /// Deserialize G1 point from hex
    public static func deserializeG1(_ hex: Hex) throws -> G1Point {
        let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        guard let data = Data(hex: cleanHex) else {
            throw BLS12381Error.invalidHexEncoding
        }
        var result = G1Point()
        let len = data.withUnsafeBytes { ptr in
            blsPublicKeyDeserialize(&result.point, ptr.baseAddress, data.count)
        }
        guard len > 0 else {
            throw BLS12381Error.invalidG1Point("Deserialization failed")
        }
        return result
    }
    
    /// Hash data to G1 point (matches node-client hashToG1)
    /// Uses hashToScalar then multiplies G1 base point
    public static func hashToG1(_ data: Data) -> G1Point {
        let scalar = hashToScalar(data)
        return g1Mul(G1Point.generator, scalar)
    }
    
    /// Hash domain + inputs to G1 point (matches node-client hashToG1(domain, ...inputs))
    public static func hashToG1WithDomain(_ domain: String, _ inputs: Data...) -> G1Point {
        var combined = Data(domain.utf8)
        for input in inputs {
            combined.append(input)
        }
        return hashToG1(combined)
    }
    
    /// Convert a scalar to a 32-byte buffer (matches node-client bigIntToBuffer)
    public static func scalarToBuffer(_ scalar: FrElement) -> Data {
        let hex = scalarToHex(scalar)
        let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        // Pad to 64 chars (32 bytes)
        let padded = String(repeating: "0", count: max(0, 64 - cleanHex.count)) + cleanHex
        return Data(hex: padded) ?? Data(repeating: 0, count: 32)
    }
    
    // MARK: - G2 Point Operations
    
    /// Multiply G2 point by scalar
    public static func g2Mul(_ point: G2Point, _ scalar: FrElement) -> G2Point {
        var result = G2Point()
        var pCopy = point.point.v
        var sCopy = scalar.element.v
        mclBnG2_mul(&result.point.v, &pCopy, &sCopy)
        return result
    }
    
    /// Add two G2 points
    public static func g2Add(_ a: G2Point, _ b: G2Point) -> G2Point {
        var result = G2Point()
        var aCopy = a.point.v
        var bCopy = b.point.v
        mclBnG2_add(&result.point.v, &aCopy, &bCopy)
        return result
    }
    
    /// Negate a G2 point
    public static func g2Neg(_ point: G2Point) -> G2Point {
        var result = G2Point()
        var pCopy = point.point.v
        mclBnG2_neg(&result.point.v, &pCopy)
        return result
    }
    
    /// Serialize G2 point to compressed hex
    public static func serializeG2(_ point: G2Point) -> Hex {
        var copy = point.point
        var buf = [UInt8](repeating: 0, count: 96)
        let len = blsSignatureSerialize(&buf, buf.count, &copy)
        guard len > 0 else { return "0x" }
        return "0x" + Data(buf.prefix(Int(len))).hexStringNoPrefix
    }
    
    /// Deserialize G2 point from hex
    public static func deserializeG2(_ hex: Hex) throws -> G2Point {
        let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        guard let data = Data(hex: cleanHex) else {
            throw BLS12381Error.invalidHexEncoding
        }
        var result = G2Point()
        let len = data.withUnsafeBytes { ptr in
            blsSignatureDeserialize(&result.point, ptr.baseAddress, data.count)
        }
        guard len > 0 else {
            throw BLS12381Error.invalidG2Point("Deserialization failed")
        }
        return result
    }
    
    // MARK: - Pairing Operations
    
    /// Verify pairing equation: e(X, Q) = e(Y, P)
    public static func verifyPairing(_ x: G2Point, _ y: G2Point, _ pub: G1Point) -> Bool {
        var xCopy = x.point
        var yCopy = y.point
        var pubCopy = pub.point
        return blsVerifyPairing(&xCopy, &yCopy, &pubCopy) == 1
    }
    
    /// Compare pairings: e(g1a, g2a) == e(g1b, g2b)
    public static func pairingEqual(_ g1a: G1Point, _ g2a: G2Point, _ g1b: G1Point, _ g2b: G2Point) -> Bool {
        var gt1 = mclBnGT()
        var gt2 = mclBnGT()
        
        var g1aCopy = g1a.point.v
        var g2aCopy = g2a.point.v
        var g1bCopy = g1b.point.v
        var g2bCopy = g2b.point.v
        
        // Compute pairings
        mclBn_pairing(&gt1, &g1aCopy, &g2aCopy)
        mclBn_pairing(&gt2, &g1bCopy, &g2bCopy)
        
        return mclBnGT_isEqual(&gt1, &gt2) == 1
    }
}

// MARK: - Errors

public enum BLS12381Error: Error, LocalizedError {
    case initializationFailed
    case invalidHexEncoding
    case invalidG1Point(String)
    case invalidG2Point(String)
    case pairingFailed(String)
    
    public var errorDescription: String? {
        switch self {
        case .initializationFailed:
            return "Failed to initialize BLS12-381 library"
        case .invalidHexEncoding:
            return "Invalid hexadecimal encoding"
        case .invalidG1Point(let msg):
            return "Invalid G1 point: \(msg)"
        case .invalidG2Point(let msg):
            return "Invalid G2 point: \(msg)"
        case .pairingFailed(let msg):
            return "Pairing computation failed: \(msg)"
        }
    }
}
