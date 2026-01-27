//
//  HexUtils.swift
//  ChainKeys
//
//  Hex encoding/decoding utilities for Ethereum-style data
//

import Foundation

public typealias Hex = String

// MARK: - Data Extensions

extension Data {
    /// Initialize from hex string (with or without 0x prefix)
    public init?(hex: String) {
        var hexString = hex
        if hexString.hasPrefix("0x") {
            hexString = String(hexString.dropFirst(2))
        }
        
        guard hexString.count % 2 == 0 else { return nil }
        
        var data = Data()
        var index = hexString.startIndex
        
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
    
    /// Convert to hex string with 0x prefix
    public var hexString: Hex {
        "0x" + map { String(format: "%02x", $0) }.joined()
    }
    
    /// Convert to hex string without prefix
    public var hexStringNoPrefix: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - String Extensions

extension String {
    /// Remove 0x prefix if present
    public var stripHexPrefix: String {
        hasPrefix("0x") ? String(dropFirst(2)) : self
    }
    
    /// Add 0x prefix if not present
    public var withHexPrefix: Hex {
        hasPrefix("0x") ? self : "0x" + self
    }
    
    /// Check if string is valid hex
    public var isValidHex: Bool {
        let hex = stripHexPrefix
        guard !hex.isEmpty else { return false }
        return hex.allSatisfy { $0.isHexDigit }
    }
    
    /// Convert hex string to Data
    public var hexData: Data? {
        Data(hex: self)
    }
}

// MARK: - Address Utilities

extension Hex {
    /// Truncate address for display (e.g., "0x1234...abcd")
    public var truncatedAddress: String {
        guard count >= 10 else { return self }
        let start = prefix(6)
        let end = suffix(4)
        return "\(start)...\(end)"
    }
    
    /// Check if this is a valid Ethereum address (42 chars with 0x prefix)
    public var isValidAddress: Bool {
        hasPrefix("0x") && count == 42 && dropFirst(2).allSatisfy { $0.isHexDigit }
    }
    
    /// Check if this is a valid private key (66 chars with 0x prefix)
    public var isValidPrivateKey: Bool {
        hasPrefix("0x") && count == 66 && dropFirst(2).allSatisfy { $0.isHexDigit }
    }
}
