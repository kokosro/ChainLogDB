//
//  ChainLogDb.swift
//  ChainLogDb
//
//  Main entry point for the ChainLogDb unified package
//
//  This package provides:
//  - Cryptography (Ethereum-compatible crypto, MLS, BBS+)
//  - Chain log models (ChainLog, GroupChainLog)
//  - DBLog event-driven database models and processor
//  - SQLite database wrapper (DBLogDatabase)
//  - Configurable API client for chain log operations
//  - WebSocket client for real-time updates
//
//  Usage:
//    import ChainLogDb
//
//  All public types are automatically available after import.
//

import Foundation

// All crypto types are now part of this package (in Crypto/ folder)
// Types exported: Cryptograph, MLSGroup, BBSPlus, AccessProofUtils, etc.
