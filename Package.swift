// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ChainLogDb",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(
            name: "ChainLogDb",
            targets: ["ChainLogDb"]
        ),
    ],
    dependencies: [
        // Crypto dependencies (previously from ChainKeys)
        .package(url: "https://github.com/Sajjon/K1", from: "0.3.0"),
        .package(url: "https://github.com/bitflying/SwiftKeccak", from: "0.1.0"),
        .package(url: "https://github.com/attaswift/BigInt", from: "5.3.0"),
        .package(url: "https://github.com/MyEtherWallet/bls-eth-swift", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "ChainLogDb",
            dependencies: [
                "K1",
                "SwiftKeccak",
                "BigInt",
                .product(name: "bls-eth-swift", package: "bls-eth-swift"),
            ]
        ),
        .testTarget(
            name: "ChainLogDbTests",
            dependencies: ["ChainLogDb"]
        ),
    ]
)
