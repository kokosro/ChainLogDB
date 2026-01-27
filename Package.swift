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
        .package(url: "https://github.com/kokosro/ChainKeys", branch: "main"),
    ],
    targets: [
        .target(
            name: "ChainLogDb",
            dependencies: ["ChainKeys"]
        ),
        .testTarget(
            name: "ChainLogDbTests",
            dependencies: ["ChainLogDb"]
        ),
    ]
)
