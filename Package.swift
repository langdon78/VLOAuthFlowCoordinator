// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VLOAuthFlowCoordinator",
    platforms: [.macOS(.v26), .iOS(.v26), .tvOS(.v16), .watchOS(.v6)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "VLOAuthFlowCoordinator",
            targets: ["VLOAuthFlowCoordinator"]),
    ],
    dependencies: [
        .package(url: "https://github.com/langdon78/VLOAuthProvider", .upToNextMajor(from: "0.1.0-alpha")),
        .package(path: "../VLDebugLogger")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "VLOAuthFlowCoordinator",
            dependencies: [
                .product(name: "VLOAuthProvider", package: "VLOAuthProvider"),
                .product(name: "VLDebugLogger", package: "VLDebugLogger")
            ]
        ),
        .testTarget(
            name: "VLOAuthFlowCoordinatorTests",
            dependencies: ["VLOAuthFlowCoordinator"]
        ),
    ]
)
