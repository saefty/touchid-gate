// swift-tools-version:5.9
import PackageDescription

// No dependencies beyond Apple frameworks: this binary guards credentials.
let package = Package(
    name: "touchpass",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "GateCore"),
        .executableTarget(name: "touchpass", dependencies: ["GateCore"]),
        // Command Line Tools ship neither XCTest nor swift-testing
        .executableTarget(name: "selftest", dependencies: ["GateCore"]),
    ]
)
