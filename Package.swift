// swift-tools-version:5.9
import PackageDescription

// No dependencies beyond Apple frameworks: this binary guards credentials.
let package = Package(
    name: "touchid-gate",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "GateCore"),
        .executableTarget(name: "touchid-gate", dependencies: ["GateCore"]),
        // Command Line Tools ship neither XCTest nor swift-testing
        .executableTarget(name: "selftest", dependencies: ["GateCore"]),
    ]
)
