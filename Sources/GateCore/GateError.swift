public struct GateError: Error, CustomStringConvertible {
    public let description: String
    public let exitCode: Int32
    /// Set when the failure is only "does not exist", so callers can map it to `rm -f` / not-found.
    public let notFound: Bool

    public init(_ description: String, exitCode: Int32 = 1, notFound: Bool = false) {
        self.description = description
        self.exitCode = exitCode
        self.notFound = notFound
    }

    public static func usage(_ description: String) -> GateError { GateError(description, exitCode: 64) }
}
