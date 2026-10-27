import Foundation

/// No env override on purpose: env is caller-controlled, the config decides what callers may do.
public struct Config: Codable {
    public var stores: [String: StoreConfig] = [:]
    public var gates: [String: GateConfig] = [:]

    public static var defaultURL: URL { expandTilde("~/.config/touchpass/config.json") }

    public init(stores: [String: StoreConfig] = [:], gates: [String: GateConfig] = [:]) {
        self.stores = stores
        self.gates = gates
    }

    // the synthesized decoder ignores property defaults, so a config without "gates" would fail
    enum CodingKeys: String, CodingKey { case stores, gates }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        stores = try c.decodeIfPresent([String: StoreConfig].self, forKey: .stores) ?? [:]
        gates = try c.decodeIfPresent([String: GateConfig].self, forKey: .gates) ?? [:]
    }

    public static func load(from url: URL = defaultURL) throws -> Config {
        try checkParents(of: url)
        let data = try readFileNoFollow(url.path, checkPerms: true)
        let config: Config
        do { config = try JSONDecoder().decode(Config.self, from: data) } catch {
            throw GateError("invalid config \(url.path): \(error)")
        }
        try config.validate()
        return config
    }

    public func save(to url: URL = defaultURL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try writeAtomically(try encoder.encode(self) + Data("\n".utf8),
                            directory: url.deletingLastPathComponent().path, name: url.lastPathComponent)
    }

    public func validate() throws {
        var seen: [(name: String, path: String)] = []
        for (name, store) in stores {
            guard store.path.hasPrefix("/") || store.path.hasPrefix("~/") else {
                throw GateError("store '\(name)': path must be absolute or start with ~/")
            }
            let path = expandTilde(store.path).path
            // nested stores would let init of the outer one delete the inner one's entries
            if let other = seen.first(where: { isWithin(path, $0.path) || isWithin($0.path, path) }) {
                throw GateError("stores '\(other.name)' and '\(name)' overlap (\(other.path), \(path))")
            }
            seen.append((name, path))
        }
        for (name, gate) in gates {
            guard gate.bin.hasPrefix("/") else { throw GateError("gate '\(name)': bin must be an absolute path") }
            // dispatch handles these names first, so such a gate could never run
            guard name != "pass" && name != "touchpass" else { throw GateError("gate name '\(name)' is reserved") }
            // an empty list would silently mean "never prompt"
            guard gate.only?.isEmpty != true else { throw GateError("gate '\(name)': only must not be empty; omit it to always prompt") }
        }
    }

    /// The store whose path is `dir`. Unknown dirs are refused, so PASSWORD_STORE_DIR
    /// (set by the caller) can only pick among stores the config already allows.
    public func store(at dir: URL) throws -> (name: String, config: StoreConfig) {
        let wanted = dir.standardizedFileURL.path
        guard let hit = stores.first(where: { expandTilde($0.value.path).path == wanted }) else {
            throw GateError("\(wanted) is not a configured store")
        }
        return (hit.key, hit.value)
    }
}

/// Whether directory `a` is `b` or lies below it. Existing parts compare by device and inode, so
/// case, Unicode and firmlink aliases (/System/Volumes/Data/…) cannot hide an overlap. Parts that
/// do not exist yet compare by Unicode case-folded, NFC-normalized name (ſ matches s, as on APFS),
/// which refuses more than needed on a case-sensitive volume.
public func isWithin(_ a: String, _ b: String) -> Bool {
    typealias Part = (id: (dev_t, ino_t)?, name: String)
    func parts(_ path: String) -> [Part] {
        var prefix = ""
        return URL(fileURLWithPath: path).standardizedFileURL.pathComponents.map { c in
            prefix = c == "/" ? "/" : (prefix == "/" ? "/" : prefix + "/") + c
            var st = stat()
            return (stat(prefix, &st) == 0 ? (st.st_dev, st.st_ino) : nil,
                    c.precomposedStringWithCanonicalMapping.folding(options: .caseInsensitive, locale: nil))
        }
    }
    let pa = parts(a), pb = parts(b)
    // anchor on b's deepest existing directory ("/" always exists), then match b's missing tail by name
    guard let k = pb.lastIndex(where: { $0.id != nil }), let anchor = pb[k].id else { return false }
    let rest = pb[(k + 1)...].map(\.name)
    return pa.indices.contains { i in
        guard let id = pa[i].id, id == anchor else { return false }
        return pa[(i + 1)...].map(\.name).starts(with: rest)
    }
}

/// Every directory from the file's parent up to and including home (or up to /) must be
/// one others cannot rewrite.
public func checkParents(of url: URL) throws {
    var dir = url.deletingLastPathComponent().standardizedFileURL
    while dir.path != "/" {
        try checkDirectory(dir.path)
        if dir.path == realHome { return }
        dir = dir.deletingLastPathComponent()
    }
}

public struct StoreConfig: Codable {
    public var path: String
    /// Fixed when the store key is created; changing it means a new store.
    public var policy: Policy = .biometryCurrentSet
    /// Code-signing requirements (csreq syntax) the calling process must match. Empty = nobody.
    /// Limitation: checked by pid, so it is a hurdle for other programs, not a boundary.
    public var callers: [String] = []
    /// What the prompt says is being unlocked, e.g. "your AWS SSO login". Defaults to the store name.
    public var label: String?
    /// Fingerprint of the store key, written by `touchpass init`. Nothing is read or
    /// written while it does not match `.enclave-key`.
    public var key: String?

    public init(path: String, policy: Policy = .biometryCurrentSet, callers: [String] = [],
                label: String? = nil, key: String? = nil) {
        self.path = path
        self.policy = policy
        self.callers = callers
        self.label = label
        self.key = key
    }

    enum CodingKeys: String, CodingKey { case path, policy, callers, label, key }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        policy = try c.decodeIfPresent(Policy.self, forKey: .policy) ?? .biometryCurrentSet
        callers = try c.decodeIfPresent([String].self, forKey: .callers) ?? []
        label = try c.decodeIfPresent(String.self, forKey: .label)
        key = try c.decodeIfPresent(String.self, forKey: .key)
    }
}

public enum Policy: String, Codable {
    case biometryCurrentSet  // any enrolled finger; re-enrolling invalidates the key
    case biometryAny         // survives fingerprint changes
    case userPresence        // Touch ID or login password
}

public struct GateConfig: Codable {
    /// Absolute path of the real binary.
    public var bin: String
    /// Only prompt for these subcommands (first non-flag argument); nil = always.
    /// Only reliable for tools whose flags use `-flag=value`: `git -C dir push` reads as "dir".
    public var only: [String]?
    /// false = no prompt of its own, e.g. for a tool whose secrets the store already guards.
    public var prompt: Bool = true
    /// Make the private `pass` link visible to this tool only (prepended to its PATH).
    public var withPass: Bool = false

    public init(bin: String, only: [String]? = nil, prompt: Bool = true, withPass: Bool = false) {
        self.bin = bin
        self.only = only
        self.prompt = prompt
        self.withPass = withPass
    }

    enum CodingKeys: String, CodingKey { case bin, only, prompt, withPass }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bin = try c.decode(String.self, forKey: .bin)
        only = try c.decodeIfPresent([String].self, forKey: .only)
        prompt = try c.decodeIfPresent(Bool.self, forKey: .prompt) ?? true
        withPass = try c.decodeIfPresent(Bool.self, forKey: .withPass) ?? false
    }

    public func requiresAuth(_ args: [String]) -> Bool {
        guard prompt else { return false }
        guard let only else { return true }
        // no recognisable subcommand: prompt rather than guess (fail closed)
        guard let sub = args.first(where: { !$0.hasPrefix("-") }) else { return true }
        return only.contains(sub)
    }
}
