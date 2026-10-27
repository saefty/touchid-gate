// Dispatches on the name it is invoked under:
//   pass show|insert|rm <name>            store mode, for tools using `pass` or the keyring pass backend
//   <gate name> …                         optional Touch ID, then exec the configured real binary
//   touchpass init <store>             create the store key (unless the pinned one is intact) and pin it
//   touchpass install <name>           link a gate into ~/.local/touchpass/bin, `pass` into libexec
//   touchpass auth <reason…>           Touch ID or login password check for scripts (exit 0 = approved)
import CryptoKit
import Darwin
import Foundation
import GateCore
import LocalAuthentication
import Security

let binDir = realHome + "/.local/touchpass/bin"
// deliberately not on PATH: only gates with "withPass" see it, so a real `pass` keeps working
let libexecDir = realHome + "/.local/touchpass/libexec"
let maxEntry = 1 << 20

func fail(_ e: Error) -> Never {
    fputs("touchpass: \(e)\n", stderr)
    exit((e as? GateError)?.exitCode ?? 1)
}

// MARK: Touch ID

func evaluate(_ ctx: LAContext, _ policy: LAPolicy, reason: String) throws {
    var err: NSError?
    guard ctx.canEvaluatePolicy(policy, error: &err) else {
        throw GateError(err?.localizedDescription ?? "authentication unavailable", exitCode: 2)
    }
    let done = DispatchSemaphore(value: 0)
    var failure: Error?
    ctx.evaluatePolicy(policy, localizedReason: reason.isEmpty ? "continue" : reason) { ok, e in
        if !ok { failure = e ?? GateError("denied") }
        done.signal()
    }
    done.wait()
    if let failure { throw GateError(failure.localizedDescription) }
}

// Touch ID, falls back to the login password (e.g. lid closed on an external display)
func authenticate(_ reason: String) throws { try evaluate(LAContext(), .deviceOwnerAuthentication, reason: reason) }

// MARK: caller

func processPath(_ pid: pid_t) -> String {
    var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : "pid \(pid)"
}

func processArgs(_ pid: pid_t) -> [String] {
    var mib = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }
    var buf = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return [] }
    return parseProcArgs(Array(buf.prefix(size)))
}

/// The parent must satisfy one of the store's code-signing requirements; returns how to name it.
/// Checks the pid, not an audit token (pipes carry none), so a process that execs into the
/// trusted binary passes: a hurdle, not a boundary (README, "Security model").
func verifyCaller(_ pid: pid_t, allowed: [String], store: String) throws -> String {
    guard pid > 1 else { throw GateError("caller exited; refusing") }
    guard !allowed.isEmpty else {
        throw GateError("store '\(store)' has no allowed callers; add a requirement to \"callers\"")
    }
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
          let code else { throw GateError("cannot inspect caller \(processPath(pid))") }
    var matched = false
    for text in allowed {
        var req: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &req) == errSecSuccess, let req else {
            throw GateError("invalid caller requirement: \(text)")
        }
        if SecCodeCheckValidity(code, [], req) == errSecSuccess { matched = true; break }
    }
    guard matched else {
        throw GateError("caller \(processPath(pid)) does not match any allowed signature for store '\(store)'")
    }
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let signing = info as? [String: Any] else { return callerLabel(identifier: nil, team: nil, platform: false) }
    return callerLabel(identifier: signing[kSecCodeInfoIdentifier as String] as? String,
                       team: signing[kSecCodeInfoTeamIdentifier as String] as? String,
                       platform: signing[kSecCodeInfoPlatformIdentifier as String] != nil)
}

// MARK: store

extension SecureEnclave.P256.KeyAgreement.PrivateKey: KeyAgreementKey {
    public func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try sharedSecretFromKeyAgreement(with: publicKey)
    }
}

func accessFlags(_ p: Policy) -> SecAccessControlCreateFlags {
    switch p {
    case .biometryCurrentSet: return [.privateKeyUsage, .biometryCurrentSet]
    case .biometryAny: return [.privateKeyUsage, .biometryAny]
    case .userPresence: return [.privateKeyUsage, .userPresence]
    }
}

func laPolicy(_ p: Policy) -> LAPolicy {
    p == .userPresence ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
}

func loadStoreKey(_ storeFd: Int32) throws -> StoreKey {
    try JSONDecoder().decode(StoreKey.self, from: readFile(in: storeFd, ".enclave-key", maxBytes: 64 * 1024, checkPerms: true))
}

/// The pinned key, with its public halves re-derived from the Secure Enclave blob, loaded
/// against `ctx` (not yet evaluated, so this check never prompts).
func pinnedKey(_ storeFd: Int32, _ store: StoreConfig, storeName: String,
               ctx: LAContext) throws -> (SecureEnclave.P256.KeyAgreement.PrivateKey, StoreKey) {
    guard let pin = store.key else { throw GateError("store '\(storeName)' is not initialised; run: touchpass init \(storeName)") }
    let key = try loadStoreKey(storeFd)
    let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: key.seKey, authenticationContext: ctx)
    // no "re-run init" hint: init replaces the key, so a tampered store should be looked at first
    guard se.publicKey.x963Representation == key.publicKey, key.fingerprint == pin else {
        throw GateError("store key of '\(storeName)' does not match the pinned key; refusing")
    }
    // the SE key's ACL is fixed at init; a config asking for another policy would get the old one
    guard key.policy == store.policy else {
        throw GateError("store '\(storeName)' key has policy \(key.policy?.rawValue ?? "unknown"), the config says "
            + "\(store.policy.rawValue); run: touchpass init \(storeName) (new key, entries are removed)")
    }
    return (se, key)
}

func promptText(_ verb: String, _ store: StoreConfig, storeName: String, caller: String, pid: pid_t) -> String {
    let command = displayCommand(processArgs(pid), home: realHome)
    return "\(verb) \(store.label ?? storeName) for \(caller).\n\nCommand, as the caller reports it:\n\(command)\n"
}

/// Secure Enclave operations fail this way when the enrolled fingerprints changed.
func enclave<T>(_ dir: String, _ body: () throws -> T) throws -> T {
    do { return try body() } catch let e as GateError { throw e } catch {
        throw GateError("Secure Enclave refused (\(error.localizedDescription)); if fingerprints changed under "
            + "policy biometryCurrentSet: rm -r \(dir), run touchpass init, log in again")
    }
}

// the flags keyring sends, per command; anything else is refused rather than ignored
let allowedFlags: [String: Set<String>] = ["show": [], "insert": ["-m", "-f", "--multiline", "--force"], "rm": ["-f", "--force"]]

func passMode(_ args: [String]) throws {
    let usage = GateError.usage("usage: pass show <name> | insert [-m] [-f] <name> | rm [-f] <name>")
    guard let cmd = args.first, let allowed = allowedFlags[cmd] else { throw usage }
    let flags = args.dropFirst().filter { $0.hasPrefix("-") }
    let names = args.dropFirst().filter { !$0.hasPrefix("-") }
    guard names.count == 1, flags.allSatisfy(allowed.contains) else { throw usage }
    let name = try normalizedName(names[0])
    let dirURL = expandTilde(ProcessInfo.processInfo.environment["PASSWORD_STORE_DIR"] ?? "~/.password-store")
    let config = try Config.load()
    let (storeName, store) = try config.store(at: dirURL)
    let dir = dirURL.path
    try checkParents(of: dirURL)
    let caller = getppid()
    let who = try verifyCaller(caller, allowed: store.callers, store: storeName)
    let file = try itemURL(store: dirURL, name: name).lastPathComponent
    let subdirs = Array(name.split(separator: "/").dropLast().map(String.init))
    // one fd for the store: key, subdirectories and entries are all opened relative to it
    let storeFd = try openDirectory(dir)
    defer { close(storeFd) }
    func entryDir(create: Bool) throws -> Int32 {
        try openDirectoryChain(from: storeFd, basePath: dir, subdirs, create: create)
    }

    switch cmd {
    case "insert":
        let plain = try readAll(fd: STDIN_FILENO, maxBytes: maxEntry)
        let ctx = LAContext()
        let (se, key) = try pinnedKey(storeFd, store, storeName: storeName, ctx: ctx)
        try evaluate(ctx, laPolicy(store.policy), reason: promptText("save", store, storeName: storeName, caller: who, pid: caller))
        let mac = try enclave(dir) { try macKey(se, peer: key.macPeer!) }
        let box = try seal(plain, to: key.publicKey, name: name, mac: mac)
        guard getppid() == caller else { throw GateError("caller changed during prompt; refusing") }
        let parent = try entryDir(create: true)
        defer { close(parent) }
        try writeAtomically(try JSONEncoder().encode(box), in: parent, name: file)
    case "rm":
        // a tampered or uninitialised store is refused here too; deleting needs no prompt (worst case: re-login)
        _ = try pinnedKey(storeFd, store, storeName: storeName, ctx: LAContext())
        let parent: Int32
        do { parent = try entryDir(create: false) } catch let e as GateError where e.notFound { return }
        defer { close(parent) }
        try removeRegularFile(in: parent, file)
    default:  // show
        let raw: Data
        do {
            let parent = try entryDir(create: false)
            defer { close(parent) }
            raw = try readFile(in: parent, file, maxBytes: 2 * maxEntry, checkPerms: false)
        } catch let e as GateError where e.notFound {
            throw GateError("\(name) is not in the password store")
        }
        let box = try JSONDecoder().decode(Box.self, from: raw)
        let ctx = LAContext()
        let (se, key) = try pinnedKey(storeFd, store, storeName: storeName, ctx: ctx)
        try evaluate(ctx, laPolicy(store.policy), reason: promptText("unlock", store, storeName: storeName, caller: who, pid: caller))
        let mac = try enclave(dir) { try macKey(se, peer: key.macPeer!) }
        let plain = try enclave(dir) { try openBox(box, with: se, name: name, mac: mac) }
        guard getppid() == caller else { throw GateError("caller changed during prompt; refusing") }
        FileHandle.standardOutput.write(plain)
    }
}

/// Creates the store key and pins its fingerprint in the config; a no-op while the pinned key is intact.
func initStore(_ storeName: String) throws {
    var config = try Config.load()
    guard var store = config.stores[storeName] else { throw GateError("no store '\(storeName)' in the config") }
    let dirURL = expandTilde(store.path)
    let dir = dirURL.path
    try checkParents(of: dirURL)  // the store dir itself may not exist yet
    if mkdir(dir, 0o700) != 0 && errno != EEXIST { throw GateError("cannot create \(dir): \(String(cString: strerror(errno)))") }
    let storeFd = try openDirectory(dir)
    defer { close(storeFd) }

    if let pin = store.key, let existing = try? loadStoreKey(storeFd), existing.fingerprint == pin,
       existing.policy == store.policy,
       (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existing.seKey))?.publicKey.x963Representation
           == existing.publicKey {
        print("store '\(storeName)' is already initialised (\(pin))")
        return
    }
    // never adopt a key found on disk: it may have been planted, e.g. with a macPeer whose
    // private half was kept, or an SE key without the configured access control
    guard SecureEnclave.isAvailable else { throw GateError("no Secure Enclave on this Mac", exitCode: 2) }
    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, accessFlags(store.policy), &cfErr)
    else { throw GateError("access control: \(cfErr!.takeRetainedValue())") }
    let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    let key = StoreKey(seKey: se.dataRepresentation, publicKey: se.publicKey.x963Representation,
                       macPeer: newMacPeer(), policy: store.policy)
    // entries sealed to any previous key are unreadable now; they are caches
    let removed = try removeEntries(in: storeFd)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    try writeAtomically(try encoder.encode(key), in: storeFd, name: ".enclave-key")
    store.key = key.fingerprint
    config.stores[storeName] = store
    try config.save()
    print("store '\(storeName)' initialised with a new key, pinned to \(store.key!)")
    if removed > 0 { print("\(removed) old entries removed; log in again") }
}

// MARK: gates

func gateMode(_ name: String, _ args: [String]) throws -> Never {
    let config = try Config.load()
    guard let gate = config.gates[name] else { throw GateError("'\(name)' is not a configured gate") }
    guard let resolved = realpath(gate.bin, nil).map({ p -> String in defer { free(p) }; return String(cString: p) }) else {
        throw GateError("cannot resolve \(gate.bin)")
    }
    var st = stat()
    guard stat(resolved, &st) == 0, isType(st, S_IFREG) else {
        throw GateError("\(resolved) is not a regular file")
    }
    try checkOwnerAndMode(st, path: resolved)
    try checkNoAllowACL(path: resolved) { acl_get_file(resolved, ACL_TYPE_EXTENDED) }
    // by inode, so a hardlink to touchpass cannot exec itself in a loop
    var me = stat()
    if let exe = Bundle.main.executablePath, stat(exe, &me) == 0, me.st_dev == st.st_dev, me.st_ino == st.st_ino {
        throw GateError("gate '\(name)' points at touchpass itself")
    }
    if gate.withPass {
        setenv("PATH", libexecDir + ":" + (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"), 1)
    }
    if gate.requiresAuth(args) {
        try authenticate("run \(printable(name)) \(middleTruncated(args.map(printable).joined(separator: " "), max: 120))")
    }
    // argv[0] stays the gate name: some tools switch behaviour on it (granted/assumego)
    var cargs = ([name] + args).map { strdup($0) } + [nil]
    execv(resolved, &cargs)
    throw GateError("exec \(resolved): \(String(cString: strerror(errno)))")
}

func install(_ name: String) throws {
    let config = try Config.load()
    guard name == "pass" || config.gates[name] != nil else {
        throw GateError("'\(name)' is neither 'pass' nor a configured gate")
    }
    guard let exe = Bundle.main.executableURL?.resolvingSymlinksInPath().path else { throw GateError("cannot locate myself") }
    let dir = name == "pass" ? libexecDir : binDir
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o755])
    try checkDirectory(dir)
    let link = dir + "/" + name
    try replaceSymlink(link, to: exe)
    print("\(link) -> \(exe)")
    let path = ProcessInfo.processInfo.environment["PATH"]?.split(separator: ":").map(String.init) ?? []
    if name != "pass" && path.first != binDir {
        print("put \(binDir) first in PATH so it wins over the real \(name)")
    }
}

// MARK: dispatch

let argv = CommandLine.arguments
let invokedAs = (argv[0] as NSString).lastPathComponent
let rest = Array(argv.dropFirst())
do {
    switch invokedAs {
    case "pass":
        try passMode(rest)
    case "touchpass":
        switch rest.first {
        case "init" where rest.count == 2: try initStore(rest[1])
        case "install" where rest.count == 2: try install(rest[1])
        case "auth": try authenticate(rest.dropFirst().map(printable).joined(separator: " "))
        default: throw GateError.usage("usage: touchpass init <store> | install <name> | auth <reason…>")
        }
    default:
        try gateMode(invokedAs, rest)
    }
} catch {
    fail(error)
}
