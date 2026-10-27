// `swift run selftest`; a software P-256 key stands in for the Secure Enclave.
import CryptoKit
import Darwin
import Foundation
import GateCore

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if !ok { failures += 1; print("FAIL line \(line): \(what)") }
}
func throwsError(_ body: () throws -> Void) -> Bool {
    do { try body(); return false } catch { return true }
}

// home comes from the password database, not from the caller's environment
setenv("CFFIXED_USER_HOME", "/tmp/evil", 1)
setenv("HOME", "/tmp/evil", 1)
check(expandTilde("~/x").path == realHome + "/x" && !realHome.hasPrefix("/tmp/evil"), "tilde ignores env")
check(Config.defaultURL.path.hasPrefix(realHome + "/"), "config path ignores env")

// names: match Go's filepath.Join, never leave the store
check(try normalizedName("granted-aws-sso-tokens/https://d-x.awsapps.com/start")
      == "granted-aws-sso-tokens/https:/d-x.awsapps.com/start", "collapses //")
for bad in ["", "/abs", "../x", "a/../../b", "./x", "a/./b"] {
    check(throwsError { _ = try normalizedName(bad) }, "rejects '\(bad)'")
}
check(try itemURL(store: URL(fileURLWithPath: "/tmp/store"), name: "a/b").path == "/tmp/store/a/b.gpg", "item path")

// prompt text
check(middleTruncated("short", max: 10) == "short", "no truncation when it fits")
let long = middleTruncated("assumego login --exec -- env PATH=/Users/x/bin make tf STACK=demo-stack MODE=apply", max: 40)
check(long.count == 40 && long.hasPrefix("assumego") && long.hasSuffix("MODE=apply"), "keeps both ends: \(long)")
check(displayCommand(["/opt/homebrew/Cellar/granted/1.2.3/bin/assumego", "login", "--exec", "--", "env",
                      "PATH=/Users/me/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin", "make", "deploy"], home: "/Users/me")
      == "assumego login --exec -- env PATH=… make deploy", "collapses long env assignment")
check(displayCommand(["x", "STACK=e2e", "/Users/me/src/f.tf"], home: "/Users/me") == "x STACK=e2e ~/src/f.tf",
      "keeps short assignments, tildes home")
check(displayCommand(["x", "--url=https://example.com/a/very/long/path/here"], home: "") ==
      "x --url=https://example.com/a/very/long/path/here", "flags with = are not env assignments")
check(displayCommand(["x", "/private/tmp/Users/me/x", "/Users/meX/y", "/Users/me", "--dir=/Users/me/z", "a=/tmp/Users/me"],
                     home: "/Users/me") == "x /private/tmp/Users/me/x /Users/meX/y ~ --dir=~/z a=/tmp/Users/me",
      "home replaced only as a leading path component")
check(printable("dev\n\nunlock prod\u{202E}") == "dev unlock prod", "newlines and bidi overrides neutralised")
check(printable("a\u{2028}b\u{2029}c") == "a b c", "line/paragraph separators neutralised")
check(printable("a" + String(repeating: " ", count: 70) + "b\u{3000}\u{3000}c") == "a b c", "whitespace runs collapsed")
check(printable("Mu\u{0308}nchen") == "Mu\u{0308}nchen", "combining marks kept")
for filler in ["\u{2800}", "\u{3164}", "\u{FFA0}", "\u{115F}", "\u{1160}"] {
    check(printable("a" + String(repeating: filler, count: 70) + "b") == "a b", "blank filler U+\(String(filler.unicodeScalars.first!.value, radix: 16)) collapsed")
}
let stacked = printable("dev" + String(repeating: "\u{0301}", count: 60))
check(stacked.unicodeScalars.count == 6 && stacked.hasPrefix("de"), "combining marks capped per character")
check(displayCommand(["x", "a" + String(repeating: "\u{0301}", count: 100_000)], home: "").unicodeScalars.count == 6,
      "mark flood does not survive the display cap")
check(printable("स्त्र") == "स्त्र", "Indic conjunct (single cluster, marks not stacked) kept whole")
// cutting per cluster and re-joining let Prepend / Hangul L runs merge into one unbounded cluster
for runner in ["\u{0D4E}", "\u{1100}"] {
    let flood = printable(String(repeating: runner + "\u{0301}\u{0301}\u{0301}\u{0301}", count: 2_000) + "a")
    check(middleTruncated(flood, max: 200).unicodeScalars.count == 200,
          "U+\(String(runner.unicodeScalars.first!.value, radix: 16)) cluster runs cannot exceed the scalar cap")
}
check(callerLabel(identifier: "granted", team: "ABCDE12345", platform: false) == "granted (Team ABCDE12345)", "caller by identifier")
check(callerLabel(identifier: "evil\n\u{2028}Command: granted sso-tokens list", team: nil, platform: false)
      == "evil Command: granted sso-tokens list (ad-hoc signed)", "caller identifier cannot fake lines")
check(callerLabel(identifier: nil, team: "ABCDE12345", platform: false) == "unknown caller", "no identifier, no name")
var procargs: [UInt8] = []
withUnsafeBytes(of: Int32(3)) { procargs += $0 }
procargs += Array("/bin/x".utf8) + [0, 0, 0] + Array("x".utf8) + [0, 0] + Array("b".utf8) + [0] + Array("ENV=1".utf8) + [0]
check(parseProcArgs(procargs) == ["x", "", "b"], "procargs keeps empty args, stops at argc")

// sealing: round trip, MAC required, forgery and tampering refused
let se = P256.KeyAgreement.PrivateKey()
let peer = newMacPeer()
let mac = try macKey(se, peer: peer)
let secret = Data("{\"token\":\"s3cr3t\"}".utf8)
let box = try seal(secret, to: se.publicKey.x963Representation, name: "svc/a", mac: mac)
check(try openBox(box, with: se, name: "svc/a", mac: mac) == secret, "round trip")
check(!box.sealed.contains(secret), "no plaintext in box")
check(throwsError { _ = try openBox(box, with: se, name: "svc/b", mac: mac) }, "box bound to its name")
var tampered = box
tampered.sealed[tampered.sealed.count - 1] ^= 1
check(throwsError { _ = try openBox(tampered, with: se, name: "svc/a", mac: mac) }, "tampering detected")
var unmacced = box
unmacced.mac = nil
check(throwsError { _ = try openBox(unmacced, with: se, name: "svc/a", mac: mac) }, "entries without MAC refused")
var shifted = box
shifted.ephemeral = box.ephemeral.dropLast()
shifted.sealed = box.ephemeral.suffix(1) + box.sealed
check(throwsError { _ = try openBox(shifted, with: se, name: "svc/a", mac: mac) }, "ephemeral/sealed boundary shift refused")
// an attacker knows the public key and the macPeer, but not ECDH(se, peer)
let attackerMac = try macKey(P256.KeyAgreement.PrivateKey(), peer: peer)
let forged = try seal(Data("attacker token".utf8), to: se.publicKey.x963Representation, name: "svc/a", mac: attackerMac)
check(throwsError { _ = try openBox(forged, with: se, name: "svc/a", mac: mac) }, "forged entry refused")
let k1 = StoreKey(seKey: Data(), publicKey: se.publicKey.x963Representation, macPeer: peer)
let k2 = StoreKey(seKey: Data(), publicKey: se.publicKey.x963Representation, macPeer: newMacPeer())
check(k1.fingerprint != nil && k1.fingerprint != k2.fingerprint, "fingerprint covers macPeer")
check(StoreKey(seKey: Data(), publicKey: Data(), macPeer: nil).fingerprint == nil, "no fingerprint without macPeer")
let k3 = StoreKey(seKey: Data(), publicKey: se.publicKey.x963Representation, macPeer: peer, policy: .biometryCurrentSet)
let k4 = StoreKey(seKey: Data(), publicKey: se.publicKey.x963Representation, macPeer: peer, policy: .userPresence)
check(k3.fingerprint != k4.fingerprint && k3.fingerprint != k1.fingerprint, "fingerprint covers policy")
let k3json = try JSONDecoder().decode(StoreKey.self, from: JSONEncoder().encode(k3))
check(k3json.policy == .biometryCurrentSet && k3json.fingerprint == k3.fingerprint, "policy survives the key file")
check(try JSONDecoder().decode(StoreKey.self, from: JSONEncoder().encode(k1)).policy == nil, "key file without policy decodes with policy nil")

// config: strict defaults, unknown/duplicate/relative stores refused
let json = """
{"stores": {"granted": {"path": "/tmp/store"}},
 "gates": {"terraform": {"bin": "/opt/homebrew/bin/terraform", "only": ["apply", "destroy"]},
           "granted": {"bin": "/opt/homebrew/bin/granted", "prompt": false, "withPass": true}}}
"""
let config = try JSONDecoder().decode(Config.self, from: Data(json.utf8))
check(config.stores["granted"]?.policy == .biometryCurrentSet, "default policy")
check(config.stores["granted"]?.callers.isEmpty == true, "default callers empty (= nobody)")
check(try config.store(at: URL(fileURLWithPath: "/tmp/store/")).name == "granted", "store lookup")
check(throwsError { _ = try config.store(at: URL(fileURLWithPath: "/tmp/other")) }, "unknown store refused")
check(throwsError { try Config(stores: ["a": StoreConfig(path: "/s"), "b": StoreConfig(path: "/s/")]).validate() },
      "duplicate store paths refused")
check(throwsError { try Config(stores: ["a": StoreConfig(path: "/s"), "b": StoreConfig(path: "/s/work")]).validate() },
      "nested store paths refused")
check(throwsError { try Config(stores: ["a": StoreConfig(path: "/s/work"), "b": StoreConfig(path: "/s")]).validate() },
      "nested store paths refused in either order")
check(!throwsError { try Config(stores: ["a": StoreConfig(path: "/s"), "b": StoreConfig(path: "/sx")]).validate() },
      "sibling paths with a shared prefix are fine")
check(throwsError { try Config(stores: ["a": StoreConfig(path: "/s/Store"), "b": StoreConfig(path: "/s/store/x")]).validate() },
      "nested store paths refused across case")
check(throwsError { try Config(stores: ["a": StoreConfig(path: "rel/s")]).validate() }, "relative store path refused")
check(throwsError { try Config(gates: ["g": GateConfig(bin: "g")]).validate() }, "relative gate bin refused")
let tf = config.gates["terraform"]!
check(tf.requiresAuth(["apply", "-auto-approve"]), "gated subcommand")
check(tf.requiresAuth(["-chdir=x", "destroy"]), "subcommand after flags")
check(!tf.requiresAuth(["plan"]), "ungated subcommand")
check(GateConfig(bin: "/x").requiresAuth([]), "no filter = always")
check(tf.requiresAuth(["-chdir=x"]), "only-filter with no subcommand prompts (fail closed)")
check(!config.gates["granted"]!.requiresAuth(["login"]) && config.gates["granted"]!.withPass, "prompt:false + withPass")
check(try JSONDecoder().decode(Config.self, from: Data("{}".utf8)).gates.isEmpty, "stores/gates may be omitted")
check(throwsError { try Config(gates: ["pass": GateConfig(bin: "/x")]).validate() }, "reserved gate name refused")
check(throwsError { try Config(gates: ["g": GateConfig(bin: "/x", only: [])]).validate() }, "empty only refused")

// file handling: symlinks, foreign-writable files, directories as items
let tmp = NSTemporaryDirectory() + "touchpass-selftest-\(getpid())"
mkdir(tmp, 0o700)
try writeAtomically(Data("x".utf8), directory: tmp, name: "f")
var st = stat()
check(stat(tmp + "/f", &st) == 0 && Int(st.st_mode) & 0o777 == 0o600, "written 0600")
check(try readFileNoFollow(tmp + "/f", checkPerms: true) == Data("x".utf8), "read back")
symlink(tmp + "/f", tmp + "/link")
check(throwsError { _ = try readFileNoFollow(tmp + "/link", checkPerms: true) }, "symlinked file refused")
chmod(tmp + "/f", 0o666)
check(throwsError { _ = try readFileNoFollow(tmp + "/f", checkPerms: true) }, "world-writable file refused")
check(throwsError { _ = try readFileNoFollow(tmp + "/f", maxBytes: 0, checkPerms: false) }, "size cap")
func addACL(_ entry: String, _ path: String) {
    let p = try! Process.run(URL(fileURLWithPath: "/bin/chmod"), arguments: ["+a", entry, path])
    p.waitUntilExit()
    check(p.terminationStatus == 0, "chmod +a '\(entry)' \(path)")
}
try writeAtomically(Data("x".utf8), directory: tmp, name: "acl-deny")
addACL("everyone deny delete", tmp + "/acl-deny")
check(!throwsError { _ = try readFileNoFollow(tmp + "/acl-deny", checkPerms: true) }, "deny-only ACL accepted (as on ~)")
try writeAtomically(Data("x".utf8), directory: tmp, name: "acl-allow")
addACL("everyone allow write", tmp + "/acl-allow")
check(throwsError { _ = try readFileNoFollow(tmp + "/acl-allow", checkPerms: true) }, "allow ACL on a file refused")
mkdir(tmp + "/acl-dir", 0o700)
addACL("everyone allow add_file", tmp + "/acl-dir")
check(throwsError { try checkDirectory(tmp + "/acl-dir") }, "allow ACL on a directory refused")
try? FileManager.default.removeItem(atPath: tmp + "/acl-dir")
check(!throwsError { try checkNoAllowACL(path: "x") { errno = ENOENT; return nil } }, "ENOENT means no ACL")
for code in [EIO, EACCES, ENOTSUP, 0] {
    check(throwsError { try checkNoAllowACL(path: "x") { errno = code; return nil } }, "ACL lookup errno \(code) refused")
}

// store overlap by filesystem identity; alias checks run only where the volume resolves the alias
mkdir(tmp + "/Sdir", 0o700)
check(isWithin(tmp + "/Sdir/new/x", tmp + "/Sdir") && !isWithin(tmp + "/Sdir", tmp + "/Sdir/new"), "nested path with a missing tail")
var aliasSt = stat()
if stat(tmp + "/\u{017F}dir", &aliasSt) == 0 {  // long s folds to s on a case-insensitive volume
    check(isWithin(tmp + "/\u{017F}dir/x", tmp + "/Sdir"), "Unicode case alias detected")
}
if let real = realpath(tmp, nil).map({ p -> String in defer { free(p) }; return String(cString: p) }),
   stat("/System/Volumes/Data" + real + "/Sdir", &aliasSt) == 0 {
    check(isWithin("/System/Volumes/Data" + real + "/Sdir/x", tmp + "/Sdir"), "firmlink alias detected")
}
check(throwsError { try Config(stores: ["a": StoreConfig(path: tmp + "/Sdir"), "b": StoreConfig(path: tmp + "/sdir/x")]).validate() },
      "existing store and case alias refused")
rmdir(tmp + "/Sdir")
check(isWithin(tmp + "/\u{017F}gone/child", tmp + "/Sgone") && !isWithin(tmp + "/Sgone", tmp + "/\u{017F}gone/child"),
      "missing paths: long s matches s")
check(throwsError { try Config(stores: ["a": StoreConfig(path: tmp + "/Sgone"), "b": StoreConfig(path: tmp + "/\u{017F}gone/child")]).validate() }
      && throwsError { try Config(stores: ["a": StoreConfig(path: tmp + "/\u{017F}gone/child"), "b": StoreConfig(path: tmp + "/Sgone")]).validate() },
      "missing stores, Unicode case alias refused in either order")
mkfifo(tmp + "/fifo.gpg", 0o600)
check(throwsError { _ = try readFileNoFollow(tmp + "/fifo.gpg", checkPerms: false) }, "FIFO refused without hanging")
let root = try openDirectory(tmp)
mkdir(tmp + "/d.gpg", 0o700)
check(throwsError { try removeRegularFile(in: root, "d.gpg") }, "rm refuses a directory")
check(!throwsError { try removeRegularFile(in: root, "missing.gpg") }, "rm -f of a missing entry is fine")
let outside = tmp + "-outside"
mkdir(outside, 0o700)
FileManager.default.createFile(atPath: outside + "/victim.gpg", contents: Data())
symlink(outside, tmp + "/sub")
check(throwsError { _ = try openDirectoryChain(from: root, basePath: tmp, ["sub"], create: true) }, "symlinked subdirectory refused")
let deeper = try openDirectoryChain(from: root, basePath: tmp, ["new", "deeper"], create: true)
try writeAtomically(Data("e".utf8), in: deeper, name: "e.gpg")
check(try readFile(in: deeper, "e.gpg", maxBytes: 10, checkPerms: false) == Data("e".utf8), "fd-relative write/read")
close(deeper)
check((try? openDirectoryChain(from: root, basePath: tmp, ["absent"], create: false)) == nil, "no create when asked not to")
do { _ = try openDirectoryChain(from: root, basePath: tmp, ["absent"], create: false) } catch let e as GateError {
    check(e.notFound, "missing directory reports notFound")
}
symlink(tmp + "/f", tmp + "/link.gpg")
// removes new/deeper/e.gpg, fifo.gpg and the link.gpg symlink itself; d.gpg is a directory
// (entered, not removed); never follows sub -> outside
check(try removeEntries(in: root) == 3, "removeEntries count")
check(FileManager.default.fileExists(atPath: outside + "/victim.gpg"), "removeEntries does not follow symlinked dirs")
check(FileManager.default.fileExists(atPath: tmp + "/f"), "removing a *.gpg symlink leaves its target")
mkdir(tmp + "/shared", 0o700)
chmod(tmp + "/shared", 0o777)
check(throwsError { _ = try removeEntries(in: root) }, "removeEntries refuses a foreign-writable subdirectory")
rmdir(tmp + "/shared")
mkdir(tmp + "/locked", 0o000)
check(throwsError { _ = try removeEntries(in: root) }, "removeEntries refuses an unreadable subdirectory")
chmod(tmp + "/locked", 0o700)
close(root)
try replaceSymlink(tmp + "/l2", to: "/x")
try replaceSymlink(tmp + "/l2", to: "/y")
check((try? FileManager.default.destinationOfSymbolicLink(atPath: tmp + "/l2")) == "/y", "replaceSymlink replaces a link")
check(throwsError { try replaceSymlink(tmp + "/f", to: "/x") }, "replaceSymlink refuses a regular file")

try? FileManager.default.removeItem(atPath: tmp)
try? FileManager.default.removeItem(atPath: outside)
print(failures == 0 ? "selftest: all checks passed" : "selftest: \(failures) failed")
exit(failures == 0 ? 0 : 1)
