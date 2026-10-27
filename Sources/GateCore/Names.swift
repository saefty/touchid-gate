import Darwin
import Foundation

/// Home from the password database. HOME and CFFIXED_USER_HOME are set by the caller,
/// and Foundation's tilde expansion honours them.
public let realHome: String = {
    guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { preconditionFailure("no passwd entry") }
    return String(cString: dir)
}()

public func expandTilde(_ path: String) -> URL {
    let expanded = path == "~" ? realHome : path.hasPrefix("~/") ? realHome + String(path.dropFirst()) : path
    return URL(fileURLWithPath: expanded).standardizedFileURL
}

/// keyring builds entry names with Go's filepath.Join, which already collapses "//";
/// normalise the same way so our file paths match its own itemExists/Keys checks.
public func normalizedName(_ name: String) throws -> String {
    guard !name.hasPrefix("/") else { throw GateError.usage("invalid name '\(name)'") }
    let parts = name.split(separator: "/")
    guard !parts.isEmpty, !parts.contains(where: { $0 == ".." || $0 == "." }) else {
        throw GateError.usage("invalid name '\(name)'")
    }
    return parts.joined(separator: "/")
}

/// `<store>/<name>.gpg` — the extension is what keyring's pass backend looks for.
public func itemURL(store: URL, name: String) throws -> URL {
    let url = store.appendingPathComponent(name + ".gpg").standardizedFileURL
    guard url.path.hasPrefix(store.standardizedFileURL.path + "/") else {
        throw GateError.usage("name escapes store: '\(name)'")
    }
    return url
}

// Cc, Cf (bidi overrides), line/paragraph separators (AppKit breaks lines on U+2028/9), unassigned
private let unprintable = CharacterSet.controlCharacters.union(.newlines).union(.illegalCharacters)

// Fillers such as U+3164, U+FFA0, U+115F and U+2800 render blank but are not whitespace.
private func blank(_ u: Unicode.Scalar) -> Bool {
    unprintable.contains(u) || u.properties.isDefaultIgnorableCodePoint || u == "\u{2800}"
}

private func isMark(_ u: Unicode.Scalar) -> Bool {
    switch u.properties.generalCategory {
    case .nonspacingMark, .spacingMark, .enclosingMark: return true
    default: return false
    }
}

/// Unprintable and blank-rendering characters become spaces, whitespace runs collapse to one,
/// and runs of combining marks are cut to 3 (a deeper stack draws over the lines above), so
/// text shown in a prompt cannot fake line breaks, overdraw, or reorder itself. Visible
/// padding can still push text onto another line; the caller's text is labelled as a claim.
public func printable(_ s: String) -> String {
    // counted per scalar, not per grapheme: cutting clusters and re-joining them lets the
    // pieces merge into new, unbounded clusters
    var out = String.UnicodeScalarView()
    var marks = 0
    for scalar in s.unicodeScalars {
        let u = blank(scalar) ? " " : scalar
        if isMark(u) {
            marks += 1
            if marks > 3 { continue }
        } else {
            marks = 0
        }
        out.append(u)
    }
    return String(out).split(whereSeparator: \.isWhitespace).joined(separator: " ")
}

/// The caller as a prompt names it: signing identifier and team, never its path, which any
/// copy or hardlink of the genuine binary chooses freely.
public func callerLabel(identifier: String?, team: String?, platform: Bool) -> String {
    guard let identifier else { return "unknown caller" }
    let id = middleTruncated(printable(identifier), max: 80)
    if let team { return "\(id) (Team \(printable(team)))" }
    return platform ? "\(id) (Apple)" : "\(id) (ad-hoc signed)"
}

/// argv as a person would read it in a prompt: program basename, `~` for home,
/// long `NAME=value` assignments (e.g. an expanded PATH) collapsed to `NAME=…`.
public func displayCommand(_ argv: [String], home: String) -> String {
    guard let first = argv.first else { return "" }
    // only a leading home path component, so /tmp/Users/me or /Users/meX do not look home-relative
    func tilde<S: StringProtocol>(_ s: S) -> String {
        home.isEmpty || !(s == home || s.hasPrefix(home + "/")) ? String(s) : "~" + s.dropFirst(home.count)
    }
    let words = [(printable(first) as NSString).lastPathComponent] + argv.dropFirst().map { raw -> String in
        let arg = printable(raw)
        guard let eq = arg.firstIndex(of: "=") else { return tilde(arg) }
        if arg[..<eq].allSatisfy({ $0.isUppercase || $0.isNumber || $0 == "_" }), arg.distance(from: eq, to: arg.endIndex) > 24 {
            return arg[...eq] + "…"
        }
        return arg[...eq] + tilde(arg[arg.index(after: eq)...])
    }
    return middleTruncated(words.joined(separator: " "), max: 200)
}

/// Shortens from the middle: the start names the profile, the end the actual command.
/// Counts scalars, because one grapheme can be arbitrarily long (Hangul jamo or Prepend runs).
public func middleTruncated(_ s: String, max: Int) -> String {
    let scalars = s.unicodeScalars
    guard scalars.count > max, max > 1 else { return s }
    let head = (max - 1) * 2 / 5
    return String(String.UnicodeScalarView(scalars.prefix(head))) + "…"
        + String(String.UnicodeScalarView(scalars.suffix(max - 1 - head)))
}

/// A Homebrew keg path (`…/Cellar/<formula>/<version>/bin/<tool>`) disappears on upgrade;
/// its `…/opt/<formula>/bin/<tool>` alias does not. Any other path comes back unchanged.
public func stableExecutablePath(_ resolved: String) -> String {
    let parts = resolved.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    guard let i = parts.lastIndex(of: "Cellar"), parts.count == i + 5, parts[i + 3] == "bin" else { return resolved }
    return (parts[..<i] + ["opt", parts[i + 1], "bin", parts[i + 4]]).joined(separator: "/")
}

/// KERN_PROCARGS2 layout: argc (Int32), exec path, NUL padding, then argc NUL-terminated
/// strings (which may be empty).
public func parseProcArgs(_ buf: [UInt8]) -> [String] {
    guard buf.count >= 4 else { return [] }
    let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = 4
    while i < buf.count && buf[i] != 0 { i += 1 }  // exec path
    while i < buf.count && buf[i] == 0 { i += 1 }  // padding
    var args: [String] = []
    while args.count < argc && i < buf.count {
        let start = i
        while i < buf.count && buf[i] != 0 { i += 1 }
        args.append(String(decoding: buf[start..<i], as: UTF8.self))
        i += 1
    }
    return args
}
