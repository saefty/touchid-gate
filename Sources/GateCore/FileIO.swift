import Darwin
import Foundation

// Everything below works on directory file descriptors opened with O_NOFOLLOW, so a path
// checked once cannot be swapped (symlink, rename) before it is used.

func errnoText() -> String { String(cString: strerror(errno)) }

public func isType(_ st: stat, _ type: mode_t) -> Bool { (st.st_mode & S_IFMT) == type }

/// Files and directories this tool trusts must not be writable by anyone but their owner,
/// and the owner must be the user or root.
public func checkOwnerAndMode(_ st: stat, path: String) throws {
    let mode = Int(st.st_mode) & 0o777
    guard mode & 0o022 == 0 else {
        throw GateError("\(path) is writable by group/others (\(String(mode, radix: 8))); chmod go-w it")
    }
    guard st.st_uid == getuid() || st.st_uid == 0 else { throw GateError("\(path) is not owned by you or root") }
}

/// An allow entry can grant others what the mode bits deny; deny entries (macOS puts one on ~)
/// only restrict. `get` is an acl_get_* call; only ENOENT counts as "no ACL", any other failure refuses.
public func checkNoAllowACL(path: String, _ get: () -> acl_t?) throws {
    errno = 0
    guard let acl = get() else {
        if errno == ENOENT { return }
        throw GateError("cannot read the ACL of \(path): \(errnoText())")
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    var which = ACL_FIRST_ENTRY.rawValue
    while acl_get_entry(acl, which, &entry) == 0, let e = entry {
        which = ACL_NEXT_ENTRY.rawValue
        var tag = acl_tag_t(rawValue: 0)
        guard acl_get_tag_type(e, &tag) == 0 else { throw GateError("cannot read the ACL of \(path)") }
        guard tag != ACL_EXTENDED_ALLOW else {
            throw GateError("\(path) has an ACL that grants access (ls -le); remove it with chmod -N")
        }
    }
}

/// checkOwnerAndMode plus checkNoAllowACL for an open fd.
func checkOpened(_ fd: Int32, _ st: stat, path: String) throws {
    try checkOwnerAndMode(st, path: path)
    try checkNoAllowACL(path: path) { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) }
}

/// A real directory (not a symlink) that passes checkOwnerAndMode and checkNoAllowACL.
public func checkDirectory(_ path: String) throws {
    close(try openDirectory(path))
}

func checkedDirectory(_ fd: Int32, path: String) throws -> Int32 {
    var st = stat()
    guard fstat(fd, &st) == 0, isType(st, S_IFDIR) else { close(fd); throw GateError("\(path) is not a directory") }
    do { try checkOpened(fd, st, path: path) } catch { close(fd); throw error }
    return fd
}

/// Opens a directory without following a final symlink; the caller closes the fd.
public func openDirectory(_ path: String) throws -> Int32 {
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else {
        throw GateError(errno == ENOENT ? "\(path) does not exist" : "\(path) is not a directory (symlinks are refused): \(errnoText())",
                        notFound: errno == ENOENT)
    }
    return try checkedDirectory(fd, path: path)
}

/// Walks `components` below `root` by fd, refusing symlinks and foreign-writable directories;
/// creates missing ones (0700) when `create` is set. The caller closes the returned fd.
public func openDirectoryChain(root: String, _ components: [String], create: Bool) throws -> Int32 {
    let fd = try openDirectory(root)
    defer { close(fd) }
    return try openDirectoryChain(from: fd, basePath: root, components, create: create)
}

/// Same, starting from an already opened and checked directory (which stays open).
public func openDirectoryChain(from base: Int32, basePath: String, _ components: [String], create: Bool) throws -> Int32 {
    var fd = dup(base)
    guard fd >= 0 else { throw GateError("dup failed: \(errnoText())") }
    var path = basePath
    for c in components {
        path += "/" + c
        if create && mkdirat(fd, c, 0o700) != 0 && errno != EEXIST {
            close(fd); throw GateError("cannot create \(path): \(errnoText())")
        }
        let next = openat(fd, c, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let err = errno
        close(fd)
        guard next >= 0 else {
            throw GateError(err == ENOENT ? "\(path) does not exist" : "\(path) is not a directory (symlinks are refused)",
                            notFound: err == ENOENT)
        }
        fd = try checkedDirectory(next, path: path)
    }
    return fd
}

public func readAll(fd: Int32, maxBytes: Int) throws -> Data {
    var out = Data()
    var buf = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
        let n = read(fd, &buf, buf.count)
        if n < 0 { if errno == EINTR { continue }; throw GateError("read failed: \(errnoText())") }
        if n == 0 { return out }
        guard out.count + n <= maxBytes else { throw GateError("input larger than \(maxBytes) bytes") }
        out.append(contentsOf: buf[0..<n])
    }
}

/// O_NONBLOCK so a FIFO planted in place of a file cannot hang the open; the type check
/// then refuses anything that is not a regular file.
func readOpened(_ fd: Int32, path: String, maxBytes: Int, checkPerms: Bool) throws -> Data {
    defer { close(fd) }
    var st = stat()
    guard fstat(fd, &st) == 0, isType(st, S_IFREG) else { throw GateError("\(path) is not a regular file") }
    if checkPerms { try checkOpened(fd, st, path: path) }
    _ = fcntl(fd, F_SETFL, 0)
    return try readAll(fd: fd, maxBytes: maxBytes)
}

func openFailure(_ path: String) -> GateError {
    GateError(errno == ELOOP ? "\(path) is a symlink; refusing" : "cannot open \(path): \(errnoText())", notFound: errno == ENOENT)
}

/// Opens without following a final symlink, then checks the file it actually opened.
public func readFileNoFollow(_ path: String, maxBytes: Int = 1 << 20, checkPerms: Bool) throws -> Data {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw openFailure(path) }
    return try readOpened(fd, path: path, maxBytes: maxBytes, checkPerms: checkPerms)
}

/// Reads `name` inside the directory `dirFd`.
public func readFile(in dirFd: Int32, _ name: String, maxBytes: Int, checkPerms: Bool) throws -> Data {
    let fd = openat(dirFd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw openFailure(name) }
    return try readOpened(fd, path: name, maxBytes: maxBytes, checkPerms: checkPerms)
}

/// Temp file with O_EXCL|O_NOFOLLOW (0600) in `dirFd`, fsync, renameat over `name`, fsync the directory.
public func writeAtomically(_ data: Data, in dirFd: Int32, name: String) throws {
    let tmp = ".\(UUID().uuidString).tmp"
    let fd = openat(dirFd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw GateError("cannot create temp file for \(name): \(errnoText())") }
    var ok = false
    defer { if !ok { unlinkat(dirFd, tmp, 0) } }
    let written = data.withUnsafeBytes { raw -> Bool in
        var offset = 0
        while offset < raw.count {
            let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
            if n < 0 { if errno == EINTR { continue }; return false }
            offset += n
        }
        return true
    }
    let synced = written && fsync(fd) == 0
    let failure = errnoText()
    guard close(fd) == 0, synced else { throw GateError("cannot write \(name): \(synced ? errnoText() : failure)") }
    guard renameat(dirFd, tmp, dirFd, name) == 0 else { throw GateError("cannot replace \(name): \(errnoText())") }
    ok = true
    fsync(dirFd)
}

public func writeAtomically(_ data: Data, directory: String, name: String) throws {
    let dirFd = try openDirectory(directory)
    defer { close(dirFd) }
    try writeAtomically(data, in: dirFd, name: name)
}

/// Unlinks `name` in `dirFd` if it is a regular file; a missing file is fine (`rm -f`).
public func removeRegularFile(in dirFd: Int32, _ name: String) throws {
    var st = stat()
    guard fstatat(dirFd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else {
        if errno == ENOENT { return }
        throw GateError("cannot stat \(name): \(errnoText())")
    }
    guard isType(st, S_IFREG) else { throw GateError("\(name) is not a regular file; refusing to remove") }
    guard unlinkat(dirFd, name, 0) == 0 else { throw GateError("cannot remove \(name): \(errnoText())") }
}

/// Unlinks every `*.gpg` below `dirFd` without following symlinks (a symlinked directory is
/// not entered; a symlink named `*.gpg` is unlinked itself) and refuses foreign-writable
/// subdirectories. Returns how many were removed.
public func removeEntries(in dirFd: Int32) throws -> Int {
    let listFd = dup(dirFd)
    guard listFd >= 0 else { throw GateError("cannot list store: \(errnoText())") }
    guard let dir = fdopendir(listFd) else { let e = errnoText(); close(listFd); throw GateError("cannot list store: \(e)") }
    defer { closedir(dir) }
    rewinddir(dir)  // dup shares the offset, so a reused dirFd would start at the end
    var removed = 0
    while let entry = readdir(dir) {
        let name = withUnsafePointer(to: entry.pointee.d_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
        }
        if name == "." || name == ".." { continue }
        var st = stat()
        // a skipped entry would survive init and later read as "forged" instead of "log in again"
        guard fstatat(dirFd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { continue }
            throw GateError("cannot stat \(name): \(errnoText())")
        }
        if isType(st, S_IFDIR) {
            let fd = openat(dirFd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else {
                if errno == ENOENT { continue }
                throw GateError("cannot open \(name): \(errnoText())")
            }
            let sub = try checkedDirectory(fd, path: name)
            defer { close(sub) }
            removed += try removeEntries(in: sub)
        } else if name.hasSuffix(".gpg") {
            guard unlinkat(dirFd, name, 0) == 0 else { throw GateError("cannot remove \(name): \(errnoText())") }
            removed += 1
        }
    }
    return removed
}

/// Replaces `link` only if nothing or a symlink is there.
public func replaceSymlink(_ link: String, to target: String) throws {
    var st = stat()
    if lstat(link, &st) == 0 {
        guard isType(st, S_IFLNK) else { throw GateError("\(link) exists and is not a symlink; refusing to replace it") }
        guard unlink(link) == 0 else { throw GateError("cannot remove \(link): \(errnoText())") }
    }
    guard symlink(target, link) == 0 else { throw GateError("cannot create \(link): \(errnoText())") }
}
