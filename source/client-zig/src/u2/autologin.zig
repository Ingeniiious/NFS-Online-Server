//! ExA Cup automatic login for Underground 2 (ExA Cup repo: docs/NFS-ONLINE.md).
//!
//! The ExA Cup launcher writes `[account] name=` and `ticket=` into
//! net_u2.ini: the player's driver name and a short-lived ticket our api
//! signed for their ExA Cup account. When the game sends its login (`auth`),
//! NAME and PASS are replaced with those, so whatever was typed (or nothing)
//! logs the player in as their ExA Cup account. The server checks the ticket
//! (server/classic/exa_ticket.py); a ticket never works as a password.
//!
//! U2's auth frame is the same 12-byte EA classic frame as MW's, but the stock
//! client pads its payload to a fixed capacity and ends it with an eight-byte
//! MD5 trailer. The rewrite rebuilds the frame COMPACT: fields up to the first
//! NUL, then NUL, with the new total. Nothing inbound validates the trailer
//! (protocols/frame.py `fields` stops at the first NUL; the stock transport
//! splits on the declared length), and the plugin changes only the game's OWN
//! outbound frame — the server's signed replies are passed through untouched.
//!
//! Pure: no Windows calls, so it is unit-tested natively (`zig test`).

const std = @import("std");

/// The longest rewritten login frame: a header, the fields the game sent and
/// our two. The stock auth frame is a few hundred bytes.
pub const max_frame = 1024;

/// Name and ticket characters the ini may carry: nothing that could break a
/// field (no `=`, separators, NUL, spaces).
pub fn validValue(value: []const u8, max_len: usize) bool {
    if (value.len == 0 or value.len > max_len) return false;
    for (value) |b| {
        const ok = (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or (b >= '0' and b <= '9') or b == '_' or b == '-' or b == '.';
        if (!ok) return false;
    }
    return true;
}

fn append(out: []u8, len: *usize, bytes: []const u8) bool {
    if (len.* + bytes.len > out.len) return false;
    @memcpy(out[len.*..][0..bytes.len], bytes);
    len.* += bytes.len;
    return true;
}

fn field(out: []u8, len: *usize, key_eq: []const u8, value: []const u8) bool {
    return append(out, len, key_eq) and append(out, len, value) and append(out, len, "\n");
}

/// `input` rebuilt into `out` with NAME and PASS replaced (or added), every
/// other field kept in order; null when `input` is not one whole `auth`
/// frame (then it is sent untouched), or when there is no account. The
/// fixed-capacity padding and the MD5 trailer after the first NUL are
/// dropped: the rebuilt frame is compact.
pub fn rewriteAuth(input: []const u8, name: []const u8, ticket: []const u8, out: []u8) ?[]const u8 {
    if (name.len == 0 or ticket.len == 0) return null;
    if (input.len < 12 or !std.mem.eql(u8, input[0..4], "auth")) return null;
    const total = std.mem.readInt(u32, input[8..12], .big);
    if (total != input.len) return null;
    var payload = input[12..];
    if (std.mem.indexOfScalar(u8, payload, 0)) |nul| payload = payload[0..nul];

    var len: usize = 12;
    var has_name = false;
    var has_pass = false;
    var fields = std.mem.tokenizeAny(u8, payload, "\n\t");
    while (fields.next()) |item| {
        const eq = std.mem.indexOfScalar(u8, item, '=') orelse continue;
        const key = item[0..eq];
        if (std.ascii.eqlIgnoreCase(key, "NAME")) {
            if (has_name or !field(out, &len, "NAME=", name)) return null;
            has_name = true;
        } else if (std.ascii.eqlIgnoreCase(key, "PASS")) {
            if (has_pass or !field(out, &len, "PASS=", ticket)) return null;
            has_pass = true;
        } else if (!append(out, &len, item) or !append(out, &len, "\n")) {
            return null;
        }
    }
    if (!has_name and !field(out, &len, "NAME=", name)) return null;
    if (!has_pass and !field(out, &len, "PASS=", ticket)) return null;
    if (!append(out, &len, "\x00")) return null;
    @memcpy(out[0..8], input[0..8]); // command + the client's reserved word
    std.mem.writeInt(u32, out[8..12], @intCast(len), .big);
    return out[0..len];
}

fn frame(buf: []u8, command: []const u8, reserved: u32, payload: []const u8) []const u8 {
    @memcpy(buf[0..4], command[0..4]);
    std.mem.writeInt(u32, buf[4..8], reserved, .big);
    const total: u32 = @intCast(12 + payload.len);
    std.mem.writeInt(u32, buf[8..12], total, .big);
    @memcpy(buf[12..][0..payload.len], payload);
    return buf[0..total];
}

test "NAME and PASS are replaced, every other field kept" {
    var in_buf: [256]u8 = undefined;
    const input = frame(&in_buf, "auth", 7, "NAME=typed\nPASS=$1a2b\nPSES=mask\nSKU=PC\n\x00");
    var out: [max_frame]u8 = undefined;
    const got = rewriteAuth(input, "Racer_01", "exa1.abc.def", &out).?;
    try std.testing.expectEqualStrings("auth", got[0..4]);
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, got[4..8], .big));
    try std.testing.expectEqual(@as(u32, @intCast(got.len)), std.mem.readInt(u32, got[8..12], .big));
    try std.testing.expectEqualStrings("NAME=Racer_01\nPASS=exa1.abc.def\nPSES=mask\nSKU=PC\n\x00", got[12..]);
}

test "a padded U2 frame is rebuilt compact, trailer dropped" {
    // The stock capture contract: fields, then NUL, then zero padding to the
    // fixed 122-byte capacity, then the eight-byte MD5 trailer (142 total).
    var in_buf: [256]u8 = undefined;
    var span: [256]u8 = undefined;
    const fields_text = "NAME=typed\nPASS=$1a2b\n";
    const capacity: usize = 122;
    const trailer: usize = 8;
    @memcpy(span[0..fields_text.len], fields_text);
    span[fields_text.len] = 0;
    var i: usize = fields_text.len + 1;
    while (i < capacity) : (i += 1) span[i] = 0; // padding
    while (i < capacity + trailer) : (i += 1) span[i] = 0xAB; // the signed bytes
    const input = frame(&in_buf, "auth", 9, span[0 .. capacity + trailer]);
    var out: [max_frame]u8 = undefined;
    const got = rewriteAuth(input, "Bayview_1", "exa1.abc.def", &out).?;
    try std.testing.expectEqualStrings("NAME=Bayview_1\nPASS=exa1.abc.def\n\x00", got[12..]);
    try std.testing.expectEqual(@as(usize, 12 + "NAME=Bayview_1\nPASS=exa1.abc.def\n".len + 1), got.len);
    try std.testing.expectEqual(@as(u32, @intCast(got.len)), std.mem.readInt(u32, got[8..12], .big));
}

test "tab-separated fields and missing NAME / PASS" {
    var in_buf: [256]u8 = undefined;
    const input = frame(&in_buf, "auth", 0, "PSES=mask\tSKU=PC\x00");
    var out: [max_frame]u8 = undefined;
    const got = rewriteAuth(input, "Driver", "exa1.t.s", &out).?;
    try std.testing.expectEqualStrings("PSES=mask\nSKU=PC\nNAME=Driver\nPASS=exa1.t.s\n\x00", got[12..]);
}

test "anything else is left alone" {
    var in_buf: [256]u8 = undefined;
    var out: [max_frame]u8 = undefined;
    const pers = frame(&in_buf, "pers", 0, "PERS=x\n\x00");
    try std.testing.expect(rewriteAuth(pers, "Driver", "exa1.t.s", &out) == null);
    const auth = frame(&in_buf, "auth", 0, "NAME=a\n\x00");
    try std.testing.expect(rewriteAuth(auth[0 .. auth.len - 2], "Driver", "exa1.t.s", &out) == null); // partial
    try std.testing.expect(rewriteAuth(auth, "", "exa1.t.s", &out) == null); // no account
    var tiny: [16]u8 = undefined;
    try std.testing.expect(rewriteAuth(auth, "Driver", "exa1.t.s", &tiny) == null); // no room
}

test "ini values are held to safe characters" {
    try std.testing.expect(validValue("Racer_01", 15));
    try std.testing.expect(validValue("exa1.eyJ1Ijo.abc-_", 600));
    try std.testing.expect(!validValue("bad name", 15));
    try std.testing.expect(!validValue("a=b", 15));
    try std.testing.expect(!validValue("", 15));
    try std.testing.expect(!validValue("toolongname1234567", 15));
}
