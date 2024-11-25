const std = @import("std");
const builtin = @import("builtin");
const AES = @import("aes.zig").AES;
const cli = @import("zig-cli");
const c = @cImport({
    @cInclude("termios.h");
    @cInclude("err.h");
});
const assert = std.debug.assert;
const KDF = std.crypto.pwhash.scrypt;
const Random = std.crypto.random;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();
const stdout = std.io.getStdOut().writer();
const stdin = std.io.getStdIn().reader();

const Action = enum { encrypt, decrypt };
const Mode = enum { ecb, ctr };

const salt = "this is an epic and very unique salt";
const kdf_config = if (builtin.mode == .Debug) KDF.Params.interactive else KDF.Params.sensitive;

var config = struct {
    infile: []const u8 = undefined,
    outfile: []const u8 = undefined,
    passwd: []const u8 = undefined,
    action: Action = undefined,
    mode: Mode = .ctr,
}{};

var infile_arg = cli.PositionalArg{
    .name = "input file",
    .help = "relative filepath",
    .value_ref = cli.mkRef(&config.infile),
};

var outfile_arg = cli.PositionalArg{
    .name = "output file",
    .help = "relative filepath",
    .value_ref = cli.mkRef(&config.outfile),
};

var passwd_arg = cli.Option{
    .long_name = "passwd",
    .short_alias = 'p',
    .help = "used as input for KDF",
    .value_ref = cli.mkRef(&config.passwd),
};

var mode_arg = cli.Option{
    .long_name = "mode",
    .short_alias = 'm',
    .help = "ctr (default) or ecb",
    .value_ref = cli.mkRef(&config.mode),
};

const encrypt_cmd = cli.Command{
    .name = "encrypt",
    .target = cli.CommandTarget{
        .action = cli.CommandAction{
            .positional_args = cli.PositionalArgs{
                .args = &.{ &infile_arg, &outfile_arg },
            },
            .exec = encrypt,
        },
    },
};

const decrypt_cmd = cli.Command{
    .name = "decrypt",
    .target = cli.CommandTarget{
        .action = cli.CommandAction{
            .positional_args = cli.PositionalArgs{
                .args = &.{ &infile_arg, &outfile_arg },
            },
            .exec = decrypt,
        },
    },
};

const app = cli.App{
    .command = cli.Command{
        .name = "aes",
        .description = .{ .one_line = 
        \\encrypt and decrypt single files
        \\example:
        \\aes encrypt file.txt file.txt
        \\aes decrypt file.txt file.txt
        },
        .options = &.{ &mode_arg, &passwd_arg },
        .target = cli.CommandTarget{
            .subcommands = &.{ &encrypt_cmd, &decrypt_cmd },
        },
    },
};

fn toggleTermEcho() void {
    const fd = stdin.context.handle;
    var term: c.termios = undefined;
    if (c.tcgetattr(fd, &term) == -1)
        c.err(1, "tcgetattr");
    term.c_lflag ^= c.ECHO;
    if (c.tcsetattr(fd, c.TCSANOW, &term) == -1)
        c.err(1, "tcsetattr");
}

pub fn main() !void {
    config.passwd.ptr = @ptrFromInt(1);
    return cli.run(&app, allocator);
}

fn encrypt() anyerror!void {
    config.action = .encrypt;
    try run();
}

fn decrypt() anyerror!void {
    config.action = .decrypt;
    try run();
}

fn generateValidator(out: *[32]u8) void {
    var state: AES = undefined;
    state.installKey(32, &[_]u8{0} ** 32);
    const data = out[0..16];
    Random.bytes(data);
    state.encrypt(data, out[16..32]);
}

fn checkValidator(data: *[32]u8) bool {
    var state: AES = undefined;
    state.installKey(32, &[_]u8{0} ** 32);
    var out: [16]u8 = undefined;
    state.encrypt(data[0..16], &out);
    return std.mem.eql(u8, &out, data[16..32]);
}

fn run() !void {
    var free_passwd = false;
    if (config.passwd.ptr == @as([*]const u8, @ptrFromInt(1))) {
        toggleTermEcho();
        free_passwd = true;
        try stdout.writeAll("Password: ");
        config.passwd = try stdin.readUntilDelimiterAlloc(allocator, '\n', 256);
        try stdout.writeByte('\n');
        if (builtin.mode != .Debug and config.action == .encrypt) {
            try stdout.writeAll("Repeat: ");
            const repeat = try stdin.readUntilDelimiterAlloc(allocator, '\n', 256);
            try stdout.writeByte('\n');
            defer allocator.free(repeat);
            if (!std.mem.eql(u8, repeat, config.passwd)) {
                toggleTermEcho();
                try stdout.writeAll("Error: passwords don't match\n");
                std.os.exit(1);
            }
        }
        toggleTermEcho();
    }
    var key: [32]u8 = undefined;
    try KDF.kdf(allocator, &key, config.passwd, salt, kdf_config);
    var aes: AES = undefined;
    aes.installKey(key.len, &key);
    const cwd = std.fs.cwd();
    const infile = cwd.openFile(config.infile, .{}) catch |err| {
        if (err == error.FileNotFound) {
            try stdout.print("Error: input file {s} not found\n", .{config.infile});
            std.os.exit(1);
        }
        return err;
    };
    defer infile.close();
    const stat = try infile.stat();
    var size = stat.size;
    if (config.action == .encrypt) {
        //16 bytes: ecb needs padding and ctr the iv
        //32 bytes for the validator
        size += 48;
    } else if (size < 48) {
        try stdout.print("Error: the input file {s} could not have been encrypted with this program\n", .{config.infile});
        std.os.exit(1);
    }
    const contents = try allocator.alloc(u8, size);
    defer allocator.free(contents);
    var data = contents;
    if (config.action == .encrypt) {
        if (config.mode == .ctr) {
            Random.bytes(contents[0..16]);
            data = contents[16..];
        }
        generateValidator(data[0..32]);
        _ = try infile.readAll(data[32..]);
    } else {
        _ = try infile.readAll(data);
    }
    var len = switch (config.mode) {
        .ecb => blk: {
            if (config.action == .encrypt) {
                var src = data;
                src.len -= 16;
                break :blk aes.encryptECB(src, data);
            } else {
                break :blk aes.decryptECB(data, data) catch {
                    try stdout.print("Error: input file {s} could not have been encrypted with mode ecb\n", .{config.infile});
                    std.os.exit(1);
                };
            }
        },
        .ctr => blk: {
            if (config.action == .decrypt) {
                data = contents[16..];
            }
            aes.modeCTR(contents[0..16], data, data);
            break :blk data.len;
        },
    };
    if (config.action == .decrypt and !checkValidator(data[0..32])) {
        try stdout.writeAll("Wrong password\n");
        std.os.exit(1);
    }
    const outfile = try cwd.createFile(config.outfile, .{});
    defer outfile.close();
    if (config.action == .decrypt) {
        try outfile.writeAll(data[32..len]);
    } else {
        if (config.mode == .ctr) {
            len = contents.len;
        }
        try outfile.writeAll(contents[0..len]);
    }
    if (free_passwd)
        allocator.free(config.passwd);
}
