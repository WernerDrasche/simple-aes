const Build = @import("std").Build;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = "aes",
        .root_source_file = .{ .path = "main.zig" },
        .target = target,
        .optimize = optimize,
    });
    const cli = b.dependency("zig-cli", .{
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("zig-cli", cli.module("zig-cli"));
    b.installArtifact(exe);
}
