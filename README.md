FUSE auto-cleanup filesystem (acfs)
===================================

FUSE overlay filesystem that removes oldest files when used space
reaches set threshold. Fork of [limit-fs] project.

Mounts over a directory, to write files through acfs mountpoint to it.\
When closing an open file on that mp, checks underlying used space against
threshold, keeps removing files until it's below that, in oldest-mtime-first order.

Different from original limit-fs in simplified project structure
(just .c + makefile), removed old fuse2 compatibility (and similar macros),
and more control over where cleanup happens (`cleanup-dir` option).

[limit-fs]: https://github.com/piuma/limit-fs

Repository URLs:

- <https://github.com/mk-fg/fuse-auto-cleanup-fs>
- <https://codeberg.org/mk-fg/fuse-auto-cleanup-fs>
- <https://fraggod.net/code/git/fuse-auto-cleanup-fs>


# Build / Requirements

Requires [libfuse3] (modern FUSE library) to build and run,
plus the usual C compiler and [make] for the build.

Run `make` to build `acfs` binary, that's it.

[libfuse3]: https://github.com/libfuse/libfuse
[make]: https://www.gnu.org/software/make


# Usage

Something like: `./acfs /mnt/storage/temp`\
Or when it's in PATH: `mount -t fuse.acfs acfs /mnt/storage/temp`\
Then unmount as usual: `umount /mnt/storage/temp`

Always replaces directory with a new mountpoint,
does not use "source" argument (`acfs` in mount-command above).
To access underlying dir at the same time, bind-mount it (or its parent dir)
to multiple places first.

Run `./acfs -h` to see acfs-specific options at the end
(like `-u/--usage-limit` threshold), with info on their defaults.

If installed to PATH like `/usr/bin/acfs`, can also be used from `/etc/fstab`
or systemd mount units, same as any other FUSE filesystem, for example:
```
acfs /mnt/storage/temp fuse.acfs usage-limit=90,uid=myuser,gid=myuser,nofail
```

systemd should auto-order that mount after `/mnt/storage`,
but when using same mountpoint on multiple fstab lines, adding `x-systemd.after=`
and similar explicit ordering options might be useful (from [man systemd.mount]).

All file operations on acfs pass through to underlying directory, but when
closing open files, it always checks used space there against `usage-limit`,
and if it's over specified percentage, finds oldest file in `cleanup-dir`
(same mounted dir by default) and removes it, checks again, repeats as-necessary.

Since used-space checks happen between e.g. sequential file-copy ops,
make sure that cleanup margin is larger than a single stored file should be.\
"Used space" here means "not available to regular user" (`f_blocks - f_bavail`) -
always counts root-reserved blocks as "used", if filesystem has those.

Intended use is file storage destination, where copying more important files
over will rotate-out less imporant ones under `cleanup-dir`, and new files stored
there can push older ones out as well, thus not normally needing any separate
cleanup routine, even if amount of files rsync'ed there in one go exceeds fs size.

This is not intended to be a general-purpose filesystem to use for e.g. rootfs,
and can potentially have issues with whatever odd concurrent operation semantics,
where proxying syscalls in a direct way isn't sufficient for correctness.

Implementation of path traversals on mounted dir is definitely insecure,
so do not use this overlay unless that directory is only accessible to trusted
users/processes, only run it with dedicated least-privileged uid/gid,
maybe in an LSM profile (to easily limit access to paths), and ideally with
symlinks/submounts/special-nodes/etc blocked on underlying filesystem entirely.

[man systemd.mount]: https://man.archlinux.org/man/systemd.mount.5
