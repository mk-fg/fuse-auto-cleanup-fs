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

"Used space" above as in "not available to regular user" (`f_blocks - f_bavail`) -
always counts root-reserved blocks as "used", if filesystem has those.

[limit-fs]: https://github.com/piuma/limit-fs


# Build / Requirements

Requires [libfuse3] (modern FUSE library) to build and run,
plus the usual C compiler and [make] for the build.

Run `make` to build `acfs` binary, that's it.

[libfuse3]: https://github.com/libfuse/libfuse
[make]: https://www.gnu.org/software/make


# Usage

Something like: `./acfs /mnt/storage/temp`\
Then unmount as usual: `umount /mnt/storage/temp`

Always replaces directory with a new mountpoint, so only needs it as a single argument.\
To access underlying dir at the same time, bind-mount it (or its parent dir)
to multiple places first.

Run `./acfs -h` to see acfs-specific options
(like `-u/--usage-limit` threshold) at the end, with info on their defaults.

If installed to PATH like `/usr/bin/acfs`, it can be used from `/etc/fstab`
or systemd mount units, same as any other fuse-fs, for example:
```
acfs /mnt/storage/temp fuse.acfs usage-limit=90,uid=myuser,gid=myuser,nofail
```

systemd should auto-order that mount after `/mnt/storage`,
but when using same mountpoint on multiple fstab lines, adding `x-systemd.after=`
and similar explicit ordering options might be useful (from [man systemd.mount]).

[man systemd.mount]: https://man.archlinux.org/man/systemd.mount.5
