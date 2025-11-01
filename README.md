FUSE auto-cleanup filesystem (acfs)
===================================

FUSE overlay filesystem that removes oldest files when used space
reaches set threshold. Fork of [limit-fs] project.

Mounts over a directory, to write files through acfs mountpoint to it.\
When closing an open file on that mp, checks underlying used space against
threshold, keeps removing files until it's below that, in oldest-mtime-first order.

Different from original limit-fs in simplified project structure
(just .c + makefile), removed old fuse2 compatibility (and similar macros),
smarter queue-based cleanup with more control over where it happens
(`cleanup-dir` option), and a ton of general fixes.

[limit-fs]: https://github.com/piuma/limit-fs

Repository URLs:

- <https://github.com/mk-fg/fuse-auto-cleanup-fs>
- <https://codeberg.org/mk-fg/fuse-auto-cleanup-fs>
- <https://fraggod.net/code/git/fuse-auto-cleanup-fs>


# Build / Requirements

Requires [libfuse3] (modern FUSE library) to build and run,
plus the usual C compiler and [make] for the build.

Run `make` to build `acfs` binary, that's it.\
Or without `make`: `gcc -I/usr/include/fuse3 -lfuse3 -Wall -O2 -o acfs acfs.c`

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
acfs /mnt/storage/temp fuse.acfs usage-limit=80,uid=myuser,gid=myuser,nofail
```

systemd should auto-order that mount after `/mnt/storage`,
but when using same mountpoint on multiple fstab lines, adding `x-systemd.after=`
and similar explicit ordering options might be useful (from [man systemd.mount]).

[man systemd.mount]: https://man.archlinux.org/man/systemd.mount.5


# Implementation quirks

All file operations on acfs pass through to underlying directory, but when
closing open files, it always checks used space there against `usage-limit`,
and if it's over specified percentage, finds oldest-mtime files in `cleanup-dir`
(same mounted dir by default) and removes those one-by-one in order,
until free space goes under `usage-lwm` ("low-water mark" threshold).
Removes empty parent dirs up to `cleanup-dir` after files in them.

Since used-space checks happen between e.g. sequential file-copy ops,
make sure that cleanup margin is larger than a single stored file should be,
to avoid running out of space while writing it.
"Used space" here means "not available to regular user" (`f_blocks - f_bavail`) -
always counts root-reserved blocks as "used", if filesystem has those.

Intended usage is long-term file storage destination, where copying more
important files over will rotate-out less imporant ones under `cleanup-dir`,
and new files stored there can push older ones out as well, thus not normally
needing any separate cleanup routine, even if amount of files rsync'ed there
in one go exceeds fs size.

This is not intended to be a general-purpose filesystem to use for e.g. rootfs,
and can potentially have issues with whatever odd concurrent operation semantics,
where proxying syscalls in a direct way isn't sufficient for correctness.
Layering this over multi-user network fs might also have issues with remote
posix locks (if used), as those are mountpoint-local here.

Implementation of path traversals on mounted dir is definitely insecure,
so do not use this overlay unless that directory is only accessible to trusted
users/processes, only run it with dedicated least-privileged uid/gid,
maybe in an LSM profile (to easily restrict access to one path), and ideally with
symlinks/submounts/special-nodes/etc blocked on underlying filesystem entirely.

> Specific use-case I have for this is an opportunistic "grab as many new files
> from here as possible" rsync-backup script for unimportant media files,
> without having to worry about space available for important things next to them,
> or whether those extra files all fit there in any way, but also without leaving
> wasted free space around at the same time.


# Links

- [limit-fs] - predecessor of this project.

    Forked it after noticing many issues with the code - obviously broken operations
    (e.g. self-recursively using paths on overlay), broken option parsing, unfinished stuff,
    very suboptimal and inflexible cleanup.

- [rotatefs] - similar to limit-fs, but a bit older, with many of the same issues.

- [example/passthrough_fh.c from libfuse] - base for [limit-fs] and many similar projects.

- [logrotate] - common well-known tool for cleaning up dirs of append-only log files.

    There are also more dynamic tools like [log_proxy] or [systemd-journal] for
    managing log files and streams without running out of storage space.

- [systemd-tmpfiles] - auto-enabled tool that comes with systemd to cleanup tmpfs files.

- [check-df cron-script] - what I use for general running-out-of-space monitoring.

    Runs basic "df" on all connected disks and emits stderr warnings with error exit,
    which cron daemon or [systemd.timer] service OnFailure= hook will email report for.

- `find /mnt/storage/temp -xdev -depth -mtime +30 -delete` can be a simple
  "delete stuff older than 30d" cleanup-command too.

- [rmlint], [rdfind] - manual cleanup tools focused on specific disk-usage pathologies.

- [BleachBit], [czkawka], [FSlint] - GUI/desktop manual disk-cleanup tools.

[rotatefs]: https://github.com/frt/rotatefs
[example/passthrough_fh.c from libfuse]:
  https://github.com/libfuse/libfuse/blob/master/example/passthrough_fh.c
[logrotate]: https://github.com/logrotate/logrotate
[log_proxy]: https://github.com/metwork-framework/log_proxy
[systemd-journal]: https://man.archlinux.org/man/core/systemd/systemd-journald.8.en
[systemd-tmpfiles]: https://man.archlinux.org/man/core/systemd/systemd-tmpfiles.8.en
[check-df cron-script]: https://github.com/mk-fg/fgtk/blob/master/cron-checks/df
[systemd.timer]: https://man.archlinux.org/man/systemd.timer.5
[rmlint]: https://github.com/sahib/rmlint
[rdfind]: https://github.com/pauldreik/rdfind
[BleachBit]: https://www.bleachbit.org/
[czkawka]: https://github.com/qarmin/czkawka
[FSlint]: https://www.pixelbeat.org/fslint/
