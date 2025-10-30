/* FUSE: Filesystem in Userspace
	Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
	Copyright (C) 2011 Sebastian Pipping <sebastian@pipping.org>
	Copyright (C) 2019 Danilo Abbasciano <danilo@piumalab.org>
	Copyright (C) 2025 Mike Kazantsev
	This program can be distributed under the terms of the GNU GPL.
	See the file COPYING. */

#define ACFS_VERSION "1.0"
#define FUSE_USE_VERSION 31

#define _GNU_SOURCE

#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/file.h> /* flock(2) */
#include <stddef.h>
#include <ftw.h>
#include <err.h>


struct acfs_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static struct acfs_mp {
	int fd;
	struct acfs_dirp *dir;
	char *path;
	char *cleanup_path;
	int cleanup_fd;
} acfs_mp;

// Can't set default values for the char* fields here because fuse_opt_parse would
//  attempt to free() them when the user specifies different values on the command line.
static struct acfs_options {
	int usage_limit;
	char *cleanup_dir;
} acfs_options;
int acfs_opts_def_usage_limit = 90;


static void *acfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
	(void) conn;
	cfg->use_ino = 1;
	cfg->nullpath_ok = 1;

	/* Pick up changes from lower filesystem right away. This is
		also necessary for better hardlink support. When the kernel
		calls the unlink() handler, it does not know the inode of
		the to-be-removed entry and can therefore not invalidate
		the cache of the associated inode - resulting in an
		incorrect st_nlink value being reported for any remaining
		hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

static int acfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	int res;
	(void) path;
	if (fi) res = fstat(fi->fh, stbuf);
	else {
		/* res = lstat(path, stbuf); */
		char relative_path[ strlen(path) + 1];
		strcpy(relative_path, ".");
		strcat(relative_path, path);
		res = fstatat(acfs_mp.fd, relative_path, stbuf, AT_SYMLINK_NOFOLLOW);
	}
	return res == -1 ? -errno : 0;
}

static int acfs_access(const char *path, int mask) {
	int res;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	res = faccessat(acfs_mp.fd, relative_path, mask, AT_EACCESS);
	return res == -1 ? -errno : 0;
}

static int acfs_readlink(const char *path, char *buf, size_t size) {
	int res;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	res = readlinkat(acfs_mp.fd, relative_path, buf, size - 1);
	if (res == -1) return -errno;
	buf[res] = '\0';
	return 0;
}

/* Relative to DIR_FD, open the directory DIR, passing EXTRA_FLAGS to
	the underlying openat call.  On success, store into *PNEW_FD the
	underlying file descriptor of the newly opened directory and return
	the directory stream.  On failure, return NULL and set errno.
	On success, *PNEW_FD is at least 3, so this is a "safer" function.  */
DIR *opendirat(int dir_fd, char const *path, int extra_flags) {
	int open_flags = (O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOCTTY | O_NONBLOCK | extra_flags);
	char relative_path[strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	int new_fd = openat(dir_fd, relative_path, open_flags);
	if (new_fd < 0) return NULL;
	DIR *dirp = fdopendir(new_fd);
	if (!dirp) {
		int fdopendir_errno = errno;
		close(new_fd);
		errno = fdopendir_errno;
	}
	return dirp;
}

static int acfs_opendir(const char *path, struct fuse_file_info *fi) {
	int res;
	if (strcmp(path, "/") == 0) {
		if (acfs_mp.dir == NULL) return -errno;
		fi->fh = (unsigned long) acfs_mp.dir;
		return 0;
	}
	struct acfs_dirp *d = malloc(sizeof(struct acfs_dirp));
	if (d == NULL) return -ENOMEM;
	d->dp = opendirat(acfs_mp.fd, path, 0);
	if (d->dp == NULL) {
		res = -errno;
		free(d);
		return res;
	}
	d->offset = 0;
	d->entry = NULL;
	fi->fh = (unsigned long) d;
	return 0;
}

static inline struct acfs_dirp *get_dirp(struct fuse_file_info *fi) {
	return (struct acfs_dirp *) (uintptr_t) fi->fh;
}

static int acfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
	struct acfs_dirp *d = get_dirp(fi);
	(void) path;
	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	while (1) {
		struct stat st;
		off_t nextoff;
		enum fuse_fill_dir_flags fill_flags = 0;
		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry) break;
		}
		if (flags & FUSE_READDIR_PLUS) {
			int res;
			res = fstatat(dirfd(d->dp), d->entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
			if (res != -1) fill_flags |= FUSE_FILL_DIR_PLUS;
		}
		if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
			memset(&st, 0, sizeof(st));
			st.st_ino = d->entry->d_ino;
			st.st_mode = d->entry->d_type << 12;
		}
		nextoff = telldir(d->dp);
		if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags)) break;
		d->entry = NULL;
		d->offset = nextoff;
	}
	return 0;
}

static int acfs_releasedir(const char *path, struct fuse_file_info *fi) {
	struct acfs_dirp *d = get_dirp(fi);
	(void) path;
	if (d->dp == acfs_mp.dir->dp) return 0;
	closedir(d->dp);
	free(d);
	return 0;
}

static int acfs_mknod(const char *path, mode_t mode, dev_t rdev) {
	int res;
	if (S_ISFIFO(mode)) res = mkfifo(path, mode);
	else res = mknod(path, mode, rdev);
	return res == -1 ? -errno : 0;
}

static int acfs_mkdir(const char *path, mode_t mode) {
	int res;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	res = mkdirat(acfs_mp.fd, relative_path, mode);
	return res == -1 ? -errno : 0;
}

static int acfs_unlink(const char *path) {
	int res;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	res = unlinkat(acfs_mp.fd, relative_path, 0);
	return res == -1 ? -errno : 0;
}

static int acfs_rmdir(const char *path) {
	int res;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	res = unlinkat(acfs_mp.fd, relative_path, AT_REMOVEDIR);
	/* res = rmdir(path); */
	return res == -1 ? -errno : 0;
}

static int acfs_symlink(const char *from, const char *to) {
	int res;
	char relative_to[ strlen(to) + 1];
	strcpy(relative_to, ".");
	strcat(relative_to, to);
	/* res = symlink(from, to); */
	res = symlinkat(from, acfs_mp.fd, relative_to);
	return res == -1 ? -errno : 0;
}

static int acfs_rename(const char *from, const char *to, unsigned int flags) {
	int res;
	char relative_from[ strlen(from) + 1];
	strcpy(relative_from, ".");
	strcat(relative_from, from);
	char relative_to[ strlen(to) + 1];
	strcpy(relative_to, ".");
	strcat(relative_to, to);
	/* When we have renameat2() in libc, then we can implement flags */
	if (flags) return -EINVAL;
	res = renameat(acfs_mp.fd, relative_from, acfs_mp.fd, relative_to);
	/* res = rename(from, to); */
	return res == -1 ? -errno : 0;
}

static int acfs_link(const char *from, const char *to) {
	int res;
	res = link(from, to);
	return res == -1 ? -errno : 0;
}

static int acfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
	int res;
	if (fi) res = fchmod(fi->fh, mode);
	else {
		char relative_path[ strlen(path) + 1];
		strcpy(relative_path, ".");
		strcat(relative_path, path);
		res = fchmodat(acfs_mp.fd, relative_path, mode, 0);
		// res = chmod(path, mode);
	}
	return res == -1 ? -errno : 0;
}

static int acfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
	int res;
	if (fi) res = fchown(fi->fh, uid, gid);
	else {
		char relative_path[ strlen(path) + 1];
		strcpy(relative_path, ".");
		strcat(relative_path, path);
		res = fchownat(acfs_mp.fd, relative_path, uid, gid, AT_SYMLINK_NOFOLLOW);
		// res = lchown(path, uid, gid);
	}
	return res == -1 ? -errno : 0;
}

static int acfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	int res;
	if (fi) res = ftruncate(fi->fh, size);
	else res = truncate(path, size);
	return res == -1 ? -errno : 0;
}

static int acfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
	int res;
	/* don't use utime/utimes since they follow symlinks */
	if (fi) res = futimens(fi->fh, ts);
	else res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	return res == -1 ? -errno : 0;
}

static int acfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	int fd;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	fd = openat(acfs_mp.fd, relative_path, fi->flags, mode);
	if (fd == -1) return -errno;
	fi->fh = fd;
	return 0;
}

static int acfs_open(const char *path, struct fuse_file_info *fi) {
	int fd;
	char relative_path[ strlen(path) + 1];
	strcpy(relative_path, ".");
	strcat(relative_path, path);
	fd = openat(acfs_mp.fd, relative_path, fi->flags);
	if (fd == -1) return -errno;
	fi->fh = fd;
	return 0;
}

static int acfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	int res;
	(void) path;
	res = pread(fi->fh, buf, size, offset);
	return res == -1 ? -errno : 0;
}

static int acfs_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset, struct fuse_file_info *fi) {
	struct fuse_bufvec *src;
	(void) path;
	src = malloc(sizeof(struct fuse_bufvec));
	if (src == NULL) return -ENOMEM;
	*src = FUSE_BUFVEC_INIT(size);
	src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	src->buf[0].fd = fi->fh;
	src->buf[0].pos = offset;
	*bufp = src;
	return 0;
}

static int acfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	int res;
	(void) path;
	res = pwrite(fi->fh, buf, size, offset);
	return res == -1 ? -errno : 0;
}

static int acfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset, struct fuse_file_info *fi) {
	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
	(void) path;
	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = offset;
	return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int acfs_statfs(const char *path, struct statvfs *stbuf) {
	int res;
	res = fstatvfs(acfs_mp.fd, stbuf);
	return res == -1 ? -errno : 0;
}

static int acfs_flush(const char *path, struct fuse_file_info *fi) {
	int res;
	(void) path;
	/* This is called from every close on an open file, so call the
		close on the underlying filesystem.	But since flush may be
		called multiple times for an open file, this must not really
		close the file.  This is important if used on a network
		filesystem like NFS which flush the data/metadata on close() */
	res = close(dup(fi->fh));
	return res == -1 ? -errno : 0;
}

char acfs_cleanup_oldest[PATH_MAX+1] = {0};
time_t acfs_cleanup_mtime = 0;
int acfs_cleanup(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	if (typeflag != FTW_F || (acfs_cleanup_mtime && acfs_cleanup_mtime < sb->st_mtime)) return 0;
	acfs_cleanup_mtime = sb->st_mtime;
	strncpy(acfs_cleanup_oldest, fpath + ftwbuf->base, PATH_MAX);
	return 0;
}

static int acfs_release(const char *path, struct fuse_file_info *fi) {
	int res = 0;
	(void) path;
	if (close(fi->fh) == -1) res = -errno;
	struct statvfs st;
	if (fstatvfs(acfs_mp.cleanup_fd, &st)) return -errno;
	while (100 - (st.f_bavail * 100 / st.f_blocks) > acfs_options.usage_limit) {
		nftw(acfs_mp.cleanup_path, acfs_cleanup, 500, FTW_MOUNT);
		if (!acfs_cleanup_oldest[0]) break;
		if ( unlinkat(acfs_mp.cleanup_fd, acfs_cleanup_oldest, 0) ||
			fstatvfs(acfs_mp.cleanup_fd, &st) ) return -errno;
		acfs_cleanup_oldest[0] = '\0'; acfs_cleanup_mtime = 0; }
	return res;
}

static int acfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	int res;
	(void) path;
	if (isdatasync) res = fdatasync(fi->fh);
	else res = fsync(fi->fh);
	return res == -1 ? -errno : 0;
}

static int acfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi) {
	(void) path;
	if (mode) return -EOPNOTSUPP;
	return -posix_fallocate(fi->fh, offset, length);
}

/* xattr operations are optional and can safely be left unimplemented */
static int acfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
	int res = lsetxattr(path, name, value, size, flags);
	return res == -1 ? -errno : 0;
}

static int acfs_getxattr(const char *path, const char *name, char *value, size_t size) {
	int res = lgetxattr(path, name, value, size);
	return res == -1 ? -errno : 0;
}

static int acfs_listxattr(const char *path, char *list, size_t size) {
	int res = llistxattr(path, list, size);
	return res == -1 ? -errno : 0;
}

static int acfs_removexattr(const char *path, const char *name) {
	int res = lremovexattr(path, name);
	return res == -1 ? -errno : 0;
}

static int acfs_flock(const char *path, struct fuse_file_info *fi, int op) {
	int res;
	(void) path;
	res = flock(fi->fh, op);
	return res == -1 ? -errno : 0;
}

static ssize_t acfs_copy_file_range(const char *path_in,
		struct fuse_file_info *fi_in, off_t off_in, const char *path_out,
		struct fuse_file_info *fi_out, off_t off_out, size_t len, int flags) {
	ssize_t res;
	(void) path_in;
	(void) path_out;
	res = copy_file_range(fi_in->fh, &off_in, fi_out->fh, &off_out, len, flags);
	return res == -1 ? -errno : 0;
}


// Same order as https://libfuse.github.io/doxygen/structfuse__operations.html
static struct fuse_operations acfs_oper = {
	.getattr = acfs_getattr,
	.readlink = acfs_readlink,
	.mknod = acfs_mknod,
	.mkdir = acfs_mkdir,
	.unlink = acfs_unlink,
	.rmdir = acfs_rmdir,
	.symlink = acfs_symlink,
	.rename = acfs_rename,
	.link = acfs_link,
	.chmod = acfs_chmod,
	.chown = acfs_chown,
	.truncate = acfs_truncate,
	.open = acfs_open,
	.read = acfs_read,
	.write = acfs_write,
	.statfs = acfs_statfs,
	.flush = acfs_flush,
	.release = acfs_release,
	.fsync = acfs_fsync,
	.setxattr = acfs_setxattr,
	.getxattr = acfs_getxattr,
	.listxattr = acfs_listxattr,
	.removexattr = acfs_removexattr,
	.opendir = acfs_opendir,
	.readdir = acfs_readdir,
	.releasedir = acfs_releasedir,
	// .fsyncdir
	.init = acfs_init,
	// .destroy
	.access = acfs_access,
	.create = acfs_create,
	// .lock - posix file locks will be mountpoint-local
	.utimens = acfs_utimens,
	// .bmap
	// .ioctl
	// .poll
	.write_buf = acfs_write_buf,
	.read_buf = acfs_read_buf,
	.flock = acfs_flock,
	.fallocate = acfs_fallocate,
	.copy_file_range = acfs_copy_file_range,
	// .lseek
};


// Copied from libfuse/lib/mount_util.c - seem to check/normalize mountpoint path
char *fuse_mnt_resolve_path(const char *progname, const char *orig) {
	char buf[PATH_MAX];
	char *copy;
	char *dst;
	char *end;
	char *lastcomp;
	const char *toresolv;

	if (!orig[0]) {
		fprintf(stderr, "%s: invalid mountpoint '%s'\n", progname, orig);
		return NULL;
	}

	copy = strdup(orig);
	if (copy == NULL) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		return NULL;
	}

	toresolv = copy;
	lastcomp = NULL;
	for (end = copy + strlen(copy) - 1; end > copy && *end == '/'; end--);
	if (end[0] != '/') {
		char *tmp;
		end[1] = '\0';
		tmp = strrchr(copy, '/');
		if (tmp == NULL) {
			lastcomp = copy;
			toresolv = ".";
		} else {
			lastcomp = tmp + 1;
			if (tmp == copy) toresolv = "/";
		}
		if (strcmp(lastcomp, ".") == 0 || strcmp(lastcomp, "..") == 0) {
			lastcomp = NULL;
			toresolv = copy;
		}
		else if (tmp) tmp[0] = '\0';
	}
	if (realpath(toresolv, buf) == NULL) {
		fprintf(stderr, "%s: bad mount point %s: %s\n", progname, orig, strerror(errno));
		free(copy);
		return NULL;
	}
	if (lastcomp == NULL) dst = strdup(buf);
	else {
		dst = (char *) malloc(strlen(buf) + 1 + strlen(lastcomp) + 1);
		if (dst) {
			unsigned buflen = strlen(buf);
			if (buflen && buf[buflen-1] == '/') sprintf(dst, "%s%s", buf, lastcomp);
			else sprintf(dst, "%s/%s", buf, lastcomp);
		}
	}
	free(copy);
	if (dst == NULL) fprintf(stderr, "%s: failed to allocate memory\n", progname);
	return dst;
}


#define ACFS_OPT(t, p) { t, offsetof(struct acfs_options, p), 1 }
enum { ACFS_KEY_HELP, ACFS_KEY_VERSION };
static const struct fuse_opt option_spec[] = {
	ACFS_OPT("-u %d", usage_limit),
	ACFS_OPT("-u=%d", usage_limit),
	ACFS_OPT("--usage-limit %d", usage_limit),
	ACFS_OPT("--usage-limit=%d", usage_limit),
	ACFS_OPT("usage-limit=%d", usage_limit),
	ACFS_OPT("cleanup-dir=%s", cleanup_dir),
	ACFS_OPT("--cleanup-dir=%s", cleanup_dir),
	FUSE_OPT_KEY("-V", ACFS_KEY_VERSION),
	FUSE_OPT_KEY("--version", ACFS_KEY_VERSION),
	FUSE_OPT_KEY("-h", ACFS_KEY_HELP),
	FUSE_OPT_KEY("--help", ACFS_KEY_HELP),
	FUSE_OPT_END };

static int acfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *args) {
	switch (key) {
		case ACFS_KEY_HELP:
			fuse_opt_add_arg(args, "-h");
			fuse_main(args->argc, args->argv, &acfs_oper, NULL);
			printf(
				"\nACFS filesystem-specific options (usable as `-o <opt>=<value>` in mount/fstab):\n"
				"    -u <d>   --usage-limit=<d>\n"
				"       Used space percentage threshold in mounted directory. Default: %d%%\n"
				"    --cleanup-dir=<path>\n"
				"       Directory to lookup for files to remove. Default is to use mounted dir.\n"
				"       Path can either be absolute or relative to the mounted dir, must be on same fs.\n"
				"       Symlinks in this dir are also only navigated within filesystem.\n\n",
				acfs_opts_def_usage_limit );
			exit(1);
		case ACFS_KEY_VERSION:
			printf("acfs version %s\n", ACFS_VERSION);
			fuse_opt_add_arg(args, "--version");
			fuse_main(args->argc, args->argv, &acfs_oper, NULL);
			exit(0);
		case FUSE_OPT_KEY_OPT:
			if (arg[0] == '-') // all rw, dev, suid, etc "-o <options>" also pass through here
				errx(1, "ERROR: unrecognized command-line option [ %s ]", arg); }
	return 1; }

int main(int argc, char *argv[]) {
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	umask(0);

	acfs_options.usage_limit = acfs_opts_def_usage_limit;
	if (fuse_opt_parse(&args, &acfs_options, option_spec, acfs_opt_proc) == -1) return 1;
	if (args.argc == 3 || args.argc == 5) {
		// Remove "device" argument in "mount -t fuse.acfs ..." with/without "-o" "<opts>"
		args.argc--; args.argv[args.argc-1] = args.argv[args.argc]; }

	acfs_mp.path = fuse_mnt_resolve_path(strdup(args.argv[0]), args.argv[args.argc-1]);
	acfs_mp.dir = malloc(sizeof(struct acfs_dirp));
	if (acfs_mp.dir == NULL) return 1;
	acfs_mp.dir->dp = opendir(acfs_mp.path);
	if (acfs_mp.dir->dp == NULL)
		err(1, "ERROR: mountpoint open [ %s ]", acfs_mp.path);
	if ((acfs_mp.fd = dirfd(acfs_mp.dir->dp)) == -1)
		err(1, "ERROR: mountpoint dirfd [ %s ]", acfs_mp.path);
	acfs_mp.dir->offset = 0;
	acfs_mp.dir->entry = NULL;

	acfs_mp.cleanup_path = acfs_mp.path;
	acfs_mp.cleanup_fd = acfs_mp.fd;
	if (acfs_options.cleanup_dir) {
		char *cwd = realpath(get_current_dir_name(), NULL);
		if ( chdir(acfs_mp.path) ||
				!(acfs_mp.cleanup_path = realpath(acfs_options.cleanup_dir, NULL)) || chdir(cwd) )
			err(1, "ERROR: cleanup-dir resolve [ %s ]", acfs_options.cleanup_dir);
		acfs_mp.cleanup_fd = openat( acfs_mp.fd,
			acfs_mp.cleanup_path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOCTTY );
		if (acfs_mp.cleanup_fd < 0)
			err(1, "ERROR: cleanup-dir open [ %s ]", acfs_mp.cleanup_path);
		free(cwd); }

	struct statvfs st;
	if (fstatvfs(acfs_mp.cleanup_fd, &st) || !st.f_blocks)
		errx(1, "ERROR: Failed to check space usage in cleanup-dir");
	unsigned long st_fsid = st.f_fsid;
	if (fstatvfs(acfs_mp.fd, &st)) err(1, "ERROR: mountpoint statvfs");
	if (st_fsid != st.f_fsid) errx(1, "ERROR: cleanup-dir is not same-fs as mountpoint");

	int ret = fuse_main(args.argc, args.argv, &acfs_oper, NULL);
	fuse_opt_free_args(&args);
	closedir(acfs_mp.dir->dp);
	free(acfs_mp.path);
	return ret;
}
