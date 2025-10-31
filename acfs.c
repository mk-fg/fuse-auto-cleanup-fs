/* FUSE: Filesystem in Userspace
	Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
	Copyright (C) 2011 Sebastian Pipping <sebastian@pipping.org>
	Copyright (C) 2019 Danilo Abbasciano <danilo@piumalab.org>
	Copyright (C) 2025 Mike Kazantsev
	This program can be distributed under the terms of the GNU GPL. See COPYING file. */

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
#include <pthread.h>
#include <libgen.h>


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
	pthread_mutex_t cleanup_mutex;
} acfs_mp;

static struct acfs_options {
	int usage_limit;
	char *cleanup_dir;
} acfs_options;
int acfs_opts_def_usage_limit = 90;


#define path_rel(p, rp) char rp[strlen(p)+2]; rp[0] = '.'; strcpy(rp+1, p);
#define return_op(op) return op == -1 ? -errno : 0;
#define return_op_fd(path, flags, op) \
	path_rel(path, rp); int fd = openat(acfs_mp.fd, rp, O_RDONLY); if (fd < 0) return -errno; \
	int res = (int) op == -1 ? -errno : 0; close(fd); return res;

// openat2 always seem to return "bad address" errno, maybe doesn't work on underlay-fs?
/* struct open_how how = { // XXX: optional RESOLVE_NO_XDEV */
/* 	.flags = flags | O_CLOEXEC, */
/* 	.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS }; */
/* return (int) syscall(SYS_openat2, acfs_mp.fd, path, how, sizeof(struct open_how)); */


int acfs_cleanup_prefixlen = 0;
char acfs_cleanup_oldest[PATH_MAX+1] = {0};
time_t acfs_cleanup_mtime = 0;

int acfs_cleanup_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	if (typeflag != FTW_F || (acfs_cleanup_mtime && acfs_cleanup_mtime <= sb->st_mtime)) return 0;
	acfs_cleanup_mtime = sb->st_mtime;
	strncpy(acfs_cleanup_oldest, fpath + acfs_cleanup_prefixlen, PATH_MAX);
	return 0;
}

static int acfs_cleanup() {
	int res = 0; struct statvfs st;
	if (fstatvfs(acfs_mp.fd, &st)) return -errno;
	while (100 - (st.f_bavail * 100 / st.f_blocks) > acfs_options.usage_limit) {
		if (pthread_mutex_lock(&acfs_mp.cleanup_mutex)) return -errno;
		acfs_cleanup_prefixlen = strlen(acfs_mp.cleanup_path) + 1;
		// FTW_PHYS is fine here because nftw uses path and this overlay anyway
		nftw(acfs_mp.cleanup_path, acfs_cleanup_cb, 500, FTW_MOUNT | FTW_PHYS);
		if (acfs_cleanup_oldest[0]) {
			char *dir = "";
			if (unlinkat(acfs_mp.cleanup_fd, acfs_cleanup_oldest, 0)) res = -errno;
			else dir = dirname(acfs_cleanup_oldest);
			// Try to remove empty parent dirs up to cleanup_fd or symlinks in path
			while (dir[0] && dir[0] != '.' && dir[0] != '/') {
				if (unlinkat(acfs_mp.cleanup_fd, dir, AT_REMOVEDIR)) {
					if (errno != ENOTEMPTY) res = -errno;
					break; }
				dir = dirname(dir); } }
		acfs_cleanup_oldest[0] = acfs_cleanup_mtime = 0;
		if (pthread_mutex_unlock(&acfs_mp.cleanup_mutex)) return -errno;
		if (!acfs_cleanup_oldest[0]) break; // nothing left to cleanup
		if (fstatvfs(acfs_mp.fd, &st)) return -errno; }
	return res;
}


// Except for init, all other calls below are defined in fuse_operations/acfs_ops order.
// Implementation is heavily derived from libfuse/example/passthrough_fh.c

static int acfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	if (fi) return_op(fstat(fi->fh, stbuf));
	path_rel(path, rp);
	return_op(fstatat(acfs_mp.fd, rp, stbuf, AT_SYMLINK_NOFOLLOW));
}

static int acfs_readlink(const char *path, char *buf, size_t size) {
	path_rel(path, rp);
	int res = readlinkat(acfs_mp.fd, rp, buf, size - 1);
	if (res == -1) return -errno;
	buf[res] = '\0';
	return 0;
}

static int acfs_mknod(const char *path, mode_t mode, dev_t rdev) {
	if (S_ISFIFO(mode)) return_op(mkfifo(path, mode));
	return_op(mknod(path, mode, rdev)); }

static int acfs_mkdir(const char *path, mode_t mode) {
	path_rel(path, rp);
	return_op(mkdirat(acfs_mp.fd, rp, mode)); }

static int acfs_unlink(const char *path) {
	path_rel(path, rp);
	return_op(unlinkat(acfs_mp.fd, rp, 0)); }

static int acfs_rmdir(const char *path) {
	path_rel(path, rp);
	return_op(unlinkat(acfs_mp.fd, rp, AT_REMOVEDIR)); }

static int acfs_symlink(const char *from, const char *to) {
	path_rel(to, rp);
	return_op(symlinkat(from, acfs_mp.fd, rp)); }

static int acfs_rename(const char *from, const char *to, unsigned int flags) {
	path_rel(from, rp_from); path_rel(to, rp_to);
	return_op(renameat2(acfs_mp.fd, rp_from, acfs_mp.fd, rp_to, flags)); }

static int acfs_link(const char *from, const char *to) {
	path_rel(from, rp_from); path_rel(to, rp_to);
	return_op(linkat(acfs_mp.fd, rp_from, acfs_mp.fd, rp_to, AT_SYMLINK_FOLLOW)); }

static int acfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
	if (fi) return_op(fchmod(fi->fh, mode));
	path_rel(path, rp);
	return_op(fchmodat(acfs_mp.fd, rp, mode, 0)); }

static int acfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
	if (fi) return_op(fchown(fi->fh, uid, gid));
	path_rel(path, rp);
	return_op(fchownat(acfs_mp.fd, rp, uid, gid, AT_SYMLINK_NOFOLLOW)); }

static int acfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	if (fi) return_op(ftruncate(fi->fh, size));
	path_rel(path, rp);
	int fd = openat(acfs_mp.fd, rp, O_WRONLY); if (fd < 0) return -errno;
	int res = ftruncate(fd, size); close(fd); return res;
}

static int acfs_open(const char *path, struct fuse_file_info *fi) {
	path_rel(path, rp);
	int fd = openat(acfs_mp.fd, rp, fi->flags);
	if (fd == -1) return -errno;
	if (fi->flags & O_DIRECT) {
		fi->direct_io = 1;
		fi->parallel_direct_writes = 1; }
	fi->fh = fd;
	return 0;
}

static int acfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	return_op(pread(fi->fh, buf, size, offset)); }

static int acfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	return_op(pwrite(fi->fh, buf, size, offset)); }

static int acfs_statfs(const char *path, struct statvfs *stbuf) { return_op(fstatvfs(acfs_mp.fd, stbuf)); }
static int acfs_flush(const char *path, struct fuse_file_info *fi) { return_op(close(dup(fi->fh))); }

static int acfs_release(const char *path, struct fuse_file_info *fi) {
	int res = 0;
	if (close(fi->fh) == -1) res = -errno;
	if (!res) res = acfs_cleanup();
	return res;
}

static int acfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	if (isdatasync) return_op(fdatasync(fi->fh));
	return_op(fsync(fi->fh)); }

static int acfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
	return_op_fd(path, 0, fsetxattr(fd, name, value, size, flags)); }
static int acfs_getxattr(const char *path, const char *name, char *value, size_t size) {
	return_op_fd(path, 0, fgetxattr(fd, name, value, size)); }
static int acfs_listxattr(const char *path, char *list, size_t size) {
	return_op_fd(path, 0, flistxattr(fd, list, size)); }
static int acfs_removexattr(const char *path, const char *name) {
	return_op_fd(path, 0, fremovexattr(fd, name)); }

static int acfs_opendir(const char *path, struct fuse_file_info *fi) {
	int res;
	if (strcmp(path, "/") == 0) {
		if (acfs_mp.dir == NULL) return -errno;
		fi->fh = (unsigned long) acfs_mp.dir;
		return 0; }
	struct acfs_dirp *d = malloc(sizeof(struct acfs_dirp));
	if (d == NULL) return -ENOMEM;
	path_rel(path, rp);
	int fd = openat( acfs_mp.fd, rp,
		O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOCTTY | O_NONBLOCK );
	if (fd < 0) { res = -errno; free(d); return res; }
	if (!(d->dp = fdopendir(fd))) { res = -errno; close(fd); free(d); return res; }
	d->offset = 0;
	d->entry = NULL;
	fi->fh = (unsigned long) d;
	return 0;
}

static int acfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
	struct acfs_dirp *d = (struct acfs_dirp *) (uintptr_t) fi->fh;
	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset; }
	while (1) {
		struct stat st;
		off_t nextoff;
		enum fuse_fill_dir_flags fill_flags = FUSE_FILL_DIR_DEFAULTS;
		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry) break; }
		if (flags & FUSE_READDIR_PLUS) {
			int res;
			res = fstatat(dirfd(d->dp), d->entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
			if (res != -1) fill_flags |= FUSE_FILL_DIR_PLUS; }
		if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
			memset(&st, 0, sizeof(st));
			st.st_ino = d->entry->d_ino;
			st.st_mode = d->entry->d_type << 12; }
		nextoff = telldir(d->dp);
		if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags)) break;
		d->entry = NULL;
		d->offset = nextoff; }
	return 0;
}

static int acfs_releasedir(const char *path, struct fuse_file_info *fi) {
	struct acfs_dirp *d = (struct acfs_dirp *) (uintptr_t) fi->fh;
	if (d->dp == acfs_mp.dir->dp) return 0;
	closedir(d->dp);
	free(d);
	return 0;
}

static int acfs_access(const char *path, int mask) {
	path_rel(path, rp);
	return_op(faccessat(acfs_mp.fd, rp, mask, AT_EACCESS)); }

static int acfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	path_rel(path, rp);
	int fd = openat(acfs_mp.fd, rp, fi->flags, mode);
	if (fd == -1) return -errno;
	fi->fh = fd;
	return 0;
}

static int acfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
	if (fi) return_op(futimens(fi->fh, ts));
	path_rel(path, rp);
	return_op(utimensat(acfs_mp.fd, rp, ts, AT_SYMLINK_NOFOLLOW));
}

static int acfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset, struct fuse_file_info *fi) {
	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = offset;
	return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int acfs_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset, struct fuse_file_info *fi) {
	struct fuse_bufvec *src;
	src = malloc(sizeof(struct fuse_bufvec));
	if (src == NULL) return -ENOMEM;
	*src = FUSE_BUFVEC_INIT(size);
	src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	src->buf[0].fd = fi->fh;
	src->buf[0].pos = offset;
	*bufp = src;
	return 0;
}

static int acfs_flock(const char *path, struct fuse_file_info *fi, int op) { return_op(flock(fi->fh, op)); }

static int acfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi) {
	if (mode) return -EOPNOTSUPP;
	if (fi) return -posix_fallocate(fi->fh, offset, length);
	path_rel(path, rp);
	int fd = openat(acfs_mp.fd, rp, O_WRONLY); if (fd < 0) return -errno;
	int res = -posix_fallocate(fd, offset, length); close(fd); return res;
}

static ssize_t acfs_copy_file_range( const char *path_in,
		struct fuse_file_info *fi_in, off_t off_in, const char *path_out,
		struct fuse_file_info *fi_out, off_t off_out, size_t len, int flags ) {
	int fd_in, fd_out;
	if (fi_in) fd_in = fi_in->fh;
	else { path_rel(path_in, rp_in);
		fd_in = openat(acfs_mp.fd, rp_in, O_RDONLY); if (fd_in < 0) return -errno; }
	if (fi_out) fd_out = fi_out->fh;
	else { path_rel(path_out, rp_out);
		fd_out = openat(acfs_mp.fd, rp_out, O_WRONLY); if (fd_out < 0) return -errno; }
	int res = copy_file_range(fd_in, &off_in, fd_out, &off_out, len, flags);
	if (res == -1) res = -errno;
	if (!fi_in) close(fd_in);
	if (!fi_out) close(fd_out);
	return res;
}

static off_t acfs_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi) {
	return_op(lseek(fi->fh, off, whence)); }


static void *acfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
	cfg->use_ino = 1;
	cfg->nullpath_ok = 1;
	cfg->parallel_direct_writes = 1;
	// Same rationale as in libfuse/example/passthrough_fh.c, except
	//  caches here are even more desynced due to cleanup in acfs_release.
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;
	return NULL;
}

// Same order as https://libfuse.github.io/doxygen/structfuse__operations.html
static const struct fuse_operations acfs_ops = {
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
	.lseek = acfs_lseek,
	// .statx - not in fuse releases yet as of 2025-10-31
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
			fuse_main(args->argc, args->argv, &acfs_ops, NULL);
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
			fuse_main(args->argc, args->argv, &acfs_ops, NULL);
			exit(0); }
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
	pthread_mutex_init(&acfs_mp.cleanup_mutex, NULL);

	struct statvfs st;
	if (fstatvfs(acfs_mp.cleanup_fd, &st) || !st.f_blocks)
		errx(1, "ERROR: Failed to check space usage in cleanup-dir");
	unsigned long st_fsid = st.f_fsid;
	if (fstatvfs(acfs_mp.fd, &st)) err(1, "ERROR: mountpoint statvfs");
	if (st_fsid != st.f_fsid) errx(1, "ERROR: cleanup-dir is not same-fs as mountpoint");

	int res = fuse_main(args.argc, args.argv, &acfs_ops, NULL);
	fuse_opt_free_args(&args);
	closedir(acfs_mp.dir->dp);
	free(acfs_mp.path);
	return res;
}
