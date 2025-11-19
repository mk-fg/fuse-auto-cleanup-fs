// Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
// Copyright (C) 2011 Sebastian Pipping <sebastian@pipping.org>
// Copyright (C) 2019 Danilo Abbasciano <danilo@piumalab.org>
// Copyright (C) 2025 Mike Kazantsev
// This program can be distributed under the terms of the GNU GPL. See COPYING file.
//
// Build: gcc -I/usr/include/fuse3 -lfuse3 -Wall -O2 -o acfs acfs.c && strip acfs
// Usage info: ./acfs -h

#define ACFS_VERSION "1.0"
#define FUSE_USE_VERSION 31

#define _GNU_SOURCE

#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/file.h>
#include <stddef.h>
#include <ftw.h>
#include <err.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/param.h>


// Internal open() that blocks symlinks - libfuse should resolve those before acfs_ops
#define acfs_open(dir_fd, path, f) acfs_openat2( dir_fd, path, \
	(struct open_how){.flags=f, .resolve=RESOLVE_NO_SYMLINKS} )
#define acfs_open_mode(dir_fd, path, f, m) acfs_openat2( dir_fd, path, \
	(struct open_how){.flags=f, .mode=m & 07777, .resolve=RESOLVE_NO_SYMLINKS} )
#define acfs_open_dir(dir_fd, path) acfs_openat2(dir_fd, path, (struct open_how){ \
	.resolve=RESOLVE_NO_SYMLINKS, \
	.flags=O_RDONLY | O_DIRECTORY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW })
int acfs_openat2(int dir_fd, const char* path, struct open_how how) {
	return syscall(SYS_openat2, dir_fd, path, &how, sizeof(struct open_how)); }


struct acfs_dirp { DIR *dp; struct dirent *entry; off_t offset; };
struct acfs_rmfile { time_t ts; char *fn; };

static struct acfs_mp {
	int fd;
	struct acfs_dirp *dir;
	char *path;
} acfs_mp;

static struct acfs_clean {
	char *path;
	int fd;
	pthread_mutex_t mutex;
	int prefixlen;
	int buff_n;
	int buff_hwm;
	bool buff_sorted;
	struct acfs_rmfile *buff;
} acfs_clean;

static struct acfs_opts {
	int usage_hwm;
	int usage_lwm;
	char *cleanup_dir;
	int cleanup_buff_sz;
} acfs_opts;

int acfs_opts_def_usage_hwm = 90;
int acfs_opts_def_usage_lwm_diff = 5;
int acfs_opts_def_cbuff_sz = 50;


#define acfs_log(fmt, arg...) // fuse_log_debug seem to spam stderr without -d, not sure why
// #define acfs_log(fmt, arg...) fuse_log(FUSE_LOG_DEBUG, "acfs :: " fmt "\n", ##arg);

static int acfs_cleanup_cmp(const void *p1, const void *p2) {
	const struct acfs_rmfile *f1 = p1, *f2 = p2;
	if (!f1->fn && f2->fn) return 1;
	if (f1->fn && !f2->fn) return -1;
	return f1->ts == f2->ts ? 0 : (f1->ts < f2->ts ? -1 : 1); }

static int acfs_cleanup_cb( const char *fpath,
		const struct stat *sb, int typeflag, struct FTW *ftwbuf ) {
	if (typeflag != FTW_F) goto end;
	// Keeps 1*sz in buff qsort'ed, and up to .5*sz tail for entries with ts < buff[sz].ts
	// Sorts when buffer fills-up, discarding tail entries after buff[sz] (with newest ts)
	struct acfs_rmfile *rmf = acfs_clean.buff_sorted ?
		acfs_clean.buff + acfs_opts.cleanup_buff_sz - 1 : NULL;
	time_t ts_last = rmf ? rmf->ts : 0;
	if (ts_last && ts_last < sb->st_mtime) goto end;
	// Sanity-checks that returned path is absolute one starting with acfs_clean.path,
	//   but assumes there won't be a double-slash or /../ returned by nftw() after that.
	if (strncmp(fpath, acfs_clean.path, acfs_clean.prefixlen)) goto end;

	if (acfs_clean.buff_n >= acfs_clean.buff_hwm) { // sort, discard tail
		qsort( acfs_clean.buff, acfs_clean.buff_hwm,
			sizeof(struct acfs_rmfile), acfs_cleanup_cmp );
		acfs_clean.buff_n = acfs_opts.cleanup_buff_sz;
		acfs_clean.buff_sorted = true;
		for (int n = acfs_clean.buff_n; n < acfs_clean.buff_hwm; n++) {
			rmf = acfs_clean.buff + n; if (rmf->fn) free(rmf->fn); } }

	rmf = acfs_clean.buff + acfs_clean.buff_n;
	int fn_sz = strlen(fpath + acfs_clean.prefixlen); // prefix-/ will free 1B for \0
	rmf->ts = sb->st_mtime; if (!(rmf->fn = malloc(fn_sz))) return FTW_STOP;
	strncpy(rmf->fn, fpath + acfs_clean.prefixlen + 1, fn_sz);
	acfs_clean.buff_n++;
	end: return FTW_CONTINUE;
}

static int acfs_cleanup_du() {
	struct statvfs st;
	if (fstatvfs(acfs_mp.fd, &st)) return -errno;
	return 100 - (st.f_bavail * 100 / st.f_blocks); }

static int acfs_cleanup() {
	// trylock is to block only one close() call by cleanup
	if (pthread_mutex_trylock(&acfs_clean.mutex))
		return errno == EBUSY ? 0 : -errno;

	int res = 0, du = acfs_cleanup_du();
	if (du < 0) res = du;
	else if (du < acfs_opts.usage_hwm) du = 0;

	if (!acfs_clean.buff) {
		acfs_clean.buff_hwm = 3 * acfs_opts.cleanup_buff_sz / 2;
		acfs_clean.buff = calloc(acfs_clean.buff_hwm, sizeof(struct acfs_rmfile));
		if (!acfs_clean.buff) { du = 0; res = -ENOMEM; } }

	while (du > acfs_opts.usage_lwm) {
		int n = 0;
		acfs_clean.prefixlen = strlen(acfs_clean.path);
		acfs_clean.buff_n = 0; acfs_clean.buff_sorted = false;

		// FTW_MOUNT is fine here because nftw uses path and this overlay anyway
		if (nftw( acfs_clean.path, acfs_cleanup_cb, 500,
				FTW_MOUNT | FTW_PHYS | FTW_ACTIONRETVAL ) == FTW_STOP) {
			res = -ENOMEM; goto buff_cleanup; }
		if (!acfs_clean.buff_n) goto skip;

		qsort( acfs_clean.buff, acfs_clean.buff_n,
			sizeof(struct acfs_rmfile), acfs_cleanup_cmp );
		while (n < acfs_clean.buff_n) {
			struct acfs_rmfile *rmf = acfs_clean.buff + n;
			acfs_log("cleanup: rm [ %s ]", rmf->fn);
			char rm[PATH_MAX+1]; int rm_pos = 0, rm_flags = 0;
			strncpy(rm, rmf->fn, PATH_MAX);
			int dir_fd = -1; char *fn = basename(rm), *dir = dirname(rmf->fn);
			if (dir[0] == '/') res = -EMEDIUMTYPE; // bug in acfs_cleanup_cb
			else if ((dir_fd = acfs_open_dir(acfs_clean.fd, dir)) < 0) res = -errno;
			while (dir_fd >= 0) { // remove file, then try to remove empty parent dirs
				if (unlinkat(dir_fd, fn, rm_flags)) {
					if (!rm_flags) res = -errno; // dir cleanup is entirely opportunistic
					break; }
				if (dir[0] == '.') break;
				acfs_log("cleanup: rmdir [ %s ]", dir);
				strcpy(rm + rm_pos, "../"); rm_pos += 3;
				if (!(fn = strrchr(dir, '/'))) fn = dir;
				strcpy(rm + rm_pos, fn); fn = rm;
				dir = dirname(dir); rm_flags = AT_REMOVEDIR; }
			free(rmf->fn); n++; if (dir_fd >= 0) close(dir_fd);
			if ((du = acfs_cleanup_du()) <= acfs_opts.usage_lwm) break; }

		buff_cleanup:
		while (n < acfs_clean.buff_n) free(acfs_clean.buff[n++].fn);

		skip:
		if (!acfs_clean.buff_n) { acfs_log("cleanup: no files found"); break; }
		if ((res = res ? res : du < 0 ? du : res)) break; }

	if (pthread_mutex_unlock(&acfs_clean.mutex)) return -errno;
	return res;
}


// Except for init, all other calls below are defined in fuse_operations/acfs_ops order.
// Implementation is heavily derived from libfuse/example/passthrough_fh.c

#define acfs_op_path_rel(p, rp) char rp[strlen(p)+2]; rp[0] = '.'; strcpy(rp+1, p);
#define acfs_op_return(op) return op == -1 ? -errno : 0;

// acfs_op_dirfd* are openat2() wrappers for symlink-safe path operations
#define acfs_op_dirfd_nocheck(path, fn, dir_fd) \
	char fn[NAME_MAX+1]; char p_##path[PATH_MAX+1]; \
	acfs_op_path_rel(path, rp_##path); \
	strcpy(p_##path, rp_##path); strncpy(fn, basename(p_##path), NAME_MAX); \
	int dir_fd = acfs_open_dir(acfs_mp.fd, dirname(rp_##path)); \
	if (dir_fd < 0) dir_fd = -errno;
#define acfs_op_dirfd(path, fd, dir_fd) \
	acfs_op_dirfd_nocheck(path, fd, dir_fd); if (dir_fd < 0) return dir_fd;
#define acfs_op_return_dirfd(dir_fd, op) \
	int res = op == -1 ? -errno : 0; close(dir_fd); return res;

static int acfs_op_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	if (fi) acfs_op_return(fstat(fi->fh, stbuf));
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, fstatat(dir_fd, fn, stbuf, AT_SYMLINK_NOFOLLOW)); }

static int acfs_op_readlink(const char *path, char *buf, size_t size) {
	acfs_op_dirfd(path, fn, dir_fd);
	int res = readlinkat(dir_fd, fn, buf, size - 1);
	if (res == -1) res = -errno;
	else { buf[res] = 0; res = 0; }
	close(dir_fd);
	return res; }

static int acfs_op_mknod(const char *path, mode_t mode, dev_t rdev) {
	acfs_op_dirfd(path, fn, dir_fd);
	if (S_ISFIFO(mode)) { acfs_op_return_dirfd(dir_fd, mkfifoat(dir_fd, fn, mode)); }
	acfs_op_return_dirfd(dir_fd, mknodat(dir_fd, fn, mode, rdev)); }

static int acfs_op_mkdir(const char *path, mode_t mode) {
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, mkdirat(dir_fd, fn, mode)); }

static int acfs_op_unlink(const char *path) {
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, unlinkat(dir_fd, fn, 0)); }

static int acfs_op_rmdir(const char *path) {
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, unlinkat(dir_fd, fn, AT_REMOVEDIR)); }

static int acfs_op_symlink(const char *from, const char *to) {
	acfs_op_dirfd(to, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, symlinkat(from, dir_fd, fn)); }

static int acfs_op_rename(const char *from, const char *to, unsigned int flags) {
	acfs_op_dirfd_nocheck(from, fn_from, dir_fd_from);
	if (dir_fd_from < 0) return dir_fd_from;
	acfs_op_dirfd_nocheck(to, fn_to, dir_fd_to);
	if (dir_fd_to < 0) { close(dir_fd_from); return dir_fd_to; }
	int res = renameat2(dir_fd_from, fn_from, dir_fd_to, fn_to, flags);
	res = res == -1 ? -errno : 0; close(dir_fd_from); close(dir_fd_to); return res; }

static int acfs_op_link(const char *from, const char *to) {
	acfs_op_dirfd_nocheck(from, fn_from, dir_fd_from);
	if (dir_fd_from < 0) return dir_fd_from;
	acfs_op_dirfd_nocheck(to, fn_to, dir_fd_to);
	if (dir_fd_to < 0) { close(dir_fd_from); return dir_fd_to; }
	int res = linkat(dir_fd_from, fn_from, dir_fd_to, fn_to, AT_SYMLINK_FOLLOW);
	res = res == -1 ? -errno : 0; close(dir_fd_from); close(dir_fd_to); return res; }

static int acfs_op_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
	if (fi) acfs_op_return(fchmod(fi->fh, mode));
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, fchmodat(dir_fd, fn, mode, AT_SYMLINK_NOFOLLOW)); }

static int acfs_op_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
	if (fi) acfs_op_return(fchown(fi->fh, uid, gid));
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd(dir_fd, fchownat(dir_fd, fn, uid, gid, AT_SYMLINK_NOFOLLOW)); }

static int acfs_op_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	if (fi) acfs_op_return(ftruncate(fi->fh, size));
	acfs_op_path_rel(path, rp);
	int fd = acfs_open(acfs_mp.fd, rp, O_WRONLY);
	if (fd < 0) return -errno;
	int res = ftruncate(fd, size); close(fd); return res; }

static int acfs_op_open(const char *path, struct fuse_file_info *fi) {
	acfs_op_path_rel(path, rp);
	int fd = acfs_open(acfs_mp.fd, rp, fi->flags);
	if (fd == -1) return -errno;
	if (fi->flags & O_DIRECT) {
		fi->direct_io = 1;
		fi->parallel_direct_writes = 1; }
	fi->fh = fd;
	return 0; }

static int acfs_op_read( const char *path, char *buf,
		size_t size, off_t offset, struct fuse_file_info *fi ) {
	acfs_op_return(pread(fi->fh, buf, size, offset)); }

static int acfs_op_write( const char *path, const char *buf,
		size_t size, off_t offset, struct fuse_file_info *fi ) {
	acfs_op_return(pwrite(fi->fh, buf, size, offset)); }

static int acfs_op_statfs(const char *path,
	struct statvfs *stbuf) { acfs_op_return(fstatvfs(acfs_mp.fd, stbuf)); }
static int acfs_op_flush(const char *path,
	struct fuse_file_info *fi) { acfs_op_return(close(dup(fi->fh))); }

static int acfs_op_release(const char *path, struct fuse_file_info *fi) {
	int res = 0;
	if (close(fi->fh) == -1) res = -errno;
	if (!res) res = acfs_cleanup();
	return res; }

static int acfs_op_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	if (isdatasync) acfs_op_return(fdatasync(fi->fh));
	acfs_op_return(fsync(fi->fh)); }

#define acfs_op_return_fd(path, op) \
	acfs_op_path_rel(path, rp); \
	int fd = acfs_open(acfs_mp.fd, rp, O_RDONLY); if (fd < 0) return -errno; \
	int res = (int) op == -1 ? -errno : 0; close(fd); return res;
static int acfs_op_setxattr(const char *path,
		const char *name, const char *value, size_t size, int flags) {
	acfs_op_return_fd(path, fsetxattr(fd, name, value, size, flags)); }
static int acfs_op_getxattr(const char *path, const char *name, char *value, size_t size) {
	acfs_op_return_fd(path, fgetxattr(fd, name, value, size)); }
static int acfs_op_listxattr(const char *path, char *list, size_t size) {
	acfs_op_return_fd(path, flistxattr(fd, list, size)); }
static int acfs_op_removexattr(const char *path, const char *name) {
	acfs_op_return_fd(path, fremovexattr(fd, name)); }

static int acfs_op_opendir(const char *path, struct fuse_file_info *fi) {
	int res;
	if (strcmp(path, "/") == 0) {
		if (acfs_mp.dir == NULL) return -errno;
		fi->fh = (unsigned long) acfs_mp.dir;
		return 0; }
	struct acfs_dirp *d = malloc(sizeof(struct acfs_dirp));
	if (d == NULL) return -ENOMEM;
	acfs_op_path_rel(path, rp);
	int fd = acfs_open_dir(acfs_mp.fd, rp);
	if (fd < 0) { res = -errno; free(d); return res; }
	if (!(d->dp = fdopendir(fd))) { res = -errno; close(fd); free(d); return res; }
	d->offset = 0;
	d->entry = NULL;
	fi->fh = (unsigned long) d;
	return 0;
}

static int acfs_op_readdir( const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags ) {
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

static int acfs_op_releasedir(const char *path, struct fuse_file_info *fi) {
	struct acfs_dirp *d = (struct acfs_dirp *) (uintptr_t) fi->fh;
	if (d->dp == acfs_mp.dir->dp) return 0;
	closedir(d->dp);
	free(d);
	return 0; }

static int acfs_op_access(const char *path, int mask) {
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd( dir_fd,
		faccessat(dir_fd, fn, mask, AT_EACCESS | AT_SYMLINK_NOFOLLOW) ); }

static int acfs_op_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	acfs_op_path_rel(path, rp);
	int fd = acfs_open_mode(acfs_mp.fd, rp, fi->flags, mode);
	if (fd == -1) return -errno;
	fi->fh = fd;
	return 0; }

static int acfs_op_utimens( const char *path,
		const struct timespec ts[2], struct fuse_file_info *fi ) {
	if (fi) acfs_op_return(futimens(fi->fh, ts));
	acfs_op_dirfd(path, fn, dir_fd);
	acfs_op_return_dirfd( dir_fd,
		utimensat(dir_fd, fn, ts, AT_SYMLINK_NOFOLLOW) ); }

static int acfs_op_write_buf( const char *path,
		struct fuse_bufvec *buf, off_t offset, struct fuse_file_info *fi ) {
	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = offset;
	return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK); }

static int acfs_op_read_buf( const char *path,
		struct fuse_bufvec **bufp, size_t size, off_t offset, struct fuse_file_info *fi ) {
	struct fuse_bufvec *src = malloc(sizeof(struct fuse_bufvec));
	if (src == NULL) return -ENOMEM;
	*src = FUSE_BUFVEC_INIT(size);
	src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	src->buf[0].fd = fi->fh;
	src->buf[0].pos = offset;
	*bufp = src;
	return 0; }

static int acfs_op_flock( const char *path,
	struct fuse_file_info *fi, int op ) { acfs_op_return(flock(fi->fh, op)); }

static int acfs_op_fallocate( const char *path,
		int mode, off_t offset, off_t length, struct fuse_file_info *fi ) {
	if (mode) return -EOPNOTSUPP;
	if (fi) return -posix_fallocate(fi->fh, offset, length);
	acfs_op_path_rel(path, rp);
	int fd = acfs_open(acfs_mp.fd, rp, O_WRONLY);
	if (fd < 0) return -errno;
	int res = -posix_fallocate(fd, offset, length); close(fd); return res;
}

static ssize_t acfs_op_copy_file_range( const char *path_in,
		struct fuse_file_info *fi_in, off_t off_in, const char *path_out,
		struct fuse_file_info *fi_out, off_t off_out, size_t len, int flags ) {
	int fd_in, fd_out;
	if (fi_in) fd_in = fi_in->fh;
	else { acfs_op_path_rel(path_in, rp_in);
		fd_in = acfs_open(acfs_mp.fd, rp_in, O_RDONLY); if (fd_in < 0) return -errno; }
	if (fi_out) fd_out = fi_out->fh;
	else { acfs_op_path_rel(path_out, rp_out);
		fd_out = acfs_open(acfs_mp.fd, rp_out, O_WRONLY); if (fd_out < 0) return -errno; }
	int res = copy_file_range(fd_in, &off_in, fd_out, &off_out, len, flags);
	if (res == -1) res = -errno;
	if (!fi_in) close(fd_in);
	if (!fi_out) close(fd_out);
	return res;
}

static off_t acfs_op_lseek( const char *path, off_t off, int whence,
	struct fuse_file_info *fi ) { acfs_op_return(lseek(fi->fh, off, whence)); }


static void *acfs_op_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
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
	.getattr = acfs_op_getattr,
	.readlink = acfs_op_readlink,
	.mknod = acfs_op_mknod,
	.mkdir = acfs_op_mkdir,
	.unlink = acfs_op_unlink,
	.rmdir = acfs_op_rmdir,
	.symlink = acfs_op_symlink,
	.rename = acfs_op_rename,
	.link = acfs_op_link,
	.chmod = acfs_op_chmod,
	.chown = acfs_op_chown,
	.truncate = acfs_op_truncate,
	.open = acfs_op_open,
	.read = acfs_op_read,
	.write = acfs_op_write,
	.statfs = acfs_op_statfs,
	.flush = acfs_op_flush,
	.release = acfs_op_release,
	.fsync = acfs_op_fsync,
	.setxattr = acfs_op_setxattr,
	.getxattr = acfs_op_getxattr,
	.listxattr = acfs_op_listxattr,
	.removexattr = acfs_op_removexattr,
	.opendir = acfs_op_opendir,
	.readdir = acfs_op_readdir,
	.releasedir = acfs_op_releasedir,
	// .fsyncdir
	.init = acfs_op_init,
	// .destroy
	.access = acfs_op_access,
	.create = acfs_op_create,
	// .lock - posix file locks will be mountpoint-local
	.utimens = acfs_op_utimens,
	// .bmap
	// .ioctl
	// .poll
	.write_buf = acfs_op_write_buf,
	.read_buf = acfs_op_read_buf,
	.flock = acfs_op_flock,
	.fallocate = acfs_op_fallocate,
	.copy_file_range = acfs_op_copy_file_range,
	.lseek = acfs_op_lseek,
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


#define ACFS_OPT(opt, key) {opt, offsetof(struct acfs_opts, key), 1}
#define ACFS_LONG_OPT(opt, type, key) ACFS_OPT(opt "=" type, key), \
	ACFS_OPT("--" opt " " type, key), ACFS_OPT("--" opt "=" type, key)

enum { ACFS_KEY_HELP, ACFS_KEY_VER };
static const struct fuse_opt option_spec[] = {
	ACFS_LONG_OPT("usage-limit", "%d", usage_hwm),
	ACFS_OPT("-u %d", usage_hwm), ACFS_OPT("-u=%d", usage_hwm),
	ACFS_LONG_OPT("usage-lwm", "%d", usage_lwm),
	ACFS_OPT("-U %d", usage_lwm), ACFS_OPT("-U=%d", usage_lwm),
	ACFS_LONG_OPT("cleanup-dir", "%s", cleanup_dir),
	ACFS_LONG_OPT("cleanup-buff-sz", "%d", cleanup_buff_sz),
	FUSE_OPT_KEY("-V", ACFS_KEY_VER), FUSE_OPT_KEY("--version", ACFS_KEY_VER),
	FUSE_OPT_KEY("-h", ACFS_KEY_HELP), FUSE_OPT_KEY("--help", ACFS_KEY_HELP),
	FUSE_OPT_END };

static int acfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *args) {
	switch (key) {
		case ACFS_KEY_HELP:
			fuse_opt_add_arg(args, "-h");
			fuse_main(args->argc, args->argv, &acfs_ops, NULL);
			printf(
"\nACFS filesystem-specific options (usable as `-o <opt>=<value>` in mount/fstab):\n\n"
"    -u <percentage>   --usage-limit=<percentage>\n"
"       Used space percentage threshold to cleanup mounted directory to. Default: %d%%\n\n"
"    -U <percentage>   --usage-lwm=<percentage>\n"
"       Used-space%% to cleanup down to after it reaches usage-limit.\n"
"       Default: %d%% under usage-limit, unless specified with this option.\n\n"
"    --cleanup-dir=<path>\n"
"       Directory to lookup for files to remove. Default is to use whole mounted dir.\n"
"       Path can either be absolute or relative to the mounted dir, must be on same fs.\n"
"       Symlinks/mountpoints under this dir are not traversed in any way.\n\n"
"    --cleanup-buff-sz=<n>\n"
"       How many oldest-mtime cleanup-candidate files to find in one cleanup-dir scan.\n"
"       Should be set above typical number of files to remove to get disk usage from\n"
"        usage-limit%% down to usage-lwm%%, depending on average file sizes. Default: %d\n\n",
				acfs_opts_def_usage_hwm, acfs_opts_def_usage_lwm_diff, acfs_opts_def_cbuff_sz );
			exit(1);
		case ACFS_KEY_VER:
			printf("acfs version %s\n", ACFS_VERSION);
			fuse_opt_add_arg(args, "--version");
			fuse_main(args->argc, args->argv, &acfs_ops, NULL);
			exit(0); }
	return 1; }

int main(int argc, char *argv[]) {
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	umask(0);

	acfs_opts.usage_hwm = acfs_opts_def_usage_hwm;
	acfs_opts.usage_lwm = 0;
	acfs_opts.cleanup_buff_sz = acfs_opts_def_cbuff_sz;
	if (fuse_opt_parse(&args, &acfs_opts, option_spec, acfs_opt_proc) == -1) return 1;
	if (!acfs_opts.usage_lwm)
		acfs_opts.usage_lwm = acfs_opts.usage_hwm - acfs_opts_def_usage_lwm_diff;
	if (acfs_opts.cleanup_buff_sz < 2) errx(1, "ERROR: cleanup-buff-sz must be >1");
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

	acfs_clean.path = acfs_mp.path;
	acfs_clean.fd = acfs_mp.fd;
	if (acfs_opts.cleanup_dir) {
		char *cwd = realpath(get_current_dir_name(), NULL);
		if ( chdir(acfs_mp.path) ||
				!(acfs_clean.path = realpath(acfs_opts.cleanup_dir, NULL)) || chdir(cwd) )
			err(1, "ERROR: cleanup-dir resolve [ %s ]", acfs_opts.cleanup_dir);
		acfs_clean.fd = acfs_open_dir(acfs_mp.fd, acfs_clean.path);
		if (acfs_clean.fd < 0)
			err(1, "ERROR: cleanup-dir open [ %s ]", acfs_clean.path);
		free(cwd); }
	pthread_mutex_init(&acfs_clean.mutex, NULL);

	struct statvfs st;
	if (fstatvfs(acfs_clean.fd, &st) || !st.f_blocks)
		errx(1, "ERROR: Failed to check space usage in cleanup-dir");
	unsigned long st_fsid = st.f_fsid;
	if (fstatvfs(acfs_mp.fd, &st)) err(1, "ERROR: mountpoint statvfs");
	if (st_fsid != st.f_fsid) errx(1, "ERROR: cleanup-dir is not same-fs as mountpoint");

	return fuse_main(args.argc, args.argv, &acfs_ops, NULL);
}
