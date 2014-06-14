/*
 * Copyright (C) 2009-2012 Joel Rosdahl
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "ccache.h"
#include "hashtable.h"
#include "hashutil.h"
#include "murmurhashneutral2.h"
#include "macroskip.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <uv.h>

unsigned
hash_from_string(void *str)
{
	return murmurhashneutral2(str, strlen((const char *)str), 0);
}

unsigned
hash_from_int(int i)
{
	return murmurhashneutral2(&i, sizeof(int), 0);
}

int
strings_equal(void *str1, void *str2)
{
	return str_eq((const char *)str1, (const char *)str2);
}

int
file_hashes_equal(struct file_hash *fh1, struct file_hash *fh2)
{
	return memcmp(fh1->hash, fh2->hash, 16) == 0
		&& fh1->size == fh2->size;
}

/*
 * Search for the strings "__DATE__" and "__TIME__" in str.
 *
 * Returns a bitmask with HASH_SOURCE_CODE_FOUND_DATE and
 * HASH_SOURCE_CODE_FOUND_TIME set appropriately.
 */
int
check_for_temporal_macros(const char *str, size_t len)
{
	int result = 0;

	/*
	 * We're using the Boyer-Moore-Horspool algorithm, which searches starting
	 * from the *end* of the needle. Our needles are 8 characters long, so i
	 * starts at 7.
	 */
	size_t i = 7;

	while (i < len) {
		/*
		 * Check whether the substring ending at str[i] has the form "__...E__". On
		 * the assumption that 'E' is less common in source than '_', we check
		 * str[i-2] first.
		 */
		if (str[i - 2] == 'E' &&
		    str[i - 0] == '_' &&
		    str[i - 7] == '_' &&
		    str[i - 1] == '_' &&
		    str[i - 6] == '_') {
			/*
			 * Check the remaining characters to see if the substring is "__DATE__"
			 * or "__TIME__".
			 */
			if (str[i - 5] == 'D' && str[i - 4] == 'A' &&
			    str[i - 3] == 'T') {
				result |= HASH_SOURCE_CODE_FOUND_DATE;
			}
			else if (str[i - 5] == 'T' && str[i - 4] == 'I' &&
				 str[i - 3] == 'M') {
				result |= HASH_SOURCE_CODE_FOUND_TIME;
			}
		}

		/*
		 * macro_skip tells us how far we can skip forward upon seeing str[i] at
		 * the end of a substring.
		 */
		i += macro_skip[(uint8_t)str[i]];
	}

	return result;
}

/*
 * Hash a string. Returns a bitmask of HASH_SOURCE_CODE_* results.
 */
int
hash_source_code_string(
	struct conf *conf, struct mdfour *hash, const char *str, size_t len,
	const char *path)
{
	int result = HASH_SOURCE_CODE_OK;
	// TODO The result of this should also be cachable with the caching hash
	// daemon.

	/*
	 * Check for __DATE__ and __TIME__ if the sloppiness configuration tells us
	 * we should.
	 */
	if (!(conf->sloppiness & SLOPPY_TIME_MACROS)) {
		result |= check_for_temporal_macros(str, len);
	}

	/*
	 * Hash the source string.
	 */
	hash_file(hash, path);

	if (result & HASH_SOURCE_CODE_FOUND_DATE) {
		/*
		 * Make sure that the hash sum changes if the (potential) expansion of
		 * __DATE__ changes.
		 */
		time_t t = time(NULL);
		struct tm *now = localtime(&t);
		cc_log("Found __DATE__ in %s", path);
		hash_delimiter(hash, "date");
		hash_buffer(hash, &now->tm_year, sizeof(now->tm_year));
		hash_buffer(hash, &now->tm_mon, sizeof(now->tm_mon));
		hash_buffer(hash, &now->tm_mday, sizeof(now->tm_mday));
	}
	if (result & HASH_SOURCE_CODE_FOUND_TIME) {
		/*
		 * We don't know for sure that the program actually uses the __TIME__
		 * macro, but we have to assume it anyway and hash the time stamp. However,
		 * that's not very useful since the chance that we get a cache hit later
		 * the same second should be quite slim... So, just signal back to the
		 * caller that __TIME__ has been found so that the direct mode can be
		 * disabled.
		 */
		cc_log("Found __TIME__ in %s", path);
	}

	return result;
}

/*
 * Hash a file ignoring comments. Returns a bitmask of HASH_SOURCE_CODE_*
 * results.
 */
int
hash_source_code_file(struct conf *conf, struct mdfour *hash, const char *path)
{
	char *data;
	size_t size;

	cc_log("hash_source_code_file %s", path);

	if (is_precompiled_header(path)) {
		if (hash_file(hash, path)) {
			return HASH_SOURCE_CODE_OK;
		} else {
			return HASH_SOURCE_CODE_ERROR;
		}
	} else {
		int result;

		if (!read_file(path, 0, &data, &size)) {
			return HASH_SOURCE_CODE_ERROR;
		}
		result = hash_source_code_string(conf, hash, data, size, path);
		free(data);
		return result;
	}
}

bool
hash_command_output(struct mdfour *hash, const char *command,
                    const char *compiler)
{
#ifdef _WIN32
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE pipe_out[2];
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DWORD exitcode;
	char *sh = NULL;
	char *win32args;
	char *path;
	BOOL ret;
	bool ok;
	int fd;
#else
	pid_t pid;
	int pipefd[2];
#endif

	struct args *args = args_init_from_string(command);
	int i;
	for (i = 0; i < args->argc; i++) {
		if (str_eq(args->argv[i], "%compiler%")) {
			args_set(args, i, compiler);
		}
	}
	cc_log_argv("Executing compiler check command ", args->argv);

#ifdef _WIN32
	memset(&pi, 0x00, sizeof(pi));
	memset(&si, 0x00, sizeof(si));

	path = find_executable(args->argv[0], NULL);
	if (!path)
		path = args->argv[0];
	sh = win32getshell(path);
	if (sh)
		path = sh;

	si.cb = sizeof(STARTUPINFO);
	CreatePipe(&pipe_out[0], &pipe_out[1], &sa, 0);
	SetHandleInformation(pipe_out[0], HANDLE_FLAG_INHERIT, 0);
	si.hStdOutput = pipe_out[1];
	si.hStdError  = pipe_out[1];
	si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
	si.dwFlags    = STARTF_USESTDHANDLES;
	win32args = win32argvtos(sh, args->argv);
	ret = CreateProcess(path, win32args, NULL, NULL, 1, 0, NULL, NULL, &si, &pi);
	CloseHandle(pipe_out[1]);
	args_free(args);
	free(win32args);
	if (ret == 0) {
		stats_update(STATS_COMPCHECK);
		return false;
	}
	fd = _open_osfhandle((intptr_t) pipe_out[0], O_BINARY);
	ok = hash_fd_raw(hash, fd);
	if (!ok) {
		cc_log("Error hashing compiler check command output: %s", strerror(errno));
		stats_update(STATS_COMPCHECK);
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exitcode);
	CloseHandle(pipe_out[0]);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	if (exitcode != 0) {
		cc_log("Compiler check command returned %d", (int) exitcode);
		stats_update(STATS_COMPCHECK);
		return false;
	}
	return ok;
#else
	if (pipe(pipefd) == -1) {
		fatal("pipe failed");
	}
	pid = fork();
	if (pid == -1) {
		fatal("fork failed");
	}

	if (pid == 0) {
		/* Child. */
		close(pipefd[0]);
		close(0);
		dup2(pipefd[1], 1);
		dup2(pipefd[1], 2);
		_exit(execvp(args->argv[0], args->argv));
		return false; /* Never reached. */
	} else {
		/* Parent. */
		int status;
		bool ok;
		args_free(args);
		close(pipefd[1]);
		ok = hash_fd_raw(hash, pipefd[0]);
		if (!ok) {
			cc_log("Error hashing compiler check command output: %s", strerror(errno));
			stats_update(STATS_COMPCHECK);
		}
		close(pipefd[0]);
		if (waitpid(pid, &status, 0) != pid) {
			cc_log("waitpid failed");
			return false;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			cc_log("Compiler check command returned %d", WEXITSTATUS(status));
			stats_update(STATS_COMPCHECK);
			return false;
		}
		return ok;
	}
#endif
}

bool
hash_multicommand_output(struct mdfour *hash, const char *commands,
                         const char *compiler)
{
	char *command_string, *command, *p, *saveptr = NULL;
	bool ok = true;

	command_string = x_strdup(commands);
	p = command_string;
	while ((command = strtok_r(p, ";", &saveptr))) {
		if (!hash_command_output(hash, command, compiler)) {
			ok = false;
		}
		p = NULL;
	}
	free(command_string);
	return ok;
}

void
perror_die(const char *msg)
{
	perror(msg);
	abort();
}

struct msg
{
	uint8_t cmd;
	union
	{
		struct {
			bool success;
			unsigned char hash[16];
		} hash_reply;
		char path[512];
		struct {
			char path[512];
			unsigned char hash[16];
		} add_hash;
	};
};

enum cmd
{
	// Update mdfour with the contents of the file at the given path.
	// The reply is a CMD_HASH_FILE with an update mdfour member.
	CMD_HASH_FILE,
	// We hashed a file, store the hash in the hash-cache.
	CMD_ADD_HASH,
};

static struct hashtable *hash_cache;
static unsigned hash_hits, hash_misses;

bool
s_cmd(struct msg *msg, const struct conf *conf)
{
	switch (msg->cmd)
	{
	case CMD_HASH_FILE:
	{
		const unsigned char *existing;

		// Planning to add some configury for how paranoid to be about things
		// in hash-cache. (e.g. check mtime (want to avoid the stat), check
		// mtime + inode + stuff, randomized rechecks.) For now, trust that
		// anything in cache will stay valid until the user kills the daemon.
		(void)conf;

		existing = hashtable_search(hash_cache, msg->path);
		if (existing)
		{
			//fprintf(stderr, "Found hash of %s in cache\n", msg->path);
			hash_hits++;
			msg->hash_reply.success = true;
			memcpy(msg->hash_reply.hash, existing, 16);
			return true;
		}

		hash_misses++;

		// Just give a negative response, let the client hash the file and
		// add it using CMD_ADD_HASH
#if 1
		msg->hash_reply.success = false;
#else
		char *path = x_strdup(msg->path);
		msg->hash_reply.success = hash_file_raw(path, msg->hash_reply.hash);
		hashtable_insert(hash_cache, path, x_strndup((const char*)buf, 16));
#endif
		return true;
	}
	case CMD_ADD_HASH:
	{
		if (!hashtable_search(hash_cache, msg->add_hash.path))
		{
			char *path = x_strndup(msg->add_hash.path, sizeof(msg->add_hash.path));
			char *hash = x_strndup((const char *)msg->add_hash.hash, sizeof(msg->add_hash.hash));
			hashtable_insert(hash_cache, path, hash);
		}
		return false;
	}
	default:
		fprintf(stderr, "Unknown/unhandled command %u", msg->cmd);
		return false;
	}
}

static uv_loop_t *loop;
static void on_new_connection(uv_stream_t *server, int status);
static void write_cb(uv_write_t* req, int status);
static time_t last_stat;

bool
hash_daemon(struct conf *conf)
{
	loop = uv_default_loop();
	int res;

	hash_cache = create_hashtable(1000, hash_from_string, strings_equal);
	assert(!conf->use_hash_daemon);

	uv_pipe_t server;
	uv_pipe_init(loop, &server, 0);

	char *name = format("%s/hash_daemon", conf->cache_dir);
	unlink(name);
	if ((res = uv_pipe_bind(&server, name))) {
		fprintf(stderr, "Bind error %s\n", uv_err_name(res));
		return false;
	}
	if ((res = uv_listen((uv_stream_t*)&server, 128, on_new_connection))) {
		fprintf(stderr, "Listen error %s\n", uv_err_name(res));
		return false;
	}
	fprintf(stderr, "hash daemon on %s\n", name);
	free(name);
    return uv_run(loop, UV_RUN_DEFAULT);
}

struct client_data
{
	struct msg msg;
	size_t fill;
	uv_write_t write_req;
};
#define CDATA(cdata, x) struct client_data *cdata = (struct client_data *)x->data

static void client_buffer(uv_handle_t *stream, size_t suggested_size, uv_buf_t *buf) {
	CDATA(client, stream);
	(void)suggested_size;
	fprintf(stderr, "client_buffer: fill=%u\n", (unsigned)client->fill);
	char *p = (char *)&client->msg + client->fill;
	*buf = uv_buf_init(p, sizeof(struct msg) - client->fill);
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	extern struct conf *conf;
	CDATA(client, stream);

	if (nread < 0) {
		fprintf(stderr, "read_cb: nread=%d (%s)\n", (int)nread, uv_err_name(nread));
		uv_close((uv_handle_t*)stream, 0);
		return;
	}

	fprintf(stderr, "read_cb: %ld bytes read\n", (unsigned long)nread);

	(void)buf;
	client->fill += nread;
	if (client->fill == sizeof(struct msg)) {
		client->fill = 0;
		fprintf(stderr, "read_cb: message complete: cmd=%u\n", client->msg.cmd);
		if (s_cmd(&client->msg, conf)) {
			uv_buf_t buf = uv_buf_init((char *)&client->msg, sizeof(struct msg));
			int res = uv_write(&client->write_req, stream, &buf, 1, write_cb);
			if (res != 0) {
				fprintf(stderr, "read_cb: write res=%d (%s)\n", res, uv_err_name(res));
				uv_close((uv_handle_t*)stream, 0);
				return;
			}
			uv_read_stop(stream);
		} else {
			fprintf(stderr, "read_cb: no reply for %u\n", client->msg.cmd);
		}
	}
}

static void write_cb(uv_write_t* req, int status) {
	uv_stream_t *stream = req->handle;

	fprintf(stderr, "write_cb: status=%d (%s)\n", status, uv_err_name(status));

	if (status) {
		uv_close((uv_handle_t*)stream, NULL);
		return;
	}

	if (last_stat != time(NULL)) {
		time(&last_stat);
		fprintf(stderr, "cache hit/miss: %u/%u\n", hash_hits, hash_misses);
	}

	uv_read_start(stream, client_buffer, read_cb);
}

static void close_client(uv_handle_t* handle) {
	free(handle->data);
	//free(handle);
}

void on_new_connection(uv_stream_t *server, int status) {
    if (status == -1) {
        // error!
        return;
    }

	fprintf(stderr, "new connection\n");

    uv_pipe_t *client = (uv_pipe_t*) malloc(sizeof(uv_pipe_t));
    uv_pipe_init(loop, client, 0);
	client->data = calloc(1, sizeof(struct client_data));
	client->close_cb = close_client;
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
		uv_read_start((uv_stream_t*)client, client_buffer, read_cb);
    } else {
        uv_close((uv_handle_t*) client, NULL);
		// Does this free client?
    }
}

ssize_t writeall(int fd, const void *buf, size_t count)
{
	size_t written = 0;
	while (written < count) {
		ssize_t res = write(fd, (char *)buf + written, count - written);
		if (res > 0) {
			written += res;
		} else {
			return res;
		}
	}
	return written;
}

ssize_t readall(int fd, void *buf, const size_t count)
{
	size_t nread = 0;
	while (nread < count) {
		ssize_t res = read(fd, (char *)buf + nread, count - nread);
		if (res > 0) {
			nread += res;
		} else {
			return res;
		}
	}
	return nread;
}

bool
c_cmd(int fd, struct msg *msg)
{
	ssize_t res = writeall(fd, msg, sizeof(struct msg));
	if (res <= 0) {
		return false;
	}

	res = readall(fd, msg, sizeof(struct msg));
	if (res <= 0) {
		fprintf(stderr, "hash-daemon didn't respond, hashing locally\n");
		return false;
	}
	return true;
}

static int hash_daemon_fd;

bool init_hash_client(struct conf *conf)
{
	if (hash_daemon_fd) {
		return true;
	}

	int s, res;
	struct sockaddr_un addr;

	hash_cache = create_hashtable(1000, hash_from_string, strings_equal);

	addr.sun_family = AF_UNIX;
	// Achtung: The cache_dir can be long, and sun_path can be as short as 100
	// bytes.
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/hash_daemon", conf->cache_dir);
	//fprintf(stderr, "hash daemon on %s\n", addr.sun_path);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s <= 0) {
		perror_die("socket");
		return false;
	}
	res = connect(s, &addr, sizeof(addr));
	if (res < 0) {
		perror_die("connect");
	}
	hash_daemon_fd = s;
	return true;
}

bool
hash_file_raw(const char *fname, unsigned char *buf)
{
	extern struct conf *conf;
	int fd = -1;
	struct mdfour md;
	bool res;
	char *real_path = x_realpath(fname);

	if (conf->use_hash_daemon)
	{
		// FIXME This only works where x_realpath uses a real realpath (which
		// produces absolute paths), instead of the fallback code which
		// doesn't. May need to explicitly involve current_working_dir.
		//extern char *current_working_dir;
		struct msg msg;
		memset(&msg, 0, sizeof(struct msg));
		msg.cmd = CMD_HASH_FILE;
		strcpy(msg.path, real_path);
		if (init_hash_client(conf) && c_cmd(hash_daemon_fd, &msg))
		{
			memcpy(buf, msg.hash_reply.hash, 16);
			res = msg.hash_reply.success;
			// If hash daemon didn't work, fall back to hashing locally.
			if (res) goto out;
		}
	}

	fd = open(fname, O_RDONLY|O_BINARY);
	if (fd == -1) {
		//fprintf(stderr, "ccache: Failed to open %s: %s\n", fname, strerror(errno));
		res = false;
		goto out;
	}

	mdfour_begin(&md);
	res = hash_fd_raw(&md, fd);
	hash_result_as_bytes(&md, buf);
	if (res && conf->use_hash_daemon && init_hash_client(conf))
	{
		struct msg msg;
		memset(&msg, 0, sizeof(struct msg));
		msg.cmd = CMD_ADD_HASH;
		strcpy(msg.add_hash.path, real_path);
		memcpy(msg.add_hash.hash, buf, 16);
		writeall(hash_daemon_fd, &msg, sizeof(msg));
	}
out:
	if (fd != -1) close(fd);
	free(real_path);
	return res;
}

