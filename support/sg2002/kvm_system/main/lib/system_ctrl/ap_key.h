#ifndef AP_KEY_H_
#define AP_KEY_H_

// The Wi-Fi AP key is the WPA2 passphrase and the provisioning key at once.
// It comes from the kernel CSPRNG. Ten characters from 31 unambiguous symbols
// give about 49 bits and still fit one OLED line in the 6x8 font.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define AP_KEY_CHARS 10

// Host tests replace the random source to simulate its failure.
#ifndef AP_KEY_RANDOM
#define AP_KEY_RANDOM getrandom
#endif

// Fill `key` with AP_KEY_CHARS random characters and a NUL. Returns 0, or -1
// with `key` cleared when the random source fails: there is no weaker fallback.
static inline int ap_key_generate(char key[AP_KEY_CHARS + 1])
{
	// No 0/o or 1/l/i: the key is read off the OLED and may be typed by hand.
	static const char alphabet[] = "23456789abcdefghjkmnpqrstuvwxyz";
	const unsigned size = sizeof(alphabet) - 1;
	// Bytes at or above the largest multiple of `size` are drawn again, so
	// every character is equally likely.
	const unsigned limit = 256 / size * size;
	unsigned char pool[32];
	size_t used = sizeof(pool);
	int count = 0;
	while (count < AP_KEY_CHARS) {
		if (used == sizeof(pool)) {
			size_t done = 0;
			while (done < sizeof(pool)) {
				ssize_t got = AP_KEY_RANDOM(pool + done, sizeof(pool) - done, 0);
				if (got < 0 && errno == EINTR) continue;
				if (got <= 0) {
					memset(pool, 0, sizeof(pool));
					memset(key, 0, AP_KEY_CHARS + 1);
					return -1;
				}
				done += (size_t)got;
			}
			used = 0;
		}
		unsigned char byte = pool[used++];
		if (byte >= limit) continue;
		key[count++] = alphabet[byte % size];
	}
	key[AP_KEY_CHARS] = '\0';
	memset(pool, 0, sizeof(pool));
	return 0;
}

// Write `key` to `path` with mode 0600: a fresh scratch file beside it is
// synced, then renamed over it. Returns 0, or -1 with `path` unchanged.
static inline int ap_key_store(const char *path, const char *key)
{
	char scratch[256];
	int length = snprintf(scratch, sizeof(scratch), "%s.new", path);
	if (length < 0 || (size_t)length >= sizeof(scratch)) return -1;
	if (unlink(scratch) != 0 && errno != ENOENT) return -1;
	int fd = open(scratch, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) return -1;
	size_t total = strlen(key);
	size_t done = 0;
	int ok = fchmod(fd, 0600) == 0;
	while (ok && done < total) {
		ssize_t wrote = write(fd, key + done, total - done);
		if (wrote < 0 && errno == EINTR) continue;
		if (wrote <= 0) ok = 0;
		else done += (size_t)wrote;
	}
	if (ok && fsync(fd) != 0) ok = 0;
	if (close(fd) != 0) ok = 0;
	if (!ok || rename(scratch, path) != 0) {
		unlink(scratch);
		return -1;
	}
	return 0;
}

#endif // AP_KEY_H_
