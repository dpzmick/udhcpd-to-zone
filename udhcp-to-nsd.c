#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct __attribute__((packed))
{
  uint32_t expire_time;
  uint32_t ip;          // network byte order
  char     mac[6];      // don't care byte order
  char     hostname[20];
  char     pad[2];
} lease_t;

typedef struct __attribute__((packed))
{
  int64_t  write_time;
  lease_t  leases[];
} lease_file_t;

lease_file_t* open_leases(char const* fname, size_t* out_n)
{
  int fd = open(fname, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "ERROR: failed to open '%s' with %s\n", fname, strerror(errno));
    return NULL;
  }

  off_t sz = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  if (sz < sizeof(uint64_t)) {
    fprintf(stderr, "ERROR: lease file %s is is missing write_time header\n", fname);
    close(fd);
    return NULL;
  }

  size_t rem_sz = sz - sizeof(uint64_t);
  if ((rem_sz/sizeof(lease_t))*sizeof(lease_t) != rem_sz) {
    fprintf(stderr, "ERROR: lease file %s is incorrect size. got=%zu, needed multiple of %zu\n",
                    fname, rem_sz, sizeof(lease_t));
    close(fd);
    return NULL;
  }

  lease_file_t* ret = mmap(0, sz, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ret == (lease_file_t*)MAP_FAILED) {
    fprintf(stderr, "ERROR: Failed to mmap with %s\n", strerror(errno));
    ret = NULL;
  }
  close(fd);

  *out_n = rem_sz/sizeof(lease_t);
  return ret;
}

void close_leases(lease_file_t* leases, size_t n)
{
  if (leases) munmap(leases, sizeof(*leases)*n + sizeof(uint64_t));
}

int main(int argc, char** argv)
{
  if (argc != 4) {
    fprintf(stderr, "Usage: %s udhcpd-leases partial-forward-zones partial-reverse-zones\n", argv[0]);
    return 1;
  }

  char const* lease_fn = argv[1];
  char const* p_fwd    = argv[2];
  char const* p_rev    = argv[3];

  FILE* f_fwd = fopen(p_fwd, "w");
  fprintf(stderr, "Writing forward names to %s\n", p_fwd);
  if (!f_fwd) {
    fprintf(stderr, "ERROR: failed to open fwd output file %s\n", p_fwd);
    return 1;
  }

  FILE* f_rev = fopen(p_rev, "w");
  fprintf(stderr, "Writing reverse names to %s\n", p_rev);
  if (!f_rev) {
    fprintf(stderr, "ERROR: failed to open rev output file %s\n", p_rev);
    return 1;
  }

  size_t n = 0;
  lease_file_t* leases = open_leases(lease_fn, &n);
  printf("Lease file last updated at %zd. Found %zu leases\n", bswap_64(leases->write_time), n);
  for (size_t i = 0; i < n; ++i) {
    lease_t const* l = &(leases->leases[i]);
    fprintf(f_fwd, "%s\tIN\tA\t%d.%d.%d.%d\n",
		   l->hostname,
		   l->ip & 0xff,
		   (l->ip & 0xff00) >> 8,
		   (l->ip & 0xff0000) >> 16,
		   (l->ip & 0xff000000) >> 24);
    fprintf(f_rev, "%d.%d.%d.%d.in-addr.arpa.\tIN\tPTR\t%s\n",
		   (l->ip & 0xff000000) >> 24,
		   (l->ip & 0xff0000) >> 16,
		   (l->ip & 0xff00) >> 8,
		   l->ip & 0xff,
		   l->hostname);
  }
  close_leases(leases, n);
  fclose(f_fwd);
}
