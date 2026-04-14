#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

extern char **environ;

static void apply_mitigations(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "scell: failed to enable no_new_privs: %s\n", strerror(errno));
        exit(1);
    }

    {
        struct rlimit limit;
        const rlim_t default_max_procs = 256;

        if (getrlimit(RLIMIT_NPROC, &limit) != 0) {
            fprintf(stderr, "scell: failed to read process limit: %s\n", strerror(errno));
            exit(1);
        }

        if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur <= default_max_procs) {
            return;
        }

        limit.rlim_cur = default_max_procs;
        if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < limit.rlim_cur) {
            limit.rlim_cur = limit.rlim_max;
        }

        if (setrlimit(RLIMIT_NPROC, &limit) != 0) {
            fprintf(stderr, "scell: failed to set process limit: %s\n", strerror(errno));
            exit(1);
        }
    }
}

static const char *find_original_command(void) {
    const size_t prefix_len = strlen("ORIGINAL_COMMAND");

    for (char **entry = environ; entry != NULL && *entry != NULL; entry++) {
        char *equals = strchr(*entry, '=');
        size_t name_len;

        if (equals == NULL) {
            continue;
        }

        name_len = (size_t) (equals - *entry);
        if (name_len < prefix_len) {
            continue;
        }

        for (size_t i = 0; i + prefix_len <= name_len; i++) {
            if (strncmp(*entry + i, "ORIGINAL_COMMAND", prefix_len) == 0) {
                return equals + 1;
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    const char *original_command;

    apply_mitigations();

    original_command = find_original_command();

    if (argc > 1) {
        char **shell_argv = calloc((size_t) argc + 1, sizeof(*shell_argv));
        if (shell_argv == NULL) {
            fprintf(stderr, "scell: calloc failed: %s\n", strerror(errno));
            return 1;
        }
        shell_argv[0] = "/bin/sh";
        for (int i = 1; i < argc; i++) {
            shell_argv[i] = argv[i];
        }
        execv("/bin/sh", shell_argv);
    } else if (original_command != NULL && original_command[0] != '\0') {
        char *const shell_argv[] = {"/bin/sh", "-c", (char *) original_command, NULL};
        execv("/bin/sh", shell_argv);
    } else {
        char *const shell_argv[] = {"/bin/sh", NULL};
        execv("/bin/sh", shell_argv);
    }

    fprintf(stderr, "scell: failed to exec /bin/sh: %s\n", strerror(errno));
    return errno == ENOENT ? 127 : 126;
}

