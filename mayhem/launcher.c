/* launcher.c — a tiny ELF that exec()s a Python entry point, forwarding argv.
 *
 * Mayhem requires every fuzz target `cmd:` to be an ELF binary (it rejects a script /
 * shebang wrapper, and fuzz-smoke.sh checks the ELF magic). endesive is pure Python, so
 * the Atheris libFuzzer harness is a `.py`. This shim is the ELF Mayhem launches; it
 * immediately execs `python3 <PY_SCRIPT> <args...>`, handing the libFuzzer/Atheris flags
 * straight through. The Python process then IS the libFuzzer target (it iterates inputs).
 *
 * The same shim also drives the known-answer test oracle (endesive-tests -> run_tests.py):
 * driving the oracle through an ELF is what makes the verify-repo §6.3 sabotage check
 * meaningful — its LD_PRELOAD constructor _exit(0)s every NON-system executable, so this
 * dynamically-linked shim gets neutered while the SPARED system /usr/bin/python3 does not.
 *
 * Built with $DEBUG_FLAGS (DWARF < 4) per SPEC §6.2 item 10, and dynamically linked so the
 * verify-repo sabotage oracle (LD_PRELOAD constructor) can neuter it.
 */
#include <stdlib.h>
#include <unistd.h>

#ifndef PY_SCRIPT
#define PY_SCRIPT "/mayhem/mayhem/fuzz_verify.py"
#endif

int main(int argc, char **argv) {
    char **nv = (char **)malloc((size_t)(argc + 2) * sizeof(char *));
    if (!nv) return 1;
    nv[0] = (char *)"python3";
    nv[1] = (char *)PY_SCRIPT;
    for (int i = 1; i < argc; i++) nv[i + 1] = argv[i];
    nv[argc + 1] = NULL;
    execvp("python3", nv);
    return 127; /* exec failed */
}
