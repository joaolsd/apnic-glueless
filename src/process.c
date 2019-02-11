/*
 * Copyright (C) 2015       Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "config.h"
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#if defined(HAVE_SYS_WAIT_H)
#include <sys/wait.h>
#elif defined(HAVE_WAIT_H)
#include <wait.h>
#endif
#include "process.h"

#ifdef __linux__
static void getcpu(cpu_set_t* cpus, int n)
{
	int count = CPU_COUNT(cpus);
	n %= count;

	for (int i = 0; n >= 0; ++i) {
		if (CPU_ISSET(i, cpus)) {
			if (n-- == 0) {
				CPU_ZERO(cpus);
				CPU_SET(i, cpus);
				return;
			}
		}
	}

	fprintf(stderr, "unexpectedly ran out of CPUs");
}
#endif

static void make_threads(int threads, routine fn, void *data, int flags)
{
	if (threads <= 1) {
		fn(data);
	} else {
		pthread_t		pt[threads];
		pthread_attr_t	attr;
#ifdef __linux__
		int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
#endif

		/* start the desired number of threads */
		pthread_attr_init(&attr);
		for (int i = 0; i < threads; ++i) {
			pthread_create(&pt[i], &attr, fn, data);
#ifdef __linux__
			if (flags & FARM_AFFINITY_THREAD) {
				cpu_set_t	cpus;
				CPU_ZERO(&cpus);
				CPU_SET(i % ncpus, &cpus);
				pthread_setaffinity_np(pt[i], sizeof(cpus), &cpus);
			}
#endif
		}
		pthread_attr_destroy(&attr);

		/* wait for all of the threads to finish */
		for (int i = 0; i < threads; ++i) {
			pthread_join(pt[i], NULL);
		}
	}
}

void farm(int forks, int threads, routine fn, void *data, int flags)
{
	if (forks <= 1) {
		make_threads(threads, fn, data, flags);
	} else {

		/* fork the desired number of children */
		for (int i = 0; i < forks; ++i) {
			pid_t pid = fork();
			if (pid == 0) {			/* child */
				make_threads(threads, fn, data, flags);
			} else if (pid < 0) {	/* error */
				perror("fork");
			} else {
#ifdef __linux__
				if (flags & FARM_AFFINITY_FORK) {
					cpu_set_t cpus;
					sched_getaffinity(pid, sizeof(cpus), &cpus);
					getcpu(&cpus, i);
					sched_setaffinity(pid, sizeof(cpus), &cpus);
				}
#endif
			}
		}

		/* reap children */
		while (wait(NULL) > 0);
	}
}
