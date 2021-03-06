/*
 * MIT License
 *
 * Copyright (c) 2019-2021 Ecole Polytechnique Federale Lausanne (EPFL)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <r2p2/api.h>

#define THREAD_COUNT 1
#define RPC_TO_SEND 1

int64_t start_time = 0;
int c = 0;
int64_t *results;

#define NB_RESULTS 100

struct r2p2_host_tuple destination;
static int __thread should_send;

static inline int64_t time_ns(void)
{
	struct timespec ts;
	int r = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(r == 0);
	return (ts.tv_nsec + ts.tv_sec * 1e9);
}

void test_success_cb(long handle, void *arg, struct iovec *iov, int iovcnt)
{
	int64_t time = time_ns() - start_time;
	results[c++] = time;
	r2p2_recv_resp_done(handle);
	should_send = 1;
}

void test_error_cb(void *arg, int err)
{
	printf("r2p2 error\n");
}

void test_timeout_cb(void *arg)
{
	printf("r2p2 timeout\n");
}

static void *thread_main(void *arg)
{
	struct r2p2_ctx ctx;
	struct iovec local_iov;
	char msg[] = "1234";
	int count = 0;
	int core_id = (int)(long)arg;

	// configure r2p2 context
	ctx.success_cb = test_success_cb;
	ctx.error_cb = test_error_cb;
	ctx.timeout_cb = test_timeout_cb;
	ctx.arg = (void *)0xDEADBEEF;
	ctx.destination = &destination;
	ctx.timeout = 10000000;
	ctx.routing_policy = LB_ROUTE;

	// configure the message iov
	local_iov.iov_len = 4; // sizeof(long);
	local_iov.iov_base = msg;

	if (r2p2_init_per_core(1, 2)) {
		printf("Error initialising per core\n");
		exit(1);
	}

	should_send = 1;
	do {
		if (should_send) {
			if (c == NB_RESULTS)
				break;
			should_send = 0;
			struct iovec server_name = {"TEST", 4};
			start_time = time_ns();
			r2p2_send_req(&local_iov, 1, &ctx, server_name);
		}
		r2p2_poll();
	} while (1);

	for (int i = 0; i < NB_RESULTS; i++) {
		printf("%lld\n", results[i]);
	}

	return;
}

int main(int argc, char **argv)
{
	int i;
	struct sockaddr_in sa;
	pthread_t tid;

	if (argc != 3) {
		printf("Usage: ./linux_client <dst_ip> <dst_port>\n");
		return -1;
	}

	if (r2p2_init(8080)) {
		printf("Error initialising\n");
		exit(1);
	}
	results = malloc(NB_RESULTS * sizeof(int64_t));
	// configure server destination
	inet_pton(AF_INET, argv[1], &(sa.sin_addr));
	destination.port = atoi(argv[2]);
	destination.ip = sa.sin_addr.s_addr;
	
	r2p2_tls_init(0);
	for (i = 1; i < THREAD_COUNT; i++) {
		if (pthread_create(&tid, NULL, thread_main, (void *)(long)i)) {
			fprintf(stderr, "failed to spawn thread %d\n", i);
			exit(-1);
		}
	}

	thread_main((void *)(long)0);
}
