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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <dp/api.h>
#include <dp/core.h>

#include <r2p2/api.h>

#include <rte_eal.h>

int should_send = 1;
int64_t start_time = 0;

#define NB_RESULTS 10

struct r2p2_host_tuple destination;
int c = 0;
int64_t *results;

static inline int64_t time_ns(void)
{
	struct timespec ts;
	int r = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(r == 0);
	return (ts.tv_nsec + ts.tv_sec * 1e9);
}

void test_success_cb(long handle, void *arg, struct iovec *iov, int iovcnt)
{
	// printf("r2p2 was successful. Arg: %lx\n", (unsigned long)arg);
	// printf("Received msg: %s\n", (char *)iov[0].iov_base);

	int64_t time = time_ns() - start_time;
	results[c++] = time;
	r2p2_recv_resp_done(handle);
	should_send = 1;
}

void test_error_cb(void *arg, int err)
{
	printf("r2p2 error\n");
	assert(0);
}

void test_timeout_cb(void *arg)
{
	printf("r2p2 timeout\n");
	assert(0);
}

int app_init(__attribute__((unused)) int argc,
			 __attribute__((unused)) char **argv)
{
	printf("Hello r2p2 echo\n");
	struct sockaddr_in sa;

	if (argc != 3) {
		printf("Usage: ./linux_client <dst_ip> <dst_port>\n");
		return -1;
	}

	r2p2_tls_init(0);
	if (r2p2_init(8080)) { // this port number is not used
		printf("Error initialising\n");
		return -1;
	}

	results = malloc(NB_RESULTS * sizeof(int64_t));

	// configure server destination
	inet_pton(AF_INET, argv[1], &(sa.sin_addr));
	destination.port = atoi(argv[2]);
	destination.ip = sa.sin_addr.s_addr;

	return 0;
}

void app_main(void)
{
	struct r2p2_ctx ctx;
	struct iovec local_iov;
	char msg[] = "1234";
	int count = 0;
	int core_id = 0;


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

	if (r2p2_init_per_core(RTE_PER_LCORE(queue_id), rte_lcore_count())) {
		printf("Error initialising per core\n");
		exit(1);
	}

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
	} while (!force_quit);

	for (int i = 0; i < NB_RESULTS; i++) {
		printf("%lld\n", results[i]);
	}

	return;
}
