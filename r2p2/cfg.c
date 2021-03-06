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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libconfig.h>

#include <r2p2/cfg.h>

#ifndef LINUX
#include <net/net.h>
#endif

struct cfg_parameters CFG;
config_t cfg;

#define CFG_PATH "/etc/r2p2.conf"

static int parse_addr(const char *name, uint32_t *dst)
{
	struct sockaddr_in router_addr;
	const char *parsed = NULL;

	config_lookup_string(&cfg, name, (const char **)&parsed);
	if (!parsed)
		return -1;
	inet_pton(AF_INET, parsed, &(router_addr.sin_addr));
	*dst = be32toh(router_addr.sin_addr.s_addr);

	return 0;
}

static int parse_port(const char *name, uint16_t *dst)
{
	int port = -1;

	config_lookup_int(&cfg, name, &port);
	if (port == -1)
		return -1;
	*dst = port;

	return 0;
}

#ifdef WITH_TIMESTAMPING
static int parse_ifname(void)
{
	const char *parsed = NULL;
	config_lookup_string(&cfg, "if_name", (const char **)&parsed);
	if (!parsed)
		return -1;

	strcpy(CFG.if_name, parsed);

	return 0;
}
#endif

#ifndef LINUX
static int parse_arp(void)
{
	const config_setting_t *arp = NULL, *entry = NULL;
	int i;
	const char *ip = NULL, *mac = NULL;

	arp = config_lookup(&cfg, "arp");
	if (!arp) {
		fprintf(stderr, "no static arp entries defined in config\n");
		return -1;
	}

	for (i = 0; i < config_setting_length(arp); ++i) {
		entry = config_setting_get_elem(arp, i);
		config_setting_lookup_string(entry, "ip", &ip);
		config_setting_lookup_string(entry, "mac", &mac);
		if (!ip || !mac)
			return -1;
		add_arp_entry(ip, mac);
	}
	return 0;
}
#endif

int parse_config(void)
{
	int ret;
	config_init(&cfg);

	if (!config_read_file(&cfg, CFG_PATH)) {
		fprintf(stderr, "Error parsing config %s:%d - %s\n",
				config_error_file(&cfg), config_error_line(&cfg),
				config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	ret = parse_addr("router_addr", &CFG.router_addr);
	if (ret) {
		fprintf(stderr, "no router addr found\n");
		CFG.router_addr = 0;
	}

	ret = parse_port("router_port", &CFG.router_port);
	if (ret) {
		fprintf(stderr, "no router port found\n");
		CFG.router_port = 0;
	}

#ifdef WITH_TIMESTAMPING
	ret = parse_ifname();
	if (ret) {
		fprintf(stderr, "no iface name found\n");
		return ret;
	}
#endif

#ifdef LINUX
	return 0;
#else
	ret = parse_addr("host_addr", &CFG.host_addr);
	if (ret) {
		fprintf(stderr, "error parsing ip\n");
		config_destroy(&cfg);
		return ret;
	}

	ret = parse_port("host_port", &CFG.host_port);
	if (ret) {
		fprintf(stderr, "error parsing port\n");
		config_destroy(&cfg);
		return ret;
	}

	ret = parse_arp();
	if (ret) {
		fprintf(stderr, "error parsing port\n");
		config_destroy(&cfg);
		return ret;
	}
#endif

	return 0;
}
