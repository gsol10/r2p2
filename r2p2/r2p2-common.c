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

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <r2p2/api-internal.h>
#include <r2p2/mempool.h>
#ifdef WITH_TIMESTAMPING
static_assert(LINUX, "Timestamping supported only in Linux");
#include <r2p2/r2p2-linux.h>
#include <r2p2/timestamping.h>
#endif

#include <picotls.h>
#include <picotls/openssl.h>
#include <openssl/pem.h>

#define POOL_SIZE 1024
#define min(a, b) ((a) < (b)) ? (a) : (b)

static recv_fn rfn;
static app_flow_control afc_fn = NULL;

static ptls_context_t tls_ctx;

static __thread struct fixed_mempool *client_pairs;
static __thread struct fixed_mempool *server_pairs;
static __thread struct fixed_linked_list pending_client_pairs = {0};
static __thread struct fixed_linked_list pending_server_pairs = {0};
static __thread struct iovec to_app_iovec[0xFF]; // change this to 0xFF;
static __thread ptls_iovec_t tls_ticket = {NULL, 0};

static int on_save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
	if (tls_ticket.base != NULL) {
		free(tls_ticket.base);//TODO: better to avoid continuous free/malloc
	}
	printf("Saving ticket, len = %ld \n", src.len);
    tls_ticket.base = malloc(src.len);
    memcpy(tls_ticket.base, src.base, src.len);
    tls_ticket.len = src.len;
    return 0;
}

static int ticket_encrypt(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
	printf("Encrypt/Decrypt: %d callback called, src len is %lu\n", is_encrypt, src.len);
    int ret;

    if ((ret = ptls_buffer_reserve(dst, src.len)) != 0)
        return ret;
    memcpy(dst->base + dst->off, src.base, src.len);
    dst->off += src.len;

    return 0;
}

int r2p2_tls_init(int is_server) {
	//common
	memset(&tls_ctx, 0, sizeof(tls_ctx));
	tls_ctx.get_time = &ptls_get_time;
	tls_ctx.random_bytes = ptls_openssl_random_bytes;
	tls_ctx.key_exchanges = ptls_openssl_key_exchanges;
	assert(tls_ctx.key_exchanges[0] != NULL);
	tls_ctx.cipher_suites = ptls_openssl_cipher_suites;

	if (is_server) {
		//server
		static ptls_iovec_t certs[16];
		size_t count = 0;
		FILE *fcert = fopen("certificate.pem", "rb");
		assert(fcert != NULL);
		X509 *cert;
		while ((cert = PEM_read_X509(fcert, NULL, NULL, NULL)) != NULL) {
			ptls_iovec_t *dst = certs + count++;
			dst->len = i2d_X509(cert, &dst->base);
		}
		fclose(fcert);
		tls_ctx.certificates.list = certs;
		tls_ctx.certificates.count = count;
		static ptls_openssl_sign_certificate_t signer;
		FILE *fkey = fopen("key.pem", "rb");
		assert(fkey != NULL);
		EVP_PKEY *pkey = PEM_read_PrivateKey(fkey, NULL, NULL, NULL);
		assert(pkey != NULL);
		ptls_openssl_init_sign_certificate(&signer, pkey);
		EVP_PKEY_free(pkey);
		tls_ctx.sign_certificate = &signer.super;
		fclose(fkey);
		//0-RTT
		ptls_encrypt_ticket_t et = {ticket_encrypt};
		tls_ctx.encrypt_ticket = &et;
		printf("Init, pointer = %p\n", tls_ctx.encrypt_ticket); //TODO: stg really wrong here
		tls_ctx.ticket_lifetime = 3600; //Values to be seen later
		tls_ctx.max_early_data_size = 4096;
		tls_ctx.require_dhe_on_psk = 0;
	} else {
		//client
		ptls_openssl_verify_certificate_t *verifier;
		verifier = malloc(sizeof(ptls_openssl_verify_certificate_t));
		 //Might need this for self-signed certificates
		X509_STORE *xstore;
		xstore = X509_STORE_new();
		X509_STORE_load_locations(xstore, "certificate.pem", NULL); 
		ptls_openssl_init_verify_certificate(verifier, xstore);
		//ptls_openssl_init_verify_certificate(verifier, NULL);
		
		tls_ctx.verify_certificate = &verifier->super;
		ptls_save_ticket_t* st = malloc(sizeof(ptls_save_ticket_t) + sizeof(ptls_iovec_t*));
		st->cb = on_save_ticket;
		//ptls_save_ticket_t *st = {on_save_ticket};
		tls_ctx.save_ticket = st;
		printf("Init, pointer = %p\n", tls_ctx.save_ticket);
		
	}
	return 0;
}

static struct r2p2_client_pair *alloc_client_pair(void)
{
	struct r2p2_client_pair *cp;

	cp = alloc_object(client_pairs);
	assert(cp);

	bzero(cp, sizeof(struct r2p2_client_pair));

	return cp;
}

static void free_client_pair(struct r2p2_client_pair *cp)
{
	generic_buffer gb;

	// Free the received reply
	gb = cp->reply.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}

#ifdef LINUX
	// Free the request sent
	gb = cp->request.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}
#endif

	// Free the socket in linux on anything implementation specific
	if (cp->on_free)
		cp->on_free(cp->impl_data);

	free_object(cp);
}

static struct r2p2_server_pair *alloc_server_pair(void)
{
	struct r2p2_server_pair *sp;

	sp = alloc_object(server_pairs);
	assert(sp);

	bzero(sp, sizeof(struct r2p2_server_pair));

	return sp;
}

static void free_server_pair(struct r2p2_server_pair *sp)
{
	generic_buffer gb;

	// Free the recv message buffers
	gb = sp->request.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}

// Free the reply sent
#ifdef LINUX
	gb = sp->reply.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}
#endif

	free_object(sp);
}

static void add_to_pending_client_pairs(struct r2p2_client_pair *cp)
{
	struct fixed_obj *fo = get_object_meta(cp);
	add_to_list(&pending_client_pairs, fo);
}

static void add_to_pending_server_pairs(struct r2p2_server_pair *sp)
{
	struct fixed_obj *fo = get_object_meta(sp);
	add_to_list(&pending_server_pairs, fo);
}

static void remove_from_pending_server_pairs(struct r2p2_server_pair *sp)
{
	struct fixed_obj *fo = get_object_meta(sp);
	remove_from_list(&pending_server_pairs, fo);
}

static void remove_from_pending_client_pairs(struct r2p2_client_pair *cp)
{
	struct fixed_obj *fo = get_object_meta(cp);
	remove_from_list(&pending_client_pairs, fo);
}

static struct r2p2_server_pair *
find_in_pending_server_pairs(uint16_t req_id, struct r2p2_host_tuple *sender)
{
	struct r2p2_server_pair *sp;
	struct fixed_obj *fo;

	fo = pending_server_pairs.head;
	while (fo) {
		sp = (struct r2p2_server_pair *)fo->elem;
		if ((sp->request.sender.ip == sender->ip) &&
			(sp->request.sender.port == sender->port) &&
			(sp->request.req_id == req_id))
			return sp;
		fo = (struct fixed_obj *)fo->next;
	}
	return NULL;
}

static struct r2p2_client_pair *
find_in_pending_client_pairs(uint16_t req_id, struct r2p2_host_tuple *sender)
{
	struct r2p2_client_pair *cp;
	struct fixed_obj *fo;

	fo = pending_client_pairs.head;
	// FIXME: inlcude ip too
	while (fo) {
		cp = (struct r2p2_client_pair *)fo->elem;
		printf("cp sender port = %u, sender port = %u, rid = %d\n", cp->request.sender.port,sender->port,cp->request.req_id);
		if ((cp->request.sender.port == sender->port) &&
			(cp->request.req_id == req_id))
			return cp;
		fo = (struct fixed_obj *)fo->next;
	}
	printf("Request not found\n");
	return NULL;
}

static int prepare_to_app_iovec(struct r2p2_msg *msg)
{
	generic_buffer gb;
	char *buf;
	int len, iovcnt = 0;

	gb = msg->head_buffer;
	while (gb != NULL) {
		buf = get_buffer_payload(gb);
		assert(buf);
		len = get_buffer_payload_size(gb);
		to_app_iovec[iovcnt].iov_base = buf;
		to_app_iovec[iovcnt++].iov_len = len;
		gb = get_buffer_next(gb);
		assert(iovcnt < 0xFF);
	}
	return iovcnt;
}

static ptls_buffer_t *perform_handshake(ptls_t *tls, ptls_buffer_t *handshake, char *incoming, int len) {
	printf("dealing with %d\n", len);
	incoming = (char *)((struct r2p2_header *) incoming + 1);
	len -= sizeof(struct r2p2_header);
	int roff = 0;
	int ret;
	ptls_buffer_init(handshake, "", 0);
	ptls_buffer_t *rbuf = malloc(sizeof(ptls_buffer_t));
	ptls_buffer_init(rbuf, "", 0);
	if (!ptls_handshake_is_complete(tls)) {
		do {
			printf("Handshake, pointer = %p\n", tls_ctx.encrypt_ticket);
			size_t consumed = len - roff;
			ret = ptls_handshake(tls, handshake, incoming + roff, &consumed, NULL);
			roff += consumed;
		} while (ret == PTLS_ERROR_IN_PROGRESS && len != roff);
		printf("State = %d, in progress = %d, len = %d, roff = %d\n", ret, PTLS_ERROR_IN_PROGRESS, len, roff);
	}
	
	while (roff < len) {
		size_t consumed = len - roff;
		ret = ptls_receive(tls, rbuf, incoming + roff, &consumed);
		roff += consumed;
		printf("2\\State = %d, in progress = %d, len = %d, roff = %d, rbuf len = %ld\n", ret, PTLS_ERROR_IN_PROGRESS, len, roff, rbuf->off);
	}
	printf("Handshake len: %ld\n", handshake->off);
	//TODO: return error code
	if (rbuf->off == 0) {
		free(rbuf);
		return NULL;
	} else {
		return rbuf;
	}
}

static void handle_drop_msg(struct r2p2_client_pair *cp)
{
	cp->ctx->error_cb(cp->ctx->arg, -ERR_DROP_MSG);

	remove_from_pending_client_pairs(cp);
	free_client_pair(cp);
}

static void forward_request(struct r2p2_server_pair *sp)
{
	int iovcnt;

	iovcnt = prepare_to_app_iovec(&sp->request);
	rfn((long)sp, to_app_iovec, iovcnt);
}

static void r2p2_msg_add_payload(struct r2p2_msg *msg, generic_buffer gb)
{
	if (msg->tail_buffer) {
		chain_buffers(msg->tail_buffer, gb);
		msg->tail_buffer = gb;
	} else {
		assert(msg->head_buffer == NULL);
		assert(msg->tail_buffer == NULL);
		msg->head_buffer = gb;
		msg->tail_buffer = gb;
	}
}

int encrypt_block(char *dst, char *src, unsigned int len, ptls_t *tls){
	ptls_buffer_t sendbuf;
	ptls_buffer_init(&sendbuf, dst, 4000); //TODO: see what's the real len of dst
	int ret;
	if ((ret = ptls_send(tls, &sendbuf, src, len)) != 0)
        return ret;
	return ret;
}
//REFACTOR: use this only to split the messages.
void r2p2_prepare_msg(struct r2p2_msg *msg, struct iovec *iov, int iovcnt,
					  uint8_t req_type, uint8_t policy, uint16_t req_id, ptls_t *tls, ptls_buffer_t *handshake, int new_request)
{
	unsigned int iov_idx, bufferleft, copied, tocopy, buffer_cnt, total_payload,
		single_packet_msg, is_first, should_small_first;
	struct r2p2_header *r2p2h;
	generic_buffer gb, new_gb;
	char *target, *src;

	// Compute the total payload
	total_payload = 0;
	for (int i = 0; i < iovcnt; i++)
		total_payload += iov[i].iov_len;

	if (total_payload <= PAYLOAD_SIZE)
		single_packet_msg = 1;
	else
		single_packet_msg = 0;

	if (!single_packet_msg && (req_type == REQUEST_MSG))
		should_small_first = 1;
	else should_small_first = 0;

	iov_idx = 0;
	bufferleft = 0;
	copied = 0;
	gb = NULL;
	buffer_cnt = 0;
	is_first = 1;
	ptls_buffer_t tbuf;
	while (iov_idx < (unsigned int)iovcnt) {
		if (!bufferleft) {
			// Set the last buffer to full size
			if (gb) {
				if (is_first && should_small_first) {
					set_buffer_payload_size(gb, MIN_PAYLOAD_SIZE +
													sizeof(struct r2p2_header));
					is_first = 0;
				} else
					set_buffer_payload_size(gb, PAYLOAD_SIZE +
													sizeof(struct r2p2_header));
			}
			new_gb = get_buffer();
			assert(new_gb);
			r2p2_msg_add_payload(msg, new_gb);
			gb = new_gb;
			target = get_buffer_payload(gb);
			if (is_first && should_small_first)
				bufferleft = MIN_PAYLOAD_SIZE;
			else
				bufferleft = PAYLOAD_SIZE;
			// FIX the header
			r2p2h = (struct r2p2_header *)target;
			bzero(r2p2h, sizeof(struct r2p2_header));
			r2p2h->magic = MAGIC;
			r2p2h->rid = req_id;
			r2p2h->header_size = sizeof(struct r2p2_header);
			r2p2h->type_policy = (req_type << 4) | (0x0F & policy);
			r2p2h->p_order = buffer_cnt++;
			r2p2h->flags = 0;
			target += sizeof(struct r2p2_header);
			if (handshake == NULL && !ptls_handshake_is_complete(tls)) {
				//TODO:First we init the handshake here
				printf("bufferleft = %d\n", bufferleft);
				ptls_buffer_init(&tbuf, target, bufferleft);
				int ret;
				size_t accepted_data_by_server = 0;
				if (tls_ticket.base != NULL) {
					printf("We're using the ticket here\n");
					assert(tls_ticket.len != 0);
					ptls_handshake_properties_t hprops = {0};
					hprops.client.session_ticket = tls_ticket; //This is ok for the client, server should not go around here
					hprops.client.max_early_data_size = &accepted_data_by_server;//TODO: fix, won't work, or will it ?
					ret = ptls_handshake(tls, &tbuf, NULL, NULL, &hprops);
				} else {
					printf("Simple handshake\n");
					ret = ptls_handshake(tls, &tbuf, NULL, NULL, NULL);
				}
				printf("ret = %d, accepted_data = %d\n", ret, accepted_data_by_server);
				if (ret == PTLS_ERROR_IN_PROGRESS && accepted_data_by_server <= 0) {
					printf("Here2, isalloc %d\n", tbuf.is_allocated);
					//No ticket for example //If handshake is not done, fix flag and send immediately
					//req_type = TLS_CLIENT_HELLO_MSG
					
					r2p2h->type_policy = (TLS_CLIENT_HELLO_MSG << 4) | (0x0F & policy);
					r2p2h->flags |= F_FLAG;
					r2p2h->p_order = ~0;//Special nb of msgs.
					msg->req_id = req_id;
					printf("Handshake 1, rid = %u\n", r2p2h->rid);
					set_buffer_payload_size(gb, sizeof(struct r2p2_header) + tbuf.off);
				} else if (ret == PTLS_ERROR_IN_PROGRESS && accepted_data_by_server > 0) {
					//Fill first packet and return. Need way to remember how much data was accepted, we send early data only if we can fill everything
					printf("Here2, isalloc %d\n", tbuf.is_allocated);
					
					r2p2h->type_policy = (REQUEST_MSG << 4) | (0x0F & policy);
					r2p2h->flags |= F_FLAG;
					r2p2h->p_order = 1;//TODO: either 1 if there is everything or -1 if there is more
					r2p2h->flags |= L_FLAG;
					msg->req_id = req_id;
					printf("Handshake 2, rid = %u\n", r2p2h->rid);
					tocopy = min(bufferleft - ptls_get_record_overhead(tls), iov[0].iov_len);//Here we can copy max data we can, not only on the first iov
					printf("Send ret = %d\n", ptls_send(tls, &tbuf, iov[iov_idx].iov_base, tocopy));
					set_buffer_payload_size(gb, sizeof(struct r2p2_header) + tbuf.off);
				}
				return;
			}
			if (handshake != NULL && is_first) {
				//First memcpy the handshake
				memcpy(target, handshake->base, handshake->off);
				target += handshake->off;
				bufferleft -= handshake->off;
				assert(bufferleft >= 0);
			}
		}
		src = iov[iov_idx].iov_base;
		tocopy = min(bufferleft - ptls_get_record_overhead(tls), iov[iov_idx].iov_len - copied);
		//if (req_type == REQUEST_MSG || req_type == RESPONSE_MSG) {
		ptls_buffer_t sbuf;
		ptls_buffer_init(&sbuf, target, bufferleft);
		//int r = encrypt_block(target, &src[copied], tocopy, tls);
		printf("Encrypting here\n");
		printf("Send ret = %d\n", ptls_send(tls, &sbuf, src + copied, tocopy));
		printf("tocopy = %d, written = %d\n", tocopy, sbuf.off);
		//} else { //TODO: see for ACKS and stuff
		//	memcpy(target, &src[copied], tocopy);
		//}
		copied += tocopy;
		bufferleft -= sbuf.off;
		target += sbuf.off;
		if (copied == iov[iov_idx].iov_len) {
			iov_idx++;
			copied = 0;
		}
	}

	// Set the len of the last buffer
	set_buffer_payload_size(gb, PAYLOAD_SIZE + sizeof(struct r2p2_header) -
									bufferleft);

	// Fix the header of the first and last packet
	r2p2h = (struct r2p2_header *)get_buffer_payload(msg->head_buffer);
	if (new_request)
		r2p2h->flags |= F_FLAG;
	r2p2h->p_order = buffer_cnt;
	r2p2h = (struct r2p2_header *)get_buffer_payload(msg->tail_buffer);
	r2p2h->flags |= L_FLAG;

	msg->req_id = req_id;
}

static int should_keep_req(__attribute__((unused))struct r2p2_server_pair *sp)
{
	if (afc_fn)
		return afc_fn();
	else
		return 1;
}

static void send_drop_msg(struct r2p2_server_pair *sp)
{
	char drop_payload[] = "DROP";
	struct iovec ack;
	struct r2p2_msg drop_msg = {0};

	ack.iov_base = drop_payload;
	ack.iov_len = 4;
	r2p2_prepare_msg(&drop_msg, &ack, 1, DROP_MSG, FIXED_ROUTE,
			sp->request.req_id, sp->tls, NULL, 1);
	buf_list_send(drop_msg.head_buffer, &sp->request.sender, NULL);
#ifdef LINUX
	free_buffer(drop_msg.head_buffer);
#endif

}

static void handle_response(generic_buffer gb, int len,
							struct r2p2_header *r2p2h,
							struct r2p2_host_tuple *source,
#ifdef WITH_TIMESTAMPING
							struct r2p2_host_tuple *local_host,
							const struct timespec *last_rx_timestamp)
#else
							struct r2p2_host_tuple *local_host)
#endif
{
	struct r2p2_client_pair *cp;
	int iovcnt;
	generic_buffer rest_to_send;

	cp = find_in_pending_client_pairs(r2p2h->rid, local_host);
	if (!cp) {
		printf("No client pair found. RID = %d ORDER = %d\n", r2p2h->rid, r2p2h->p_order);
		free_buffer(gb);
		return;
	}

#ifdef WITH_TIMESTAMPING
	// Update ctx rx_timestamp if bigger than the current one.
	if (last_rx_timestamp != NULL && last_rx_timestamp->tv_sec != 0 &&
		is_smaller_than(&cp->ctx->rx_timestamp, last_rx_timestamp)) {
		cp->ctx->rx_timestamp = *last_rx_timestamp;
	}
#endif

	cp->reply.sender = *source;
	ptls_buffer_t handshake;
	switch(get_msg_type(r2p2h)) {
		case TLS_SERVER_HELLO_MSG: //IT means that there is no response in the packet ie that requests were rejected (in case of ticket use)
			assert(cp->state == R2P2_W_TLS_HANDSHAKE || cp->state == R2P2_W_RESPONSE);
			//TODO: Here we perform the end of the handshake, then resend
			
			printf("Handshake, pointer = %p\n", tls_ctx.save_ticket);
			perform_handshake(cp->tls, &handshake, get_buffer_payload(gb), len);
			printf("Received server hello\n");
#ifdef LINUX
			// Free the request already sent
			generic_buffer sb = cp->request.head_buffer;
			while (sb != NULL) {
				free_buffer(sb);
				sb = get_buffer_next(sb);
			}
#endif
			cp->request.head_buffer = NULL;
			cp->request.tail_buffer = NULL;
			r2p2_prepare_msg(&cp->request, cp->iov, cp->iovcnt, REQUEST_MSG,
					 cp->ctx->routing_policy,  cp->rid, cp->tls, &handshake, 0); //Save and replace the policy
			//TODO: if we copied iov, free it.
			rest_to_send = cp->request.head_buffer;
			buf_list_send(rest_to_send, &cp->reply.sender, cp->impl_data);
			break;
		case RESPONSE_MSG:
			assert(cp->state == R2P2_W_RESPONSE || cp->state == R2P2_W_TLS_HANDSHAKE);
			set_buffer_payload_size(gb, len);
			generic_buffer unencrypted = get_buffer();
			assert(unencrypted);
			//char *src = get_buffer_payload(gb) + sizeof(struct r2p2_header);
			char *target = get_buffer_payload(unencrypted);
			ptls_buffer_t *rbuf;
			rbuf = perform_handshake(cp->tls, &handshake, get_buffer_payload(gb), len);
			assert(rbuf->off != 0);
			memcpy(target, rbuf->base, rbuf->off);
			// size_t input_size = len - sizeof(struct r2p2_header);
			// size_t off = 0;
			// int ret = 0;
			// do {
			// 	size_t consumed = input_size - off;
			// 	ret = ptls_receive(cp->tls, &rbuf, src + off, &consumed);
			// 	off += consumed;
			// 	printf("ptls_receive ret %d, off %ld, input_size = %ld\n", ret, off, input_size);
			// } while (ret == 0 && off < input_size);
			printf("Received %ld bytes : %s\n", rbuf->off, rbuf->base);
			set_buffer_payload_size(unencrypted, (uint32_t)rbuf->off);
			free_buffer(gb);
			
			r2p2_msg_add_payload(&cp->reply, unencrypted);

			if (is_first(r2p2h)) {
				cp->reply_expected_packets = r2p2h->p_order;
				cp->reply_received_packets = 1;

			} else {
				if (r2p2h->p_order != cp->reply_received_packets++) {
					printf("OOF in response\n");
					cp->ctx->error_cb(cp->ctx->arg, -1);
					remove_from_pending_client_pairs(cp);
					free_client_pair(cp);
					return;
				}
			}

			// Is it full msg? Should I call the application?
			if (!is_last(r2p2h))
				return;

			if (cp->reply_received_packets != cp->reply_expected_packets) {
				printf("Wrong total size in response\n");
				cp->ctx->error_cb(cp->ctx->arg, -1);
				remove_from_pending_client_pairs(cp);
				free_client_pair(cp);
				return;

			}
			if (cp->timer)
				disarm_timer(cp->timer);
			iovcnt = prepare_to_app_iovec(&cp->reply);

#ifdef WITH_TIMESTAMPING
			// Extract tx timestamp if it wasn't there (due to packet order)
			if (cp->ctx->rx_timestamp.tv_sec != 0 &&
					cp->ctx->tx_timestamp.tv_sec == 0) {
				extract_tx_timestamp(((struct r2p2_socket *)cp->impl_data)->fd,
						&cp->ctx->tx_timestamp);

			}
#endif

			cp->ctx->success_cb((long)cp, cp->ctx->arg, to_app_iovec, iovcnt);
			break;
		case ACK_MSG:
			// Send the rest packets
			assert(cp->state == R2P2_W_ACK);
			if (len != (sizeof(struct r2p2_header) + 3))
				printf("ACK msg size is %d\n", len);
			assert(len == (sizeof(struct r2p2_header) + 3));
			free_buffer(gb);
#ifdef LINUX
			rest_to_send = get_buffer_next(cp->request.head_buffer);
#else
			rest_to_send = cp->request.head_buffer;
#endif
			buf_list_send(rest_to_send, &cp->reply.sender, cp->impl_data);
			cp->state = R2P2_W_RESPONSE;
			break;
		case DROP_MSG:
			handle_drop_msg(cp);
			free_buffer(gb);
			break;
		default:
			fprintf(stderr, "Unknown msg type %d for response\n",
					get_msg_type(r2p2h));
			assert(0);
	}
}

static void handle_request(generic_buffer gb, int len,
						   struct r2p2_header *r2p2h,
						   struct r2p2_host_tuple *source)
{
	struct r2p2_server_pair *sp;
	uint16_t req_id;
	char ack_payload[] = "ACK";
	struct iovec ack;
	struct r2p2_msg ack_msg = {0};

	req_id = r2p2h->rid;
	ptls_buffer_t *rbuf = NULL;
	if (is_first(r2p2h)) {
		/*
		 * FIXME
		 * Consider the case that an old request with the same id and
		 * src ip port is already there
		 * remove before starting the new one
		 */
		sp = alloc_server_pair();
		assert(sp);
		sp->request.sender = *source;
		sp->request.req_id = req_id;
		sp->request_expected_packets = r2p2h->p_order;
		sp->request_received_packets = 1;
		sp->tls = ptls_new(&tls_ctx, 1); //TODO: Add the handshake msg - check for 0RTT and try to decrypt
		sp->handshake = malloc(sizeof(ptls_buffer_t));

		if (!should_keep_req(sp)) {
			set_buffer_payload_size(gb, len);
			r2p2_msg_add_payload(&sp->request, gb);
			send_drop_msg(sp);
			free_server_pair(sp);
			return;
		}

		rbuf = perform_handshake(sp->tls, sp->handshake, get_buffer_payload(gb), len);

		if (is_handshake(r2p2h)) {
			// add to pending request
			add_to_pending_server_pairs(sp);
			printf("Sending server hello\n");
			//TODO: wrap this up in a proper function
			generic_buffer tls_server_hello = get_buffer();
			assert(tls_server_hello);
			r2p2_msg_add_payload(&ack_msg, tls_server_hello);
			char *target = get_buffer_payload(tls_server_hello);
			//TODO: setup the header
			struct r2p2_header *r2p2h = (struct r2p2_header *)target;
			bzero(r2p2h, sizeof(struct r2p2_header));
			r2p2h->magic = MAGIC;
			r2p2h->rid = req_id;
			r2p2h->header_size = sizeof(struct r2p2_header);
			r2p2h->type_policy = (TLS_SERVER_HELLO_MSG << 4) | (0x0F & FIXED_ROUTE);
			r2p2h->p_order = 1;
			r2p2h->flags = 0;
			target = (char *)(((struct r2p2_header *) target) + 1);
			memcpy(target, sp->handshake->base, sp->handshake->off);
			set_buffer_payload_size(tls_server_hello, sp->handshake->off + sizeof(struct r2p2_header));
			ptls_buffer_dispose(sp->handshake);
			buf_list_send(ack_msg.head_buffer, source, NULL);
#ifdef LINUX
			free_buffer(ack_msg.head_buffer);
#endif
			return;
		}

		if (!is_last(r2p2h)) {
			// add to pending request
			add_to_pending_server_pairs(sp);

			// send ACK
			ack.iov_base = ack_payload;
			ack.iov_len = 3;
			r2p2_prepare_msg(&ack_msg, &ack, 1, ACK_MSG, FIXED_ROUTE, req_id, sp->tls, sp->handshake, 1);
			ptls_buffer_dispose(sp->handshake);
			buf_list_send(ack_msg.head_buffer, source, NULL);
#ifdef LINUX
			free_buffer(ack_msg.head_buffer);
#endif
		}
	} else {
		// find in pending msgs
		sp = find_in_pending_server_pairs(req_id, source);
		assert(sp);
		rbuf = perform_handshake(sp->tls, sp->handshake, get_buffer_payload(gb), len);
		if (r2p2h->p_order != sp->request_received_packets++) {
			printf("OOF in request\n");
			remove_from_pending_server_pairs(sp);
			free_server_pair(sp);
			free_buffer(gb);
			return;
		}
	}
	set_buffer_payload_size(gb, len);
	generic_buffer unencrypted = get_buffer();
	assert(unencrypted);
	//char *src = get_buffer_payload(gb) + sizeof(struct r2p2_header);
	char *target = get_buffer_payload(unencrypted);
	if (rbuf != NULL && rbuf->off != 0) {
		memcpy(target, rbuf->base, rbuf->off);
		printf("Received %ld bytes : %s\n", rbuf->off, rbuf->base);
		set_buffer_payload_size(unencrypted, (uint32_t)rbuf->off);
		r2p2_msg_add_payload(&sp->request, unencrypted);
		free(rbuf);
	}
	// ptls_buffer_t rbuf;
	// ptls_buffer_init(&rbuf, target, len);
	// size_t input_size = len - sizeof(struct r2p2_header);
	// size_t off = 0;
	// int ret = 0;
	// do {
    //     size_t consumed = input_size - off;
    //     ret = ptls_receive(sp->tls, &rbuf, src + off, &consumed);
    //     off += consumed;
	// 	printf("ptls_receive ret %d, off %ld, input_size = %ld\n", ret, off, input_size);
    // } while (ret == 0 && off < input_size);
	
	free_buffer(gb);
	
	

	if (!is_last(r2p2h))
		return;

	// if (sp->request_received_packets != sp->request_expected_packets) {
	// 	printf("Wrong total size in request\n");
	// 	remove_from_pending_server_pairs(sp);
	// 	free_server_pair(sp);
	// 	return;
	// }
	assert(rfn);
	forward_request(sp);
}

void handle_incoming_pck(generic_buffer gb, int len,
						 struct r2p2_host_tuple *source,
#ifdef WITH_TIMESTAMPING
						 struct r2p2_host_tuple *local_host,
						 const struct timespec *last_rx_timestamp)
#else
						 struct r2p2_host_tuple *local_host)
#endif
{
	struct r2p2_header *r2p2h;
	char *buf;

	if ((unsigned)len < sizeof(struct r2p2_header))
		printf("I received %d\n", len);
	assert((unsigned)len >= sizeof(struct r2p2_header));
	buf = get_buffer_payload(gb);
	r2p2h = (struct r2p2_header *)buf;

	if (is_response(r2p2h))
#ifdef WITH_TIMESTAMPING
		handle_response(gb, len, r2p2h, source, local_host, last_rx_timestamp);
#else
		handle_response(gb, len, r2p2h, source, local_host);
#endif
	else
		handle_request(gb, len, r2p2h, source);
}

int r2p2_backend_init_per_core(void)
{
	time_t t;

	client_pairs = create_mempool(POOL_SIZE, sizeof(struct r2p2_client_pair));
	assert(client_pairs);
	server_pairs = create_mempool(POOL_SIZE, sizeof(struct r2p2_server_pair));
	assert(server_pairs);

	srand((unsigned)time(&t));

	return 0;
}

void timer_triggered(struct r2p2_client_pair *cp)
{
	struct fixed_obj *fo = get_object_meta(cp);
	if (!fo->taken)
		return;

	assert(cp->ctx->timeout_cb);
	cp->ctx->timeout_cb(cp->ctx->arg);
	//printf("Timer triggered: received packets %d expected %d\n",
	//		cp->reply_received_packets, cp->reply_expected_packets);

	remove_from_pending_client_pairs(cp);
	free_client_pair(cp);
}

/*
 * API
 */
void r2p2_send_response(long handle, struct iovec *iov, int iovcnt)
{
	struct r2p2_server_pair *sp;

	sp = (struct r2p2_server_pair *)handle;
	r2p2_prepare_msg(&sp->reply, iov, iovcnt, RESPONSE_MSG, FIXED_ROUTE,
					 sp->request.req_id, sp->tls, sp->handshake, 1);
	buf_list_send(sp->reply.head_buffer, &sp->request.sender, NULL);

	// Notify router
	router_notify();

	remove_from_pending_server_pairs(sp);
	free_server_pair(sp);
}

void r2p2_send_req(struct iovec *iov, int iovcnt, struct r2p2_ctx *ctx, struct iovec server_name)
{
	generic_buffer second_buffer;
	struct r2p2_client_pair *cp;
	uint16_t rid;

	cp = alloc_client_pair();
	assert(cp);
	cp->ctx = ctx;
	cp->tls = ptls_new(&tls_ctx, 0);
	ptls_set_server_name(cp->tls, server_name.iov_base, server_name.iov_len);

	if (prepare_to_send(cp)) {
		free_client_pair(cp);
		return;
	}

	rid = rand();
	printf("Test, rid = %u\n", rid);

	cp->iov = iov; //TODO: do we copy it or not ?
	cp->iovcnt = iovcnt;
	cp->rid = rid;
	r2p2_prepare_msg(&cp->request, iov, iovcnt, REQUEST_MSG,
					 ctx->routing_policy, rid, cp->tls, NULL, 1); //Here we need to store the iov in case handshake is not done directly
	cp->state = cp->request.head_buffer == cp->request.tail_buffer
					? R2P2_W_RESPONSE
					: R2P2_W_ACK;
	printf("Test2, rid = %u\n", cp->request.req_id);

	add_to_pending_client_pairs(cp);

	// Send only the first packet
	second_buffer = get_buffer_next(cp->request.head_buffer);
	chain_buffers(cp->request.head_buffer, NULL);
	buf_list_send(cp->request.head_buffer, ctx->destination, cp->impl_data);
#ifdef LINUX
	chain_buffers(cp->request.head_buffer, second_buffer);
#else
	cp->request.head_buffer = second_buffer;
#endif
}

void r2p2_recv_resp_done(long handle)
{
	struct r2p2_client_pair *cp = (struct r2p2_client_pair *)handle;

	remove_from_pending_client_pairs(cp);
	free_client_pair(cp);
}

void r2p2_set_recv_cb(recv_fn fn)
{
	rfn = fn;
}

void r2p2_set_app_flow_control_fn(app_flow_control fn)
{
	afc_fn = fn;
}
