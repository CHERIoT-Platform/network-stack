#include "../../third_party/BearSSL/inc/bearssl.h"
#include <NetAPI.h>
#include <debug.hh>
#include <locks.hh>
#include <platform-entropy.hh>
#include <tls.h>
#include <token.h>

using Debug = ConditionalDebug<false, "TLS">;

namespace
{
	/**
	 * The object for a sealed TLS connection.
	 */
	struct TLSContext
	{
		/// The underlying TCP socket.
		SObj socket;
		/**
		 * The allocator used to allocate memory for this object.  Needed for
		 * freeing it and for allocating internal buffers.
		 */
		SObj allocator;
		/// The BearSSL client context.
		br_ssl_client_context *clientContext;
		/// The BearSSL X.509 context.
		br_x509_minimal_context *x509Context;
		/// The input buffer for the TLS engine.
		unsigned char *iobuf_in;
		/// The output buffer for the TLS engine.
		unsigned char *iobuf_out;
		/**
		 * The received data buffer.  If we have received data from the TCP
		 * socket but not yet processed all of it, it will be stored here.
		 * This is a buffer allocated by `allocator` and will be freed as soon
		 * as it is either consumed or the connection is torn down.
		 */
		uint8_t                  *received       = nullptr;
		size_t                    receivedLength = 0;
		size_t                    receivedOffset = 0;
		FlagLockPriorityInherited lock;
		TLSContext(SObj                     socket,
		           SObj                     allocator,
		           br_ssl_client_context   *clientContext,
		           br_x509_minimal_context *x509Context,
		           unsigned char           *iobuf_in,
		           unsigned char           *iobuf_out)
		  : socket{socket},
		    allocator{allocator},
		    clientContext{clientContext},
		    x509Context{x509Context},
		    iobuf_in{iobuf_in},
		    iobuf_out{iobuf_out}
		{
		}
		void destroy(SObj allocator)
		{
			Timeout t{UnlimitedTimeout};
			network_socket_close(&t, allocator, socket);
			heap_free(allocator, iobuf_in);
			heap_free(allocator, iobuf_out);
			heap_free(allocator, received);
			heap_free(allocator, clientContext);
			heap_free(allocator, x509Context);
		}
	};

	__always_inline SKey tls_key()

	{
		return STATIC_SEALING_TYPE(TLSConnection);
	}

	auto rand()
	{
		static EntropySource source;
		return source();
	}

	ssize_t
	with_sealed_tls_context(Timeout *timeout, SObj sealed, auto callback)
	{
		Sealed<TLSContext> sealedContext{sealed};
		auto              *unsealed = token_unseal(tls_key(), sealedContext);
		if (unsealed == nullptr)
		{
			Debug::log("Failed to unseal TLS context {}", sealed);
			return -EINVAL;
		}
		if (LockGuard g{unsealed->lock, timeout})
		{
			auto state =
			  br_ssl_engine_current_state(&unsealed->clientContext->eng);
			Debug::log("TLS state: {}", state);
			if ((state & BR_SSL_CLOSED) == BR_SSL_CLOSED)
			{
				Debug::log(
				  "Connection closed, last error: {}",
				  br_ssl_engine_last_error(&unsealed->clientContext->eng));
			}
			return callback(unsealed);
		}
		Debug::log("Failed to acquire lock on TLS context");
		return -ETIMEDOUT;
	}

	/// Minimal BearSSL context initialisation.
	void br_ssl_client_init(br_ssl_client_context      *cc,
	                        br_x509_minimal_context    *xc,
	                        const br_x509_trust_anchor *trust_anchors,
	                        size_t                      trust_anchors_num)
	{
		/*
		 * A small set of cypher suites that should be the intersection of the
		 * ones supported by most modern servers.
		 */
		static const uint16_t suites[] = {
		  BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		  BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		  BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		  BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		};

		/*
		 * Reset client context and set supported versions to TLS-1.2.
		 */
		br_ssl_client_zero(cc);
		br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);

		/*
		 * X.509 engine uses SHA-256 to hash certificate DN (for
		 * comparisons).
		 */
		br_x509_minimal_init(
		  xc, &br_sha256_vtable, trust_anchors, trust_anchors_num);

		/*
		 * Set suites and asymmetric crypto implementations. We use the
		 * "i31" code for RSA (it is somewhat faster than the "i32"
		 * implementation).
		 * TODO: change that when better implementations are made available.
		 */
		br_ssl_engine_set_suites(
		  &cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
		br_ssl_client_set_default_rsapub(cc);
		br_ssl_engine_set_default_rsavrfy(&cc->eng);
		br_ssl_engine_set_default_ecdsa(&cc->eng);
		br_x509_minimal_set_rsa(xc, br_ssl_engine_get_rsavrfy(&cc->eng));
		br_x509_minimal_set_ecdsa(xc,
		                          br_ssl_engine_get_ec(&cc->eng),
		                          br_ssl_engine_get_ecdsa(&cc->eng));

		/*
		 * Set supported hash functions, for the SSL engine and for the
		 * X.509 engine.
		 */
		br_ssl_engine_set_hash(&cc->eng, br_sha256_ID, &br_sha256_vtable);
		Debug::log("Setting vtable for br_sha256_ID: {}", &br_sha256_vtable);
		for (int i = 0; i < 6; i++)
		{
			Debug::log("hash engines[{}] = {}", i, cc->eng.mhash.impl[i]);
		}

		br_x509_minimal_set_hash(xc, br_sha256_ID, &br_sha256_vtable);

		/*
		 * Link the X.509 engine in the SSL engine.
		 */
		br_ssl_engine_set_x509(&cc->eng, &xc->vtable);

		/*
		 * Set the PRF implementations.
		 */
		br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);

		/*
		 * Symmetric encryption. We use the "default" implementations
		 * (fastest among constant-time implementations).
		 */
		br_ssl_engine_set_default_aes_cbc(&cc->eng);
		br_ssl_engine_set_default_aes_ccm(&cc->eng);
		br_ssl_engine_set_default_aes_gcm(&cc->eng);
	}

} // namespace

SObj tls_connection_create(Timeout                    *t,
                           SObj                        allocator,
                           SObj                        connectionCapability,
                           const br_x509_trust_anchor *trustAnchors,
                           size_t                      trustAnchorsCount)
{
	const char *hostname = network_host_get(connectionCapability);
	if (hostname == nullptr)
	{
		Debug::log("Failed to get hostname");
		return nullptr;
	}
	auto socketDeleter = [&](SObj s) {
		Timeout unlimited{UnlimitedTimeout};
		network_socket_close(&unlimited, allocator, s);
		t->elapse(unlimited.elapsed);
	};
	std::unique_ptr<struct SObjStruct, decltype(socketDeleter)> socket{
	  network_socket_connect_tcp(t, allocator, connectionCapability),
	  socketDeleter};
	if (socket == nullptr)
	{
		Debug::log("Failed to connect to host");
		return nullptr;
	}
	auto deleter = [=](void *ptr) { heap_free(allocator, ptr); };
	std::unique_ptr<br_ssl_client_context, decltype(deleter)> clientContext{
	  static_cast<br_ssl_client_context *>(
	    heap_allocate(t, allocator, sizeof(br_ssl_client_context))),
	  deleter};
	if (clientContext == nullptr)
	{
		Debug::log("Failed to allocate client context");
		return nullptr;
	}
	std::unique_ptr<br_x509_minimal_context, decltype(deleter)> x509Context{
	  static_cast<br_x509_minimal_context *>(
	    heap_allocate(t, allocator, sizeof(br_x509_minimal_context))),
	  deleter};
	auto *engine = &clientContext->eng;
	if (x509Context == nullptr)
	{
		Debug::log("Failed to allocate X509 context");
		return nullptr;
	}
	Debug::log("Initialising TLS context");
	br_ssl_client_init(
	  clientContext.get(), x509Context.get(), trustAnchors, trustAnchorsCount);

	static constexpr size_t                           MinimumBufferSize = 837;
	std::unique_ptr<unsigned char, decltype(deleter)> iobuf_in{
	  static_cast<unsigned char *>(
	    heap_allocate(t, allocator, MinimumBufferSize)),
	  deleter};
	std::unique_ptr<unsigned char, decltype(deleter)> iobuf_out{
	  static_cast<unsigned char *>(
	    heap_allocate(t, allocator, MinimumBufferSize)),
	  deleter};
	if (iobuf_in == nullptr || iobuf_out == nullptr)
	{
		Debug::log("Failed to allocate buffers");
		return nullptr;
	}

	Debug::log("Setting up TLS buffers");
	br_ssl_engine_set_buffers_bidi(&clientContext->eng,
	                               iobuf_in.get(),
	                               MinimumBufferSize,
	                               iobuf_out.get(),
	                               MinimumBufferSize);

	auto entropy = rand();
	br_ssl_engine_inject_entropy(
	  &clientContext->eng, &entropy, sizeof(entropy));

	void *unsealed;
	SObj  sealed = token_sealed_unsealed_alloc(
	   t, allocator, tls_key(), sizeof(TLSContext), &unsealed);
	Debug::log("Created tls context sealed with {}", tls_key());
	if (sealed == nullptr)
	{
		Debug::log("Failed to allocate TLS context");
		return nullptr;
	}
	TLSContext *context = new (unsealed) TLSContext{socket.release(),
	                                                allocator,
	                                                clientContext.release(),
	                                                x509Context.release(),
	                                                iobuf_in.release(),
	                                                iobuf_out.release()};

	// Try to connect to the server.
	Debug::log("Resetting TLS connection for {}", hostname);
	br_ssl_client_reset(context->clientContext, hostname, 0);

	// FIXME: Inject some entropy

	auto     state        = br_ssl_engine_current_state(engine);
	uint8_t *receivedData = nullptr;
	uint8_t *toProcess    = nullptr;
	size_t   remaining    = 0;
	// Pump the engine until it's ready for data to be sent or until the
	// connection is closed.
	while ((state & (BR_SSL_SENDAPP)) == 0)
	{
		Debug::log("TLS state: {}", state);
		Debug::log("Last error: {}", br_ssl_engine_last_error(engine));
		// FIXME: This will do the wrong thing if we time out during TLS
		// negotiation.
		if ((state & BR_SSL_CLOSED) == BR_SSL_CLOSED)
		{
			Debug::log("Connection closed, last error: {}",
			           br_ssl_engine_last_error(engine));
			context->~TLSContext();
			token_obj_destroy(allocator, tls_key(), sealed);
			heap_free(allocator, receivedData);
			return nullptr;
		}
		// If we need to send records, send them first.
		if ((state & BR_SSL_SENDREC) == BR_SSL_SENDREC)
		{
			size_t readyLength;
			auto *readyBuffer = br_ssl_engine_sendrec_buf(engine, &readyLength);
			Debug::log("Sending {} bytes of records", readyLength);
			auto sent =
			  network_socket_send(t, context->socket, readyBuffer, readyLength);
			Debug::log("Send returned {}", sent);
			if (sent > 0)
			{
				br_ssl_engine_sendrec_ack(engine, sent);
			}
			else
			{
				Debug::log("Sending records failed: {}", sent);
			}
			// TODO: Handle sending errors.
		}
		else if ((state & BR_SSL_RECVREC) == BR_SSL_RECVREC)
		{
			if (remaining == 0)
			{
				Debug::log("Receiving records");
				auto [received, buffer] =
				  network_socket_receive(t, allocator, context->socket);
				if (received > 0)
				{
					receivedData = buffer;
					toProcess    = buffer;
					remaining    = received;
					Debug::log("Received {} bytes of records", remaining);
				}
				else if (received == 0 || received == -ENOTCONN)
				{
					// FIXME: Shut down gracefully
					Debug::log("Connection closed, shutting down");
				}
				else
				{
					Debug::log("Receive failed: {}", received);
					continue;
				}
				// FIXME: Other errors
			}
			Debug::log("{} bytes of records available", remaining);
			size_t         length;
			unsigned char *inputBuffer =
			  br_ssl_engine_recvrec_buf(engine, &length);
			size_t nextBlockSize = std::min<size_t>(remaining, length);
			Debug::log("Pushing {} bytes into TLS engine (space for {})",
			           nextBlockSize,
			           length);
			// FIXME: Handle the case where we can't handle as much as
			// has been received.  We should buffer the remainder of the
			// received data internally.
			memcpy(inputBuffer, toProcess, nextBlockSize);
			br_ssl_engine_recvrec_ack(&context->clientContext->eng,
			                          nextBlockSize);
			Debug::log("Finished TLS processing data");
			remaining -= nextBlockSize;
			toProcess += nextBlockSize;
			if (remaining == 0)
			{
				Debug::log("Finished processing incoming buffer, freeing");
				heap_free(allocator, receivedData);
			}
			// Next loop iteration, we'll try pulling the data out of
			// the TLS engine.
		}
		state = br_ssl_engine_current_state(engine);
	}
	if (receivedData != nullptr)
	{
		heap_free(allocator, receivedData);
	}
	return sealed;
}

ssize_t tls_connection_send(Timeout *t,
                            SObj     sealedConnection,
                            void    *buffer,
                            size_t   length,
                            int      flags)
{
	return with_sealed_tls_context(
	  t, sealedConnection, [&](TLSContext *connection) {
		  auto  *engine    = &connection->clientContext->eng;
		  bool   forceLoop = false;
		  size_t totalSent = 0;
		  while ((length > 0) || forceLoop)
		  {
			  forceLoop  = false;
			  auto state = br_ssl_engine_current_state(engine);
			  // If there's data ready to send over the network, prioritise
			  // sending it
			  if ((state & BR_SSL_SENDREC) == BR_SSL_SENDREC)
			  {
				  size_t readyLength;
				  auto  *readyBuffer =
				    br_ssl_engine_sendrec_buf(engine, &readyLength);
				  Debug::log("TLS engine has {} bytes ready to send, passing "
				             "to TCP layer",
				             readyLength);
				  auto sent = network_socket_send(
				    t, connection->socket, readyBuffer, readyLength);
				  Debug::log("TCP sent {} bytes", sent);
				  if (sent > 0)
				  {
					  br_ssl_engine_sendrec_ack(engine, sent);
					  // If we've sent less than the engine is ready to send,
					  // try again.
					  if (sent < readyLength)
					  {
						  Debug::log("TCP sent {} bytes, TLS engine can still "
						             "send {} bytes",
						             sent,
						             readyLength - sent);
						  forceLoop = true;
					  }
				  }
				  // TODO: Handle sending errors.
			  }
			  else if (((state & BR_SSL_SENDAPP) == BR_SSL_SENDAPP) &&
			           (length > 0))
			  {
				  size_t         readyLength;
				  unsigned char *readyBuffer =
				    br_ssl_engine_sendapp_buf(engine, &readyLength);
				  size_t toSend = std::min(length, readyLength);
				  Debug::log("TLS engine can accept {} bytes, sending {} bytes",
				             readyLength,
				             toSend);
				  memcpy(readyBuffer, buffer, toSend);
				  br_ssl_engine_sendapp_ack(engine, toSend);
				  length -= toSend;
				  buffer = static_cast<uint8_t *>(buffer) + toSend;
				  totalSent += toSend;
				  if ((flags & TLSSendNoFlush) == 0)
				  {
					  br_ssl_engine_flush(engine, 0);
				  }
				  // Make sure that we try to send the data we just put in the
				  // buffer.
				  forceLoop = true;
			  }
			  else
			  {
				  if (t->may_block())
				  {
					  Timeout shortSleep{1};
					  thread_sleep(&shortSleep);
					  t->elapse(shortSleep.elapsed);
				  }
				  if (!t->may_block())
				  {
					  break;
				  }
			  }
		  }
		  return totalSent > 0 ? totalSent : -ETIMEDOUT;
	  });
}

NetworkReceiveResult tls_connection_receive(Timeout *t, SObj sealedConnection)
{
	uint8_t *outBuffer = nullptr;
	ssize_t  result =
	  with_sealed_tls_context(t, sealedConnection, [&](TLSContext *connection) {
		  auto *engine = &connection->clientContext->eng;
		  while (true)
		  {
			  auto state = br_ssl_engine_current_state(engine);
			  if ((state & BR_SSL_RECVAPP) == BR_SSL_RECVAPP)
			  {
				  size_t         length;
				  unsigned char *inputBuffer =
				    br_ssl_engine_recvapp_buf(engine, &length);
				  Debug::log("TLS engine has {} bytes ready to receive, "
				             "returning to caller",
				             length);
				  auto *receivedBuffer = static_cast<unsigned char *>(
				    heap_allocate(t, connection->allocator, length));
				  if (receivedBuffer == nullptr)
				  {
					  Debug::log("Failed to allocate receive buffer");
					  return -ENOMEM;
				  }
				  memcpy(receivedBuffer, inputBuffer, length);
				  br_ssl_engine_recvapp_ack(engine, length);
				  Debug::log(
				    "Received {} bytes into {}", length, receivedBuffer);
				  outBuffer = receivedBuffer;
				  return ssize_t(length);
			  }
			  else if ((state & BR_SSL_RECVREC) == BR_SSL_RECVREC)
			  {
				  // Pull some data out of the network stack.
				  if (connection->received == nullptr)
				  {
					  auto [received, buffer] = network_socket_receive(
					    t, connection->allocator, connection->socket);
					  if (received > 0)
					  {
						  connection->received       = buffer;
						  connection->receivedLength = received;
						  connection->receivedOffset = 0;
					  }
					  else if (received == 0 || received == -ENOTCONN)
					  {
						  // FIXME: Shut down gracefully
						  Debug::log("Connection closed, shutting down");
						  return 0;
					  }
					  else if (received == -ETIMEDOUT)
					  {
						  return -ETIMEDOUT;
					  }
				  }
				  size_t pendingData =
				    connection->receivedLength - connection->receivedOffset;
				  size_t         length;
				  unsigned char *inputBuffer =
				    br_ssl_engine_recvrec_buf(engine, &length);
				  Debug::log("TCP provided {} bytes, TLS engine can process {}",
				             pendingData,
				             length);
				  size_t nextBlockSize = std::min<size_t>(pendingData, length);
				  // FIXME: Handle the case where we can't handle as much as
				  // has been received.  We should buffer the remainder of
				  // the received data internally.
				  memcpy(inputBuffer,
				         connection->received + connection->receivedOffset,
				         nextBlockSize);
				  br_ssl_engine_recvrec_ack(&connection->clientContext->eng,
				                            nextBlockSize);
				  connection->receivedOffset += nextBlockSize;
				  if (connection->receivedOffset == connection->receivedLength)
				  {
					  Debug::log(
					    "Finished processing incoming buffer, freeing");
					  heap_free(connection->allocator, connection->received);
					  connection->received       = nullptr;
					  connection->receivedLength = 0;
					  connection->receivedOffset = 0;
				  }
				  // Next loop iteration, we'll try pulling the data out of
				  // the TLS engine.
			  }
			  else
			  {
				  if (!t->may_block())
				  {
					  return -ETIMEDOUT;
				  }
			  }
		  }
	  });
	return {result, outBuffer};
}

int tls_connection_close(Timeout *t, SObj sealed)
{
	Sealed<TLSContext> sealedContext{sealed};
	auto              *tls = token_unseal(tls_key(), sealedContext);
	if (tls == nullptr)
	{
		Debug::log("Failed to unseal TLS context {}", sealed);
		return -EINVAL;
	}
	if (!tls->lock.try_lock(t))
	{
		Debug::log("Failed to acquire lock on TLS context during close");
		return -ETIMEDOUT;
	}
	auto *engine = &tls->clientContext->eng;
	br_ssl_engine_close(engine);
	auto    state = br_ssl_engine_current_state(&tls->clientContext->eng);
	Timeout unlimited{UnlimitedTimeout};
	do
	{
		// Silently discard any pending app data
		if ((state & BR_SSL_RECVAPP) == BR_SSL_RECVAPP)
		{
			size_t length;
			if (br_ssl_engine_recvapp_buf(engine, &length) != nullptr)
			{
				br_ssl_engine_recvapp_ack(engine, length);
			}
		}
		else if ((state & BR_SSL_SENDREC) == BR_SSL_SENDREC)
		{
			size_t readyLength;
			auto *readyBuffer = br_ssl_engine_sendrec_buf(engine, &readyLength);
			Debug::log("Sending {} bytes of records", readyLength);
			auto sent = network_socket_send(
			  &unlimited, tls->socket, readyBuffer, readyLength);
			Debug::log("Send returned {}", sent);
			if (sent > 0)
			{
				br_ssl_engine_sendrec_ack(engine, sent);
			}
			else
			{
				// Give up and don't gracefully terminate if we failed to
				// send.
				Debug::log("Sending records failed: {}", sent);
				break;
			}
		}
		else if ((state & BR_SSL_RECVREC) == BR_SSL_RECVREC)
		{
			if (tls->received == nullptr)
			{
				auto [received, buffer] = network_socket_receive(
				  &unlimited, tls->allocator, tls->socket);
				if (received > 0)
				{
					tls->received       = buffer;
					tls->receivedLength = received;
					tls->receivedOffset = 0;
				}
				else
				{
					Debug::log("Failed to receive data: {}", received);
					break;
				}
			}
			size_t pendingData = tls->receivedLength - tls->receivedOffset;
			size_t length;
			unsigned char *inputBuffer =
			  br_ssl_engine_recvrec_buf(engine, &length);
			size_t nextBlockSize = std::min<size_t>(pendingData, length);
			memcpy(
			  inputBuffer, tls->received + tls->receivedOffset, nextBlockSize);
			br_ssl_engine_recvrec_ack(&tls->clientContext->eng, nextBlockSize);
		}
		state = br_ssl_engine_current_state(&tls->clientContext->eng);
	} while ((state & BR_SSL_CLOSED) != BR_SSL_CLOSED);
	auto allocator = tls->allocator;
	tls->~TLSContext();
	token_obj_destroy(allocator, tls_key(), sealed);
	return 0;
}
