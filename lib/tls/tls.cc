// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include "../../third_party/BearSSL/inc/bearssl.h"
#include <NetAPI.h>
#include <debug.hh>
#include <function_wrapper.hh>
#include <locks.hh>
#include <platform-entropy.hh>
#include <timeout.h>
#include <tls.h>
#include <token.h>

using Debug = ConditionalDebug<false, "TLS">;
using namespace CHERI;

namespace
{
	constexpr bool EnableRSA =
#ifdef CHERIOT_TLS_ENABLE_RSA
	  true
#else
	  false
#endif
	  ;
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
		unsigned char *iobufIn;
		/// The output buffer for the TLS engine.
		unsigned char            *iobufOut;
		FlagLockPriorityInherited lock;
		TLSContext(SObj                     socket,
		           SObj                     allocator,
		           br_ssl_client_context   *clientContext,
		           br_x509_minimal_context *x509Context,
		           unsigned char           *iobufIn,
		           unsigned char           *iobufOut)
		  : socket{socket},
		    allocator{allocator},
		    clientContext{clientContext},
		    x509Context{x509Context},
		    iobufIn{iobufIn},
		    iobufOut{iobufOut}
		{
		}
		~TLSContext()
		{
			Timeout t{UnlimitedTimeout};
			network_socket_close(&t, allocator, socket);
			heap_free(allocator, iobufIn);
			heap_free(allocator, iobufOut);
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
	                        const br_x509_trust_anchor *trustAnchors,
	                        size_t                      trustAnchorsCount)
	{
		/*
		 * A small set of cypher suites that should be the intersection of the
		 * ones supported by most modern servers.
		 */
		static const uint16_t Suites[] = {
		  BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		  BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
#ifdef CHERIOT_TLS_ENABLE_RSA
		  BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		  BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
#endif
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
		  xc, &br_sha256_vtable, trustAnchors, trustAnchorsCount);

		/*
		 * Set suites and asymmetric crypto implementations. We use the
		 * "i31" code for RSA (it is somewhat faster than the "i32"
		 * implementation).
		 * TODO: change that when better implementations are made available.
		 */
		br_ssl_engine_set_suites(
		  &cc->eng, Suites, (sizeof Suites) / (sizeof Suites[0]));
		br_ssl_engine_set_default_ecdsa(&cc->eng);
		if constexpr (EnableRSA)
		{
			br_ssl_client_set_default_rsapub(cc);
			br_ssl_engine_set_default_rsavrfy(&cc->eng);
			br_x509_minimal_set_rsa(xc, br_ssl_engine_get_rsavrfy(&cc->eng));
		}
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
		br_ssl_engine_set_default_aes_gcm(&cc->eng);
	}

	int receive_records(Timeout *t, TLSContext *connection)
	{
		auto      *engine = &connection->clientContext->eng;
		size_t     length;
		Capability inputBuffer = br_ssl_engine_recvrec_buf(engine, &length);
		inputBuffer.bounds().set_inexact_at_most(length);
		length = inputBuffer.length();

		// Remove local so that the network stack cannot capture
		// this, remove load so that we cannot leak state.
		inputBuffer.permissions() &= Permission::Store;
		Debug::log("Receiving {} bytes into {}", length, inputBuffer);
		// Pull some data out of the network stack.
		int received = network_socket_receive_preallocated(
		  t, connection->socket, inputBuffer, length);
		Debug::log("Network stack returned {}", received);
		// Any failure here is treated the same way: give up.
		// Note: the BearSSL documentation says 'The len value MUST NOT
		// be 0', so we treat it as an error too. Still, assuming
		// `network_socket_receive_preallocated` is correctly
		// implemented, 0 should never be returned.
		if (received <= 0)
		{
			return received;
		}
		br_ssl_engine_recvrec_ack(engine, received);
		return received;
	}

	/**
	 * Helper to send records from the TLS engine to the network stack.
	 *
	 * Returns the response from the network stack (zero for a closed
	 * connection, negative for errors, positive for the number of bytes sent)
	 * and a boolean indicating whether there are more records to send that
	 * were not transmitted in this call.
	 */
	std::pair<int, bool> send_records(Timeout *t, TLSContext *connection)
	{
		auto      *engine = &connection->clientContext->eng;
		size_t     readyLength;
		Capability readyBuffer =
		  br_ssl_engine_sendrec_buf(engine, &readyLength);
		readyBuffer.bounds().set_inexact_at_most(readyLength);
		readyLength = readyBuffer.length();

		// Remove local so that the network stack cannot capture
		// this, remove store so that we cannot leak state.
		readyBuffer.permissions() &= Permission::Load;
		Debug::log("Sending {} bytes of records", readyLength);
		auto sent =
		  network_socket_send(t, connection->socket, readyBuffer, readyLength);
		Debug::log("Send returned {}", sent);
		if (sent > 0)
		{
			br_ssl_engine_sendrec_ack(engine, sent);
		}
		else
		{
			return {sent, false};
		}
		return {sent, sent < readyLength};
	}

	/**
	 * Helper to receive data from the TLS connection. This uses the
	 * `prepareBuffer` function to acquire a buffer for the data.
	 */
	__noinline int tls_connection_receive_internal(
	  Timeout *t,
	  SObj     sealedConnection,
	  FunctionWrapper<void *(int &available, SObj &mallocCapability)>
	    prepareBuffer)
	{
		if (!check_timeout_pointer(t))
		{
			return -EINVAL;
		}
		return with_sealed_tls_context(
		  t, sealedConnection, [&](TLSContext *connection) {
			  auto *engine = &connection->clientContext->eng;
			  while (true)
			  {
				  auto state = br_ssl_engine_current_state(engine);
				  if ((state & BR_SSL_CLOSED) == BR_SSL_CLOSED)
				  {
					  return -ENOTCONN;
				  }
				  if ((state & BR_SSL_RECVAPP) == BR_SSL_RECVAPP)
				  {
					  // If there are data ready to receive, return
					  // it immediately.
					  size_t         unsignedLength;
					  int            length;
					  unsigned char *inputBuffer =
					    br_ssl_engine_recvapp_buf(engine, &unsignedLength);
					  Debug::log("TLS engine has {} bytes ready to receive, "
					             "returning to caller",
					             unsignedLength);
					  length = unsignedLength;
					  void *receivedBuffer =
					    prepareBuffer(length, connection->allocator);
					  if (receivedBuffer == nullptr)
					  {
						  // `prepareBuffer` sets length to an
						  // error code if it cannot supply an
						  // appropriate buffer
						  Debug::log("TLS engine failed to prepare receive "
						             "buffer, error {}",
						             length);

						  return length;
					  }
					  memcpy(receivedBuffer, inputBuffer, length);
					  br_ssl_engine_recvapp_ack(engine, length);
					  Debug::log(
					    "Received {} bytes into {}", length, receivedBuffer);
					  return ssize_t(length);
				  }
				  if ((state & BR_SSL_RECVREC) == BR_SSL_RECVREC)
				  {
					  int received = receive_records(t, connection);
					  if (received == -ETIMEDOUT)
					  {
						  return -ETIMEDOUT;
					  }
					  if (received <= 0)
					  {
						  // The receive failed. This
						  // can happen for a number of
						  // reasons, but most likely
						  // if the link died. After
						  // getting -ENOTCONN, the
						  // caller of this API should
						  // close the TLS socket.
						  return -ENOTCONN;
					  }
					  // Next loop iteration, we'll try pulling the
					  // data out of the TLS engine.
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
	if (!Capability{clientContext.get()}.is_valid())
	{
		Debug::log("Failed to allocate client context");
		return nullptr;
	}
	std::unique_ptr<br_x509_minimal_context, decltype(deleter)> x509Context{
	  static_cast<br_x509_minimal_context *>(
	    heap_allocate(t, allocator, sizeof(br_x509_minimal_context))),
	  deleter};
	auto *engine = &clientContext->eng;
	if (!Capability{x509Context.get()}.is_valid())
	{
		Debug::log("Failed to allocate X509 context");
		return nullptr;
	}
	Debug::log("Initialising TLS context");
	br_ssl_client_init(
	  clientContext.get(), x509Context.get(), trustAnchors, trustAnchorsCount);

	static constexpr size_t                           MinimumBufferSize = 837;
	std::unique_ptr<unsigned char, decltype(deleter)> iobufIn{
	  static_cast<unsigned char *>(
	    heap_allocate(t, allocator, MinimumBufferSize)),
	  deleter};
	std::unique_ptr<unsigned char, decltype(deleter)> iobufOut{
	  static_cast<unsigned char *>(
	    heap_allocate(t, allocator, MinimumBufferSize)),
	  deleter};
	if (!Capability{iobufIn.get()}.is_valid() ||
	    !Capability{iobufOut.get()}.is_valid())
	{
		Debug::log("Failed to allocate buffers");
		return nullptr;
	}

	Debug::log("Setting up TLS buffers");
	br_ssl_engine_set_buffers_bidi(&clientContext->eng,
	                               iobufIn.get(),
	                               MinimumBufferSize,
	                               iobufOut.get(),
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
	                                                iobufIn.release(),
	                                                iobufOut.release()};
	auto        cleanup = [&](auto *) {
        context->~TLSContext();
        token_obj_destroy(allocator, tls_key(), sealed);
	};
	std::unique_ptr<struct SObjStruct, decltype(cleanup)> sealedContext{
	  sealed, cleanup};

	// Try to connect to the server.
	Debug::log("Resetting TLS connection for {}", hostname);
	br_ssl_client_reset(context->clientContext, hostname, 0);

	// Note from the BearSSL API spec: 'The first time the sendapp channel
	// opens marks the completion of the initial handshake'. We are thus
	// safe to return as soon as we see the first `BR_SSL_SENDAPP` flag.
	for (auto state = br_ssl_engine_current_state(engine);
	     ((state & (BR_SSL_SENDAPP)) == 0);
	     state = br_ssl_engine_current_state(engine))
	{
		Debug::log("TLS state: {}", state);
		Debug::log("Last error: {}", br_ssl_engine_last_error(engine));
		if ((state & BR_SSL_CLOSED) == BR_SSL_CLOSED)
		{
			Debug::log("Connection closed, last error: {}",
			           br_ssl_engine_last_error(engine));
			return nullptr;
		}
		if ((state & BR_SSL_SENDREC) == BR_SSL_SENDREC)
		{
			// If we need to send records, send them first.
			auto [sent, unfinished] = send_records(t, context);
			if (sent <= 0)
			{
				return nullptr;
			}
		}
		else if ((state & BR_SSL_RECVREC) == BR_SSL_RECVREC)
		{
			if (receive_records(t, context) <= 0)
			{
				return nullptr;
			}
		}
		else
		{
			if (!t->may_block())
			{
				return nullptr;
			}
		}
	}
	return sealedContext.release();
}

ssize_t tls_connection_send(Timeout *t,
                            SObj     sealedConnection,
                            void    *buffer,
                            size_t   length,
                            int      flags)
{
	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}
	return with_sealed_tls_context(
	  t, sealedConnection, [&](TLSContext *connection) {
		  auto  *engine    = &connection->clientContext->eng;
		  bool   forceLoop = false;
		  size_t totalSent = 0;
		  while ((length > 0) || forceLoop)
		  {
			  forceLoop  = false;
			  auto state = br_ssl_engine_current_state(engine);
			  if ((state & BR_SSL_CLOSED) == BR_SSL_CLOSED)
			  {
				  return -ENOTCONN;
			  }
			  if ((state & BR_SSL_SENDREC) == BR_SSL_SENDREC)
			  {
				  // If there's data ready to send over the network, prioritise
				  // sending it
				  auto [sent, unfinished] = send_records(t, connection);
				  if (sent == -ECOMPARTMENTFAIL)
				  {
					  // The TCP/IP stack crashed; tell the
					  // caller that the link is dead.
					  return -ENOTCONN;
				  }
				  if (sent <= 0)
				  {
					  return sent;
				  }
				  forceLoop = unfinished;
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
				  int ret = heap_claim_fast(t, buffer);
				  if (ret != 0)
				  {
					  return ret;
				  }
				  if (!check_pointer<Permission::Load>(buffer, toSend))
				  {
					  return -EPERM;
				  }
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
				  // Check for timeout. Note that we want to
				  // run this after the short sleep as we may
				  // now have timed out.
				  if (!t->may_block())
				  {
					  // Timed out.
					  break;
				  }
			  }
		  }
		  return totalSent > 0 ? int(totalSent) : -ETIMEDOUT;
	  });
}

NetworkReceiveResult tls_connection_receive(Timeout *t, SObj sealedConnection)
{
	uint8_t *buffer = nullptr;
	ssize_t  result = tls_connection_receive_internal(
	   t,
	   sealedConnection,
	   [&](int &available, SObj &mallocCapability) -> void  *{
          do
          {
              // Do the initial allocation without timeout: if the quota or the
              // heap is almost exhausted, we will block until timeout without
              // achieving anything.
              Timeout zeroTimeout{0};
              buffer = static_cast<unsigned char *>(
                heap_allocate(&zeroTimeout, mallocCapability, available));
              t->elapse(zeroTimeout.elapsed);

              if (!Capability{buffer}.is_valid())
              {
                  // If there's a lot of data, just try a small
                  // allocation and see if that works.
                  if (available > 128)
                  {
                      available = 128;
                      continue;
                  }
                  // If allocation failed and the timeout is zero, give
                  // up now.
                  if (!t->may_block())
                  {
                      available = -ETIMEDOUT;
                      return nullptr;
                  }
                  // If there's time left, let's try allocating a
                  // smaller buffer.
                  auto quota = heap_quota_remaining(mallocCapability);
                  // Subtract 16 bytes to account for the allocation
                  // header.
                  if ((quota < available) && (quota > 16))
                  {
                      available = quota - 16;
                      continue;
                  }
                  available = -ENOMEM;
                  return nullptr;
              }
          } while (!Capability{buffer}.is_valid());
          return buffer;
	   });
	return {result, buffer};
}

int tls_connection_receive_preallocated(Timeout *t,
                                        SObj     sealedConnection,
                                        void    *outputBuffer,
                                        size_t   outputBufferLength)
{
	return tls_connection_receive_internal(
	  t,
	  sealedConnection,
	  [&](int &available, SObj &mallocCapability) -> void * {
		  int ret = heap_claim_fast(t, outputBuffer);
		  if (ret != 0)
		  {
			  available = ret;
			  return nullptr;
		  }
		  if (!check_pointer<PermissionSet{Permission::Store}>(
		        outputBuffer, outputBufferLength))
		  {
			  available = -EPERM;
			  return nullptr;
		  }
		  // If the requested size is larger than the provided buffer
		  // size, we need to tell that to the caller
		  available =
		    std::min(static_cast<size_t>(available), outputBufferLength);
		  return outputBuffer;
	  });
}

int tls_connection_close(Timeout *t, SObj sealed)
{
	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}
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
	auto state = br_ssl_engine_current_state(&tls->clientContext->eng);
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
			auto [sent, unfinished] = send_records(t, tls);
			if (sent < 0)
			{
				// Give up and don't gracefully terminate if we failed to
				// send.
				break;
			}
		}
		else if ((state & BR_SSL_RECVREC) == BR_SSL_RECVREC)
		{
			int received = receive_records(t, tls);
			if (received == -ETIMEDOUT)
			{
				return -ETIMEDOUT;
			}
			if (received == -ECOMPARTMENTFAIL)
			{
				// The TCP/IP stack crashed; give up and don't
				// gracefully terminate.
				break;
			}
			if (received <= 0)
			{
				// If we failed for any reason other than
				// timeout, the socket is likely unusable
				// already.  There will be no graceful cleanup,
				// give up and just close the connection.
				Debug::log("Failed to receive records for graceful close: {}",
				           received);
				break;
			}
		}
		state = br_ssl_engine_current_state(&tls->clientContext->eng);
	} while ((state & BR_SSL_CLOSED) != BR_SSL_CLOSED);
	// At this point, we have shut down the TLS connection.  We can now
	// close the socket and free memory.  This is the point of no return,
	// so upgrade the lock for destruction.
	tls->lock.upgrade_for_destruction();
	auto allocator = tls->allocator;
	tls->~TLSContext();
	token_obj_destroy(allocator, tls_key(), sealed);
	return 0;
}
