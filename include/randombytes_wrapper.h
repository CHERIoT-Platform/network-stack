// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <randombytes.h>

#ifdef __cplusplus

namespace rbw_detail
{
	template<typename P>
	concept HasRandomBytesOverload = requires(P &v) { ::randombytes(v); };
} // namespace rbw_detail

// In order to ensure source compatibility with older RTOS versions that do
// not expose the C++ convenience wrappers for randombytes(), we define our
// own copies here, using concept probes to avoid redefining them if they
// already exist.

/**
 * Populate a container-like `output` with entropy using its `.size()` and
 * `.data`() APIs.
 *
 * This will be cryptographically secure entropy if and only if the system
 * entropy source is cryptographically secure.
 *
 * Returns 0 on success.
 */
template<typename T>
    requires(!rbw_detail::HasRandomBytesOverload<T>) && requires(T &v) {
	    requires std::is_pointer_v<decltype(v.data())>;
	    requires std::is_convertible_v<decltype(v.size()), size_t>;
    }
__always_inline int randombytes(T &output)
{
	return randombytes(reinterpret_cast<uint8_t *>(output.data()),
	                   output.size() * sizeof(*output.data()));
}

/**
 * Populate an `output` array of length `N` with `N * sizeof(output[0])` bytes
 * of entropy from the system's entropy source.
 *
 * This will be cryptographically secure entropy if and only if the system
 * entropy source is cryptographically secure.
 *
 * Returns 0 on success.
 */
template<typename T, size_t N>
    requires(!rbw_detail::HasRandomBytesOverload<T[N]> &&
             std::is_arithmetic_v<T>)
__always_inline int randombytes(T (&output)[N])
{
	return randombytes(reinterpret_cast<uint8_t *>(&output), sizeof(output));
}

/**
 * Populate `output` with `sizeof(output)` bytes of entropy from the system's
 * entropy source.
 *
 * This will be cryptographically secure entropy if and only if the system
 * entropy source is cryptographically secure.
 *
 * Returns 0 on success.
 */
template<typename T>
    requires(!rbw_detail::HasRandomBytesOverload<T> && std::is_arithmetic_v<T>)
__always_inline int randombytes(T &output)
{
	return randombytes(reinterpret_cast<uint8_t *>(&output), sizeof(output));
}

#endif // ifdef __cplusplus
