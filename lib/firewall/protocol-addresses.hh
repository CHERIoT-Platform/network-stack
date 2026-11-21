// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>

/**
 * Ethernet MAC address.
 */
struct MACAddress
{
	using Raw = std::array<uint8_t, 6>;

	Raw raw;

	constexpr MACAddress() = default;

	constexpr MACAddress(Raw &&r) : raw(r) {}

	/// Pass-through aggregate initialization
	template<typename... T>
	constexpr MACAddress(const T &&...r) : raw({static_cast<uint8_t>(r)...})
	{
	}

	template<typename Self>
	auto data(this Self &&self)
	{
		return self.raw.data();
	}

	template<typename Self>
	auto begin(this Self &&self)
	{
		return self.raw.begin();
	}

	template<typename Self>
	auto end(this Self &&self)
	{
		return self.raw.end();
	}

	template<typename Self>
	auto &operator[](this Self &&self, size_t ix)
	{
		return self.raw[ix];
	}

	template<typename Self>
	constexpr bool operator==(this Self &&self, MACAddress &other)
	{
		return self.raw == other.raw;
	}

	template<typename Self>
	constexpr operator Raw &(this Self &&self)
	{
		return self.raw;
	}
};
static_assert(sizeof(MACAddress) == sizeof(MACAddress::Raw));

struct IPv4Address
{
	uint32_t raw;

	constexpr IPv4Address() = default;

	constexpr IPv4Address(uint32_t r) : raw(r) {};

	constexpr IPv4Address(const IPv4Address &) = default;

	operator uint32_t() const
	{
		return raw;
	}
};

/**
 * IPv6 address.
 *
 * This should be `std::array<uint8_t, 16>` but our version of `std::array`
 * does not yet have a three-way comparison operator.
 */
struct IPv6Address
{
	/**
	 * The bytes of the address.
	 */
	uint8_t bytes[16];
	/**
	 * Returns a pointer to the bytes of this address.
	 */
	auto data()
	{
		return bytes;
	}
	/**
	 * Returns the size of an address.
	 */
	[[nodiscard]] size_t size() const
	{
		return sizeof(bytes);
	}
	/// Comparison operator.
	// A clang-tidy bug thinks that this should be = nullptr instead of =
	// default.
	auto operator<=>(const IPv6Address &) const = default; // NOLINT
};
