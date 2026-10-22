#pragma once

#include "protocol-headers.hh"
#include <debug.hh>

/**
 * Pretty-print a MACAddress.
 *
 * This relies on the address being valid across the duration of the call.
 */
template<>
struct DebugFormatArgumentAdaptor<MACAddress>
{
	__always_inline static DebugFormatArgument construct(MACAddress &address)
	{
		return {reinterpret_cast<uintptr_t>(&address),
		        reinterpret_cast<uintptr_t>(&print)};
	}

	private:
	static void print(uintptr_t value, DebugWriter &writer)
	{
		auto *address = reinterpret_cast<MACAddress *>(value);
		writer.write_hex_byte((*address)[0]);
		for (size_t ix = 1; ix < sizeof(*address); ix++)
		{
			writer.write(':');
			writer.write_hex_byte((*address)[ix]);
		}
	}
};

/**
 * Pretty-print an IPv4Address.
 */
template<>
struct DebugFormatArgumentAdaptor<IPv4Address>
{
	__always_inline static DebugFormatArgument construct(IPv4Address &address)
	{
		return {static_cast<uintptr_t>(address.raw),
		        reinterpret_cast<uintptr_t>(&print)};
	}

	private:
	static void print(uintptr_t value, DebugWriter &writer)
	{
		auto address = static_cast<uint32_t>(value);
		writer.write(static_cast<int32_t>((address >> 0) & 0xFF));
		writer.write('.');
		writer.write(static_cast<int32_t>((address >> 8) & 0xFF));
		writer.write('.');
		writer.write(static_cast<int32_t>((address >> 16) & 0xFF));
		writer.write('.');
		writer.write(static_cast<int32_t>((address >> 24) & 0xFF));
	}
};
