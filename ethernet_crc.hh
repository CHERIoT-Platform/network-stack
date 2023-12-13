#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

/**
 * Helper class to compute Ethernet CRC32 checksums.
 *
 * This is intended for use in Ethernet MAC drivers that do not do hardware FCS
 * calculation.
 */
class CRC32
{
	/**
	 * Generate a CRC32 table.
	 */
	inline static constexpr auto crc32_table2 = []() consteval
	{
		std::array<std::uint32_t, 256> retval{};
		uint32_t                       n = 0;
		for (auto &word : retval)
		{
			auto c = n++;
			for (uint8_t k = 0; k < 8; ++k)
			{
				if (c & 1)
				{
					c = uint32_t{0xedb88320} ^ (c >> 1);
				}
				else
				{
					c >>= 1;
				}
			}
			word = c;
		}
		return retval;
	}
	();

	public:
	constexpr uint32_t operator()(const uint8_t *frame, size_t frame_len)
	{
		size_t   i;
		uint32_t crc;

		crc = 0xFFFFFFFF;
		for (i = 0; i < frame_len; i++)
			crc = crc32_table2[(crc ^ frame[i]) & 0xff] ^ (crc >> 8);

		return ~crc;
	}

	private:
	/**
	 * A valid frame captured from the network containing a correct FCS.  This
	 * is used only in the test below.
	 */
	static constexpr uint8_t CRC32TestValue[] = {
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x64, 0xc9, 0x1,  0xb5, 0x6,
	  0x22, 0x8,  0x6,  0x0,  0x1,  0x8,  0x0,  0x6,  0x4,  0x0,  0x1,
	  0x64, 0xc9, 0x1,  0xb5, 0x6,  0x22, 0xc0, 0xa8, 0x1,  0x53, 0x0,
	  0x0,  0x0,  0x0,  0x0,  0x0,  0xa9, 0xfe, 0xa9, 0xfe, 0x0,  0x0,
	  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
	  0x0,  0x0,  0x0,  0x0,  0x0,  0x37, 0x32, 0xbf, 0xd5,
	};

	/**
	 * Compile-time check that the CRC32 implementation is correct.
	 */
	static void test()
	{
		static_assert(CRC32{}(CRC32TestValue, sizeof(CRC32TestValue) - 4) ==
		              0xd5bf3237);
	}
};
