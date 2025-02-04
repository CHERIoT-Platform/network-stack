// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <cheri-builtins.h>
#include <token.h>

/**
 * Owning pointer modelled on a `std::unique_ptr` for owning sealed resources.
 */
template<typename T, typename Cleanup>
class SealedOwner
{
	using Sealed   = CHERI_SEALED(T *);
	Sealed  object = nullptr;
	Cleanup cleanup;

	public:
	SealedOwner(Sealed object, Cleanup cleanup)
	  : object(object), cleanup(cleanup)
	{
	}

	Sealed release()
	{
		Sealed tmp = object;
		object     = nullptr;
		return tmp;
	}

	void reset(Sealed ptr)
	{
		std::swap(ptr, object);
		if (ptr != nullptr)
		{
			cleanup(ptr);
		}
	}

	~SealedOwner()
	{
		reset(nullptr);
	}

	operator bool()
	{
		return cheri_tag_get(object);
	}

	Sealed operator*()
	{
		return object;
	}

	Sealed get()
	{
		return object;
	}
};
