#pragma once

#include "microvium/microvium.h"
#include <debug.hh>
#include <functional>
#include <magic_enum/magic_enum.hpp>
#include <microvium/microvium.h>
#include <platform-gpio.hh>
#include <string_view>
#include <tuple>

/**
 * Code related to the JavaScript interpreter.
 */
namespace
{
	using CHERI::Capability;

	/**
	 * Constants for functions exposed to JavaScript->C++ FFI
	 *
	 * The values here must match the ones used in cheri.js.
	 */
	enum Exports : mvm_HostFunctionID
	{
		Print = 1,
		LEDOn,
		LEDOff,
		ReadButtons,
		ReadSwitches,
		MQTTPublish,
		MQTTSubscribe,
	};

	/// Constant for the run function exposed to C++->JavaScript FFI
	static constexpr mvm_VMExportID ExportTick      = 1234;
	static constexpr mvm_VMExportID ExportPublished = 1235;

	/**
	 * Template that returns JavaScript argument specified in `arg` as a C++
	 * type T.
	 */
	template<typename T>
	T extract_argument(mvm_VM *vm, mvm_Value arg);

	/**
	 * Specialisation to return integers.
	 */
	template<>
	__always_inline int32_t extract_argument<int32_t>(mvm_VM *vm, mvm_Value arg)
	{
		return mvm_toInt32(vm, arg);
	}

	/**
	 * Specialisation to return booleans.
	 */
	template<>
	__always_inline bool extract_argument<bool>(mvm_VM *vm, mvm_Value arg)
	{
		return mvm_toBool(vm, arg);
	}

	/**
	 * Specialisation to return string views.
	 */
	template<>
	__always_inline std::string_view
	extract_argument<std::string_view>(mvm_VM *vm, mvm_Value arg)
	{
		size_t      length;
		const char *buffer = mvm_toStringUtf8(vm, arg, &length);
		return {buffer, length};
	}

	/**
	 * Populate a tuple with arguments from an array of JavaScript values.
	 * This uses `extract_argument` to coerce each JavaScript value to the
	 * expected type.
	 */
	template<typename Tuple, int Idx = 0>
	__always_inline void
	args_to_tuple(Tuple &tuple, mvm_VM *vm, mvm_Value *args)
	{
		if constexpr (Idx < std::tuple_size_v<Tuple>)
		{
			std::get<Idx>(tuple) = extract_argument<
			  std::remove_reference_t<decltype(std::get<Idx>(tuple))>>(
			  vm, args[Idx]);
			args_to_tuple<Tuple, Idx + 1>(tuple, vm, args);
		}
	}

	/**
	 * Helper template to extract the arguments from a function type.
	 */
	template<typename T>
	struct FunctionSignature;

	/**
	 * The concrete specialisation that decomposes the function type.
	 */
	template<typename R, typename... Args>
	struct FunctionSignature<R(Args...)>
	{
		/**
		 * A tuple type containing all of the argument types of the function
		 * whose type is being extracted.
		 */
		using ArgumentType = std::tuple<Args...>;
	};

	/**
	 * The concrete specialisation that decomposes the function type.
	 */
	template<typename R, typename... Args>
	struct FunctionSignature<R __attribute__((cheri_ccall)) (Args...)>
	{
		/**
		 * A tuple type containing all of the argument types of the function
		 * whose type is being extracted.
		 */
		using ArgumentType = std::tuple<Args...>;
	};

	/**
	 * Call `Fn` with arguments from the Microvium arguments array.
	 *
	 * This is a wrapper that allows automatic forwarding from a function
	 * exported to JavaScript
	 */
	template<auto Fn>
	__always_inline mvm_TeError call_export(mvm_VM    *vm,
	                                        mvm_Value *result,
	                                        mvm_Value *args,
	                                        uint8_t    argsCount)
	{
		using TupleType = typename FunctionSignature<
		  std::remove_pointer_t<decltype(Fn)>>::ArgumentType;
		// Return an error if we have the wrong number of arguments.
		if (argsCount < std::tuple_size_v<TupleType>)
		{
			return MVM_E_UNEXPECTED;
		}
		// Get the arguments in a tuple.
		TupleType arguments;
		args_to_tuple(arguments, vm, args);
		// If this returns void, we don't need to do anything with the return.
		if constexpr (std::is_same_v<void, decltype(std::apply(Fn, arguments))>)
		{
			std::apply(Fn, arguments);
		}
		else
		{
			// Coerce the return type to a JavaScript object of the correct
			// type and return it.
			auto primitiveResult = std::apply(Fn, arguments);
			if constexpr (std::is_same_v<decltype(primitiveResult), bool>)
			{
				*result = mvm_newBoolean(primitiveResult);
			}
			if constexpr (std::is_same_v<decltype(primitiveResult), int32_t>)
			{
				*result = mvm_newInt32(vm, primitiveResult);
			}
			if constexpr (std::is_same_v<decltype(primitiveResult),
			                             std::string>)
			{
				*result = mvm_newString(
				  vm, primitiveResult.data(), primitiveResult.size());
			}
		}
		return MVM_E_SUCCESS;
	}

	/**
	 * Helper that maps from Exports
	 */
	template<Exports>
	constexpr static std::nullptr_t ExportedFn = nullptr;

	/**
	 * Turn an LED on.
	 */
	void export_led_on(int32_t index)
	{
		MMIO_CAPABILITY(GPIO, gpio_led0)->led_on(index);
	}

	template<>
	constexpr static auto ExportedFn<LEDOn> = export_led_on;

	/**
	 * Turn an LED off.
	 */
	void export_led_off(int32_t index)
	{
		MMIO_CAPABILITY(GPIO, gpio_led0)->led_off(index);
	}

	template<>
	constexpr static auto ExportedFn<LEDOff> = export_led_off;

	/**
	 * Read all buttons.
	 */
	int32_t export_read_buttons()
	{
		return MMIO_CAPABILITY(GPIO, gpio_led0)->buttons();
	}

	template<>
	constexpr static auto ExportedFn<ReadButtons> = export_read_buttons;

	/**
	 * Read all switches.
	 */
	int32_t export_read_switches()
	{
		return MMIO_CAPABILITY(GPIO, gpio_led0)->switches();
	}

	template<>
	constexpr static auto ExportedFn<ReadSwitches> = export_read_switches;

	/**
	 * Publish a message to an MQTT topic.
	 */
	bool export_mqtt_publish(std::string_view topic, std::string_view message);

	template<>
	constexpr static auto ExportedFn<MQTTPublish> = export_mqtt_publish;

	/**
	 * Subscribe to an MQTT topic.
	 */
	bool export_mqtt_subscribe(std::string_view topic);

	template<>
	constexpr static auto ExportedFn<MQTTSubscribe> = export_mqtt_subscribe;

	/**
	 * Base template for exported functions.  Forwards to the function defined
	 * with `ExportedFn<E>`.
	 */
	template<Exports E>
	mvm_TeError exported_function(mvm_VM *vm,
	                              mvm_HostFunctionID,
	                              mvm_Value *result,
	                              mvm_Value *args,
	                              uint8_t    argCount)
	{
		return call_export<ExportedFn<E>>(vm, result, args, argCount);
	}

	/**
	 * Print a string passed from JavaScript.
	 */
	template<>
	mvm_TeError exported_function<Print>(mvm_VM            *vm,
	                                     mvm_HostFunctionID funcID,
	                                     mvm_Value         *result,
	                                     mvm_Value         *args,
	                                     uint8_t            argCount)
	{
		// Helper to write a C string to the UART.
		auto puts = [](const char *str) {
			auto *uart = MMIO_CAPABILITY(Uart, uart);
			while (char c = *(str++))
			{
				uart->blocking_write(c);
			}
		};
		puts("\033[32;1m");
		// Iterate over the arguments.
		for (unsigned i = 0; i < argCount; i++)
		{
			// Coerce the argument to a string and get it as a C string and
			// write it to the UART.
			puts(mvm_toStringUtf8(vm, args[i], nullptr));
		}
		// Write a trailing newline
		puts("\033[0m\n");
		// Unconditionally return success
		return MVM_E_SUCCESS;
	}

	/**
	 * Callback from microvium that resolves imports.
	 *
	 * This resolves each function to the template instantiation of
	 * `exported_function` with `funcID` as the template parameter.
	 */
	mvm_TeError
	resolve_import(mvm_HostFunctionID funcID, void *, mvm_TfHostFunction *out)
	{
		return magic_enum::enum_switch(
		  [&](auto val) {
			  constexpr Exports Export = val;
			  *out                     = exported_function<Export>;
			  return MVM_E_SUCCESS;
		  },
		  Exports(funcID),
		  MVM_E_UNRESOLVED_IMPORT);
	}

	/**
	 * Helper that deletes a Microvium VM when used with a C++ unique pointer.
	 */
	struct MVMDeleter
	{
		void operator()(mvm_VM *mvm) const
		{
			mvm_free(mvm);
		}
	};
} // namespace
