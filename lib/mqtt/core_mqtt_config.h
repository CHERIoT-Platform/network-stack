// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#if DEBUG_MQTT
#	include <stdio.h>

/**
 * coreMQTT calls the logging macros with parameters wrapped in double
 * parentheses, which explains why we need an indirection (`LogError` redirects
 * to `LogFunction`) and call the second printf without parentheses.
 */
#	define LogFunction(LEVEL, ...)                                            \
		printf(LEVEL);                                                         \
		printf __VA_ARGS__;                                                    \
		printf("\n");
#else
#	define LogFunction(LEVEL, ...)                                            \
		do                                                                     \
		{                                                                      \
		} while (0)
#endif

#define LogError(...) LogFunction("coreMQTT Error: ", __VA_ARGS__);
#define LogWarn(...) LogFunction("coreMQTT Warn: ", __VA_ARGS__);
#define LogInfo(...) LogFunction("coreMQTT Info: ", __VA_ARGS__);
#define LogDebug(...) LogFunction("coreMQTT Debug: ", __VA_ARGS__);
