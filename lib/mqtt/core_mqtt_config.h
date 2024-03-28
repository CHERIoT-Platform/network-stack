// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#if DEBUG_MQTT
#	include <stdio.h>

/**
 * coreMQTT calls the logging macros with parameters wrapped in double
 * parentheses, which explains why we need an indirection (`LogError` redirects
 * to `PRINT_LOG_MESSAGE`) and call the second printf without parentheses.
 */
#	define PRINT_LOG_MESSAGE(LEVEL, ...)                                      \
		printf(LEVEL);                                                         \
		printf __VA_ARGS__;                                                    \
		printf("\n");
#else
#	define PRINT_LOG_MESSAGE(LEVEL, ...)                                      \
		do                                                                     \
		{                                                                      \
		} while (0)
#endif

// These macros use the coreMQTT naming convention and so must be excluded from
// clang-tidy warnings.
#define LogError(...) /*NOLINT*/                                               \
	PRINT_LOG_MESSAGE("coreMQTT Error: ", __VA_ARGS__)
#define LogWarn(...) /*NOLINT*/                                                \
	PRINT_LOG_MESSAGE("coreMQTT Warn: ", __VA_ARGS__)
#define LogInfo(...) /*NOLINT*/                                                \
	PRINT_LOG_MESSAGE("coreMQTT Info: ", __VA_ARGS__)
#define LogDebug(...) /*NOLINT*/                                               \
	PRINT_LOG_MESSAGE("coreMQTT Debug: ", __VA_ARGS__)
