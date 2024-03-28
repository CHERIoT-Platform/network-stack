// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#if DEBUG_SNTP
#	include <stdio.h>

/**
 * coreSNTP calls the logging macros with parameters wrapped in double
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

// These macros must match the coreSNTP naming conventions, so don't lint them.
#define LogError(...) /*NOLINT*/ PRINT_LOG_MESSAGE("SNTP Error: ", __VA_ARGS__)
#define LogWarn(...) /*NOLINT*/ PRINT_LOG_MESSAGE("SNTP Warn: ", __VA_ARGS__)
#define LogInfo(...) /*NOLINT*/ PRINT_LOG_MESSAGE("SNTP Info: ", __VA_ARGS__)
#define LogDebug(...) /*NOLINT*/ PRINT_LOG_MESSAGE("SNTP Debug: ", __VA_ARGS__)
