#ifndef DEBUG_SNTP
#	define DEBUG_SNTP false
#endif

#if DEBUG_SNTP
#	include <stdio.h>

/**
 * coreSNTP calls the logging macros with parameters wrapped in double
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

#define LogError(...) LogFunction("SNTP Error: ", __VA_ARGS__);
#define LogWarn(...) LogFunction("SNTP Warn: ", __VA_ARGS__);
#define LogInfo(...) LogFunction("SNTP Info: ", __VA_ARGS__);
#define LogDebug(...) LogFunction("SNTP Debug: ", __VA_ARGS__);
