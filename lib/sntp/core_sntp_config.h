#ifdef DEBUG_SNTP
#	define PrintfError(...)                                                   \
		printf("Error: "__VA_ARGS__);                                          \
		printf("\n")
#	define PrintfWarn(...)                                                    \
		printf("Warn: "__VA_ARGS__);                                           \
		printf("\n")
#	define PrintfInfo(...)                                                    \
		printf("Info: " __VA_ARGS__);                                          \
		printf("\n")
#	define PrintfDebug(...)                                                   \
		printf("Debug: " __VA_ARGS__);                                         \
		printf("\n")
#else
#	define PrintfError(...)                                                   \
		do                                                                     \
		{                                                                      \
		} while (0)
#	define PrintfWarn(...)                                                    \
		do                                                                     \
		{                                                                      \
		} while (0)
#	define PrintfInfo(...)                                                    \
		do                                                                     \
		{                                                                      \
		} while (0)
#	define PrintfDebug(...)                                                   \
		do                                                                     \
		{                                                                      \
		} while (0)
#endif
