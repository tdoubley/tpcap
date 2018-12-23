#ifndef _HEADERS_DEBUG_H_
#define _HEADERS_DEBUG_H_

#ifndef NO_DEBUG
#define DEBUG_PRINT(fmt, ...) \
    do { \
        printf(fmt, __VA_ARGS__); \
    }while(0)
#else
#define DEBUG_PRINT(fmt, ...) \
    do{ \
    }while(0)
#endif

#ifndef NO_DEBUG
#define DEBUG_ASSERT(s) \
    do { \
        if (!s) { \
            printf("FILE: %s, LINE: %d, %s\n", __FILE__, __LINE__, #s); \
            while(1); \
        } \
    }while(0)
#else
#define DEBUG_ASSERT(s) \
    do{ \
    }while(0)
#endif


#endif /* end of _HEADERS_DEBUG_H_ */
