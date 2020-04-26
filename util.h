#ifndef UTIL_H
#define UTIL_H

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) < (y) ? (y) : (x))
#define ARRAY_SIZE(array) (sizeof((array)) / sizeof((array)[0]))

static inline uint8_t ROTL8(uint8_t k, uint8_t n)
{
    return (k << n) | (k >> (8 - n));
}

static inline uint8_t ROTR8(uint8_t k, uint8_t n)
{
    return (k >> n) | (k << (8 - n));
}

static inline uint32_t ROTL32(uint32_t k, uint32_t n)
{
    return (k << n) | (k >> (32 - n));
}

#endif // UTIL_H
