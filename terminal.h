#ifndef _TERMINAL_H_
#define _TERMINAL_H_

long my_strtol(const char *str, char **endptr, int base) {
    const char *p = str;
    long result = 0;
    int sign = 1;

    if (base != 10) {
        if (endptr) *endptr = (char *)str;
        return 0; // Only base 10 supported in this simple version
    }

    // Skip leading whitespace
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;

    // Optional sign
    if (*p == '-') {
        sign = -1;
        p++;
    } else if (*p == '+') {
        p++;
    }

    if (*p < '0' || *p > '9') {
        if (endptr) *endptr = (char *)str;
        return 0; // No digits
    }

    while (*p >= '0' && *p <= '9') {
        result = result * 10 + (*p - '0');
        p++;
    }

    if (endptr) *endptr = (char *)p;
    return sign * result;
}

#endif