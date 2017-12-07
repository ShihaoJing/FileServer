#ifndef BUFFER_H
#define BUFFER_H

#include <stdlib.h>
#include <string>
#include <stdarg.h>
#include <stdio.h>

class Buffer {
private:
    std::string data;
    size_t count;
public:
    Buffer() : count(0) { }

    void append(const char *s, size_t n) {
        data.append(s, n);
        count += n;
    }

    void append(const char *s) {
        data.append(s);
        count += strlen(s);
    }

    void appendf(const char *format, ...) {
        char *tmp = NULL;
        int bytes_written, status;

        va_list argp;
        va_start(argp, format);

        bytes_written = vasprintf(&tmp, format, argp);
        if (bytes_written < 0) {
            printf("format append failed\n");
            exit(1);
        }

        va_end(argp);

        append(tmp, bytes_written);

        delete tmp;
    }

    const char* get_c_str() {
        return data.c_str();
    }

    size_t size() {
        return count;
    }
};

#endif