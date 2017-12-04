#include "buffer.h"

Buffer* buffer_alloc(int initial_size)
{
    Buffer *buf = (Buffer*)malloc(sizeof(Buffer));
    char *tmp = (char*)calloc(1, initial_size * sizeof(char));

    if (buf == NULL || tmp == NULL) {
        if (buf != NULL) {
            free(buf);
        }
        if (tmp != NULL) {
            free(tmp);
        }
        return NULL;
    }

    buf->contents   = tmp;
    buf->bytes_used = 0;
    buf->total_size = initial_size;

    return buf;
}

int buffer_strlen(Buffer *buf)
{
    return buf->bytes_used;
}

void buffer_free(Buffer *buf)
{
    free(buf->contents);
    free(buf);
}

int buffer_has_space(Buffer *buf, int desired_length)
{
    int bytes_remaining = buf->total_size - buf->bytes_used;

    return desired_length <= bytes_remaining;
}

int buffer_grow(Buffer *buf, int minimum_size)
{
    int factor = buf->total_size;

    if (factor < minimum_size) {
        factor = minimum_size;
    }

    int new_size = factor * 2;

    char *tmp = (char*)realloc(buf->contents, new_size * sizeof(char));

    if (tmp == NULL) {
        return -1;
    }

    buf->contents   = tmp;
    buf->total_size = new_size;

    return 1;
}

void buffer_cat(Buffer *buf, char *append, int length)
{
    int i               = 0;
    int bytes_copied    = 0;
    int buffer_position = 0;

    strncpy(buf->contents + buf->bytes_used, append, length);
    buf->bytes_used += length;
    buf->contents[buf->bytes_used] = '\0';
}

int buffer_append(Buffer *buf, char *append, int length)
{
    int desired_length = length + 1; // Space for NUL byte

    if (!buffer_has_space(buf, desired_length)) {
        if (!buffer_grow(buf, desired_length)) {
            return -1;
        }
    }

    buffer_cat(buf, append, length);

    return 1;
}

int buffer_appendf(Buffer *buf, const char *format, ...)
{
    char *tmp = NULL;
    int bytes_written, status;

    va_list argp;
    va_start(argp, format);

    bytes_written = vasprintf(&tmp, format, argp);
    if (bytes_written < 0) {
        if (tmp != NULL) {
            free(tmp);
        }
        return - 1;
    }

    va_end(argp);

    if (!buffer_append(buf, tmp, bytes_written)) {
        free(tmp);
        return -1;
    }

    free(tmp);

    return 1;
}

int buffer_nappendf(Buffer *buf, size_t length, const char *format, ...)
{
    int printf_length = length + 1;

    char *tmp  = (char*)calloc(1, printf_length * sizeof(char));

    if (tmp != NULL) { 
        free(tmp); 
        return -1;
    }

    va_list argp;
    va_start(argp, format);

    if (vsnprintf(tmp, printf_length, format, argp) < 0) {
        if (tmp != NULL) { 
            free(tmp); 
            return -1;
        }
    }

    va_end(argp);

    if (buffer_append(buf, tmp, length) < 0) {
        if (tmp != NULL) { 
            free(tmp); 
            return -1;
        }
    }

    free(tmp);

    return 1;
}

char* buffer_to_s(Buffer *buf)
{
    char *result = (char*)calloc(1, buf->bytes_used + 1);
    strncpy(result, buf->contents, buffer_strlen(buf));

    return result;
}