#ifndef VTFS_HTTP_H
#define VTFS_HTTP_H

#define POST "post"
#define PUT "put"
#define DELETE "delete"

#include <linux/inet.h>

int64_t vtfs_http_call(const char *token, const char *method,
                            char *response_buffer, size_t buffer_size,
                            size_t arg_size, ...);

void encode(const char *, char *);

#endif // VTFS_HTTP_H
