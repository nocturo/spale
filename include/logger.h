// SPDX-License-Identifier: MIT
#pragma once

#include <stdarg.h>

enum logger_level {
    LOGGER_ERROR = 0,
    LOGGER_WARN  = 1,
    LOGGER_INFO  = 2,
    LOGGER_DEBUG = 3,
};

void logger_init_from_env(void);
void logger_set_level(int level);
void logger_use_syslog(int enable);
void logger_close(void);
void logger_log(int level, const char *fmt, ...);

#ifndef SPALE_LOGGER_INTERNAL
#undef LOG_ERROR
#undef LOG_WARN
#undef LOG_INFO
#undef LOG_DEBUG
#define LOG_ERROR(...) logger_log(LOGGER_ERROR, __VA_ARGS__)
#define LOG_WARN(...)  logger_log(LOGGER_WARN,  __VA_ARGS__)
#define LOG_INFO(...)  logger_log(LOGGER_INFO,  __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(LOGGER_DEBUG, __VA_ARGS__)
#endif


