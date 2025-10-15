// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>

#define SPALE_LOGGER_INTERNAL 1
#include "logger.h"

static int g_level = LOGGER_INFO;
static int g_use_syslog = 0;

void logger_set_level(int level) { g_level = level; }
void logger_use_syslog(int enable)
{
    if (enable && !g_use_syslog) { openlog("spale", LOG_PID, LOG_DAEMON); }
    else if (!enable && g_use_syslog) { closelog(); }
    g_use_syslog = enable ? 1 : 0;
}
void logger_close(void) { if (g_use_syslog) closelog(); g_use_syslog = 0; }

void logger_init_from_env(void)
{
    const char *lvl = getenv("SPALE_LOG_LEVEL");
    if (lvl && *lvl) {
        if (strcmp(lvl, "debug") == 0) g_level = LOGGER_DEBUG;
        else if (strcmp(lvl, "info") == 0) g_level = LOGGER_INFO;
        else if (strcmp(lvl, "warn") == 0) g_level = LOGGER_WARN;
        else if (strcmp(lvl, "error") == 0) g_level = LOGGER_ERROR;
    }
    const char *sysl = getenv("SPALE_USE_SYSLOG");
    if (sysl && (*sysl == '1' || *sysl == 'y' || *sysl == 'Y')) logger_use_syslog(1);
}

static int map_level_syslog(int level)
{
    switch (level) {
        case LOGGER_ERROR: return LOG_ERR;
        case LOGGER_WARN:  return LOG_WARNING;
        case LOGGER_INFO:  return LOG_INFO;
        case LOGGER_DEBUG: return LOG_DEBUG;
        default: return LOG_INFO;
    }
}

void logger_log(int level, const char *fmt, ...)
{
    if (level > g_level) return;
    va_list ap;
    va_start(ap, fmt);
    if (g_use_syslog) {
        vsyslog(map_level_syslog(level), fmt, ap);
        va_end(ap);
        return;
    }
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv; (void)localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    const char *p = "INFO";
    if (level == LOGGER_ERROR) p = "ERROR"; else if (level == LOGGER_WARN) p = "WARN"; else if (level == LOGGER_DEBUG) p = "DEBUG";
    fprintf(stderr, "%s [%s] ", ts, p);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}


