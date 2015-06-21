#pragma once


/* BEGIN PROTOTYPES */

void loginit(const char* ident, int to_stderr, int debug_flag);
void vlogit(int level, const char* fmt, va_list args);
void logit(int level, const char* fmt, ...);
void logitm(int level, const char* fmt, ...);
void logerr(const char* fmt, ...);
void logerrx(const char* fmt, ...);

/* END PROTOTYPES */
