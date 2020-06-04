#if !defined(COMMON_H)

#ifdef _MSC_VER
#define ssize_t intptr_t
#endif

#include <stdio.h>
#include <stdbool.h>
#include <nghttp2/nghttp2.h>
#include <uv.h>
#include <sodium.h>
#include <pdfium/fpdfview.h>
#include <pq/libpq-fe.h>
#include "mustach.h"
#include "mustach-json-c.h"
#include "picohttpparser.h"
#define ZPL_IMPL
#include "zpl.h"

#define COMMON_H
#endif
