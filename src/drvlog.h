// drvlog.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2026 Ake Hedman, the VSCP Project
// <akhe@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//
// Logging for the driver.
//
// A driver lives inside a host (the VSCP daemon, VSCP Works, ...), and
// spdlog's registry and default logger are shared by everything in the
// process. The driver therefore never changes them. It logs to its own
// logger when its configuration enables file or console logging, and to
// the host's default logger otherwise.
//

#if !defined(VSCPL2DRV_TCPIPSRV_DRVLOG_H__INCLUDED_)
#define VSCPL2DRV_TCPIPSRV_DRVLOG_H__INCLUDED_

#include <memory>
#include <utility>

#include <spdlog/spdlog.h>

namespace drvlog {

/*!
  Set the driver's own logger. nullptr makes the driver log to the host's
  default logger.
*/
void setLogger(std::shared_ptr<spdlog::logger> logger);

/// The driver's own logger, or the host's default logger if there is none
std::shared_ptr<spdlog::logger> get(void);

template <typename... Args>
inline void trace(spdlog::format_string_t<Args...> fmt, Args&&... args)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->trace(fmt, std::forward<Args>(args)...);
  }
}

template <typename T>
inline void trace(const T& msg)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->trace(msg);
  }
}

template <typename... Args>
inline void debug(spdlog::format_string_t<Args...> fmt, Args&&... args)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->debug(fmt, std::forward<Args>(args)...);
  }
}

template <typename T>
inline void debug(const T& msg)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->debug(msg);
  }
}

template <typename... Args>
inline void info(spdlog::format_string_t<Args...> fmt, Args&&... args)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->info(fmt, std::forward<Args>(args)...);
  }
}

template <typename T>
inline void info(const T& msg)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->info(msg);
  }
}

template <typename... Args>
inline void warn(spdlog::format_string_t<Args...> fmt, Args&&... args)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->warn(fmt, std::forward<Args>(args)...);
  }
}

template <typename T>
inline void warn(const T& msg)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->warn(msg);
  }
}

template <typename... Args>
inline void error(spdlog::format_string_t<Args...> fmt, Args&&... args)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->error(fmt, std::forward<Args>(args)...);
  }
}

template <typename T>
inline void error(const T& msg)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->error(msg);
  }
}

template <typename... Args>
inline void critical(spdlog::format_string_t<Args...> fmt, Args&&... args)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->critical(fmt, std::forward<Args>(args)...);
  }
}

template <typename T>
inline void critical(const T& msg)
{
  std::shared_ptr<spdlog::logger> l = get();
  if (l) {
    l->critical(msg);
  }
}

} // namespace drvlog

#endif // VSCPL2DRV_TCPIPSRV_DRVLOG_H__INCLUDED_
