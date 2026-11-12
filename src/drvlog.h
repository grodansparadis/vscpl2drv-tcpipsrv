// drvlog.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// Copyright © 2000-2026 Ake Hedman, the VSCP Project
// <akhe@vscp.org>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-2.0-only
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
