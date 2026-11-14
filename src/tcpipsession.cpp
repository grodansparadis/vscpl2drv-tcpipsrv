// tcpipsession.cpp
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

//
// One client connection of the VSCP tcp/ip server. The connection is
// driven by the mongoose event loop of the driver (see tcpipWorkerThread in
// tcpipsrvdrv.cpp), which calls onAccept, onRead, onPoll and onClose.
//

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <algorithm>
#include <list>
#include <string>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mongoose.h>
#include <vscp.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include "tcpipsession.h"
#include <crc.h>
#include <openssl/crypto.h>
#include "tcpipsrvdrv.h"
#include "drvlog.h"
#include "version.h"

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include <spdlog/spdlog.h>

using json = nlohmann::json;
using namespace kainjow::mustache;

///////////////////////////////////////////////////////////////////////////////
// CTcpipSession
//

CTcpipSession::CTcpipSession(CTcpipSrvDrv* pObj, struct mg_connection* conn)
{
  m_conn         = conn;
  m_pObj         = pObj;
  m_pClientItem  = nullptr;
  m_rv           = 0;
  m_bReceiveLoop = false;
  m_bBinaryMode  = false;
  m_bBinaryOpen  = false;
}

CTcpipSession::~CTcpipSession()
{
  onClose();
}

///////////////////////////////////////////////////////////////////////////////
// isOpen
//

bool
CTcpipSession::isOpen(void) const
{
  return (nullptr != m_conn) && !m_conn->is_closing && !m_conn->is_draining;
}

///////////////////////////////////////////////////////////////////////////////
// close
//

void
CTcpipSession::close(void)
{
  if (nullptr != m_conn) {
    m_conn->is_draining = 1; // Send what is queued, then close
  }
}

///////////////////////////////////////////////////////////////////////////////
// getRemoteAddress
//

std::string
CTcpipSession::getRemoteAddress(void) const
{
  if (nullptr == m_conn) {
    return std::string();
  }
  char buf[100];
  mg_snprintf(buf, sizeof(buf), "%M", mg_print_ip, &m_conn->rem);
  return std::string(buf);
}

///////////////////////////////////////////////////////////////////////////////
// write
//

bool
CTcpipSession::write(std::string& str, bool bAddCRLF)
{
  if (!isOpen()) {
    return false;
  }

  if (bAddCRLF) {
    str += std::string("\r\n");
  }

  return write(str.c_str(), str.length());
}

bool
CTcpipSession::write(const char* buf, size_t len)
{
  if (!isOpen() || (nullptr == buf)) {
    return false;
  }

  // mg_send queues the data on the connection; it is sent by the event loop
  if (!mg_send(m_conn, buf, len)) {
    m_rv = 0;
    return false;
  }

  m_rv = len;
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// onAccept
//

bool
CTcpipSession::onAccept(void)
{
  m_pClientItem = new (std::nothrow) CClientItem();
  if (nullptr == m_pClientItem) {
    drvlog::error("[TCP/IP srv] Memory error, can't allocate client structure.");
    return false;
  }

  vscpdatetime now;
  m_pClientItem->m_dtutc         = now;
  m_pClientItem->m_bOpen         = true;
  m_pClientItem->m_type          = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_TCPIP;
  m_pClientItem->m_strDeviceName = "Remote tcp/ip server connection @ [";
  m_pClientItem->m_strDeviceName += m_pObj->getListeningInterface();
  m_pClientItem->m_strDeviceName += "]";
  m_pClientItem->m_clientActivity = (long)time(NULL);

  pthread_mutex_lock(&m_pObj->m_clientList.m_mutexItemList);
  if (!m_pObj->addClient(m_pClientItem)) {
    pthread_mutex_unlock(&m_pObj->m_clientList.m_mutexItemList);
    delete m_pClientItem;
    m_pClientItem = nullptr;
    drvlog::error("[TCP/IP srv] Failed to add client.");
    write(MSG_MAX_NUMBER_OF_CLIENTS, strlen(MSG_MAX_NUMBER_OF_CLIENTS));
    return false;
  }
  pthread_mutex_unlock(&m_pObj->m_clientList.m_mutexItemList);

  // Clear the filter (allow everything )
  vscp_clearVSCPFilter(&m_pClientItem->m_filter);

  std::string str = std::string(MSG_WELCOME);
  str += std::string("Version: ");
  str += vscp_str_format("%d.%d.%d-%d", MAJOR_VERSION, MINOR_VERSION, RELEASE_VERSION, BUILD_VERSION);
  str += std::string("\r\n");
  str += std::string(DRIVER_COPYRIGHT);
  str += std::string("\r\n");
  str += std::string(MSG_OK);
  write(str.c_str(), str.length());

  drvlog::debug("[TCP/IP srv] Ready to serve client {}.", getRemoteAddress());
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// onRead
//

void
CTcpipSession::onRead(const char* buf, size_t len)
{
  if ((nullptr == m_pClientItem) || !isOpen()) {
    return;
  }

  m_pClientItem->m_clientActivity = (long)time(NULL);

  if (m_bBinaryMode) {
    onBinaryData((const uint8_t*)buf, len);
    return;
  }

  m_strResponse.append(buf, len);
  onTextData();
}

///////////////////////////////////////////////////////////////////////////////
// onTextData
//

void
CTcpipSession::onTextData(void)
{
  size_t pos;
  while (isOpen() && !m_bBinaryMode && (std::string::npos != (pos = m_strResponse.find('\n')))) {
    std::string strCommand = m_strResponse.substr(0, pos + 1);
    m_strResponse.erase(0, pos + 1);
    if (!handleLine(strCommand)) {
      close();
      return;
    }
  }

  // After BINARY the rest of the data is binary
  if (m_bBinaryMode) {
    std::string rest;
    rest.swap(m_strResponse);
    if (!rest.empty()) {
      onBinaryData((const uint8_t*)rest.data(), rest.size());
    }
    return;
  }

  // A line can not grow without bound
  if (m_strResponse.length() > TCPIPSRV_MAX_LINE_LENGTH) {
    drvlog::warn("[TCP/IP srv] Command line too long from {}. Closing.", getRemoteAddress());
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    close();
  }
}

///////////////////////////////////////////////////////////////////////////////
// handleLine
//

bool
CTcpipSession::handleLine(std::string strCommand)
{
  vscp_trim(strCommand);
  if (0 == strCommand.length()) {
    return true;
  }

  // Command history ("++" lists it, "+" or "+n" repeats a command)
  if (m_commandArray.size() && ('+' == strCommand[0])) {

    if (vscp_startsWith(strCommand, "++", &strCommand)) {
      for (int i = (int)m_commandArray.size() - 1; i >= 0; i--) {
        std::string str = vscp_str_format("%d - %s", (int)(m_commandArray.size() - i - 1), m_commandArray[i].c_str());
        vscp_trim(str);
        write(str, true);
      }
      return true;
    }

    size_t n = 0;
    if (strCommand.length() > 1) {
      n = vscp_readStringValue(strCommand.substr(1));
    }
    if (n >= m_commandArray.size()) {
      n = m_commandArray.size() - 1;
    }
    strCommand = m_commandArray[m_commandArray.size() - n - 1];
    std::string echo = strCommand;
    write(echo, true);
  }

  m_commandArray.push_back(strCommand);
  if (m_commandArray.size() > VSCP_TCPIP_COMMAND_LIST_MAX) {
    m_commandArray.pop_front();
  }

  return (VSCP_TCPIP_RV_CLOSE != CommandHandler(strCommand));
}

///////////////////////////////////////////////////////////////////////////////
// onPoll
//

void
CTcpipSession::onPoll(void)
{
  if ((nullptr == m_pClientItem) || !isOpen()) {
    return;
  }

  if ((time(NULL) - m_pClientItem->m_clientActivity) > TCPIPSRV_INACTIVITY_TIMEOUT) {
    drvlog::info("[TCP/IP srv] Client {} closed due to inactivity.", getRemoteAddress());
    close();
    return;
  }

  // Binary mode: send events asynchronously once the client has issued OPEN
  if (m_bBinaryMode) {
    while (m_bBinaryOpen && isOpen() && (m_conn->send.len < (256 * 1024))) {
      vscpEvent* pEvent = popEvent();
      if (nullptr == pEvent) {
        break;
      }
      bool ok = sendBinaryEvent(pEvent);
      vscp_deleteEvent_v2(&pEvent);
      if (!ok) {
        close();
        break;
      }
    }
    return;
  }

  if (m_bReceiveLoop) {

    // Don't let the send buffer grow without bound for a slow client
    while ((m_conn->send.len < (256 * 1024)) && sendOneEventFromQueue(false))
      ;

    // Keep alive
    if ((time(NULL) - m_pClientItem->m_timeRcvLoop) > 2) {
      m_pClientItem->m_timeRcvLoop    = time(NULL);
      m_pClientItem->m_clientActivity = (long)time(NULL);
      write("+OK\r\n", 5);
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// onClose
//

void
CTcpipSession::onClose(void)
{
  if (nullptr != m_pClientItem) {
    m_pClientItem->m_bOpen = false;
    pthread_mutex_lock(&m_pObj->m_clientList.m_mutexItemList);
    m_pObj->removeClient(m_pClientItem);
    pthread_mutex_unlock(&m_pObj->m_clientList.m_mutexItemList);
    m_pClientItem = nullptr;
  }
  m_conn = nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// CommandHandler
//

int
CTcpipSession::CommandHandler(std::string& strCommand)
{
  // Must be connected
  if (!isOpen()) {
    return VSCP_TCPIP_RV_ERROR;
  }

  if (NULL == m_pObj) {
    drvlog::error(
      "[TCP/IP srv] ERROR: Control object pointer is NULL in command "
      "handler.");
    return VSCP_TCPIP_RV_CLOSE; // Close connection
  }

  if (NULL == m_pClientItem) {
    drvlog::error(
      "[TCP/IP srv] ERROR: ClientItem pointer is NULL in command handler.");
    return VSCP_TCPIP_RV_CLOSE; // Close connection
  }

  m_pClientItem->m_currentCommand = strCommand;
  vscp_trim(m_pClientItem->m_currentCommand);

  // If nothing to handle just return
  if (0 == m_pClientItem->m_currentCommand.length()) {
    write(MSG_OK, strlen(MSG_OK));
    return VSCP_TCPIP_RV_OK;
  }

  //*********************************************************************
  //                            No Operation
  //*********************************************************************

  if (m_pClientItem->CommandStartsWith(("noop"))) {
    write(MSG_OK, strlen(MSG_OK));
    return VSCP_TCPIP_RV_OK;
  }

  //*********************************************************************
  //                     Binary - switch to binary mode
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("binary"))) {
    handleClientBinary();
  }

  //*********************************************************************
  //                             Rcvloop
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("rcvloop")) ||
           m_pClientItem->CommandStartsWith(("receiveloop"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
      try {
        m_pClientItem->m_timeRcvLoop = time(NULL);
        handleClientRcvLoop();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientRcvLoop");
      }
    }
  }

  //*********************************************************************
  //                             Quitloop
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("quitloop"))) {
    m_bReceiveLoop = false;
    write(MSG_QUIT_LOOP, strlen(MSG_QUIT_LOOP));
  }

  //*********************************************************************
  //                             Username
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("user"))) {
    try {
      handleClientUser();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientUser");
    }
  }

  //*********************************************************************
  //                            Password
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("pass"))) {

    try {
      if (!handleClientPassword()) {
        drvlog::error("[TCP/IP srv] Command: Password. Not authorized.");
        return VSCP_TCPIP_RV_CLOSE; // Close connection
      }
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientPassword");
    }

    drvlog::debug("[TCP/IP srv] Command: Password. OK");
  }

  //*********************************************************************
  //                              Challenge
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("challenge"))) {
    try {
      handleChallenge();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleChallange");
    }
  }

  // *********************************************************************
  //                                 QUIT
  // *********************************************************************

  else if (m_pClientItem->CommandStartsWith("quit") ||
           m_pClientItem->CommandStartsWith("exit")) {
    drvlog::debug("[TCP/IP srv] Command: Close.");
    write(MSG_GOODBY, strlen(MSG_GOODBY));
    return VSCP_TCPIP_RV_CLOSE; // Close connection
  }

  //*********************************************************************
  //                              Shutdown
  //*********************************************************************
  else if (m_pClientItem->CommandStartsWith(("shutdown"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_SHUTDOWN)) {
      try {
        handleClientShutdown();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientShutdown");
      }
    }
  }

  //*********************************************************************
  //                             Send event
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("send"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {
      try {
        handleClientSend();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientSend");
      }
    }
  }

  //*********************************************************************
  //                            Read event
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("retr")) ||
           m_pClientItem->CommandStartsWith(("retrieve"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
      try {
        handleClientReceive();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientReceive");
      }
    }
  }

  //*********************************************************************
  //                            Data Available
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("cdta")) ||
           m_pClientItem->CommandStartsWith(("chkdata")) ||
           m_pClientItem->CommandStartsWith(("checkdata"))) {
    try {
      handleClientDataAvailable();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientDataAvailable");
    }
  }

  //*********************************************************************
  //                          Clear input queue
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("clra")) ||
           m_pClientItem->CommandStartsWith(("clearall")) ||
           m_pClientItem->CommandStartsWith(("clrall"))) {
    try {
      handleClientClearInputQueue();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientClearInputQueue");
    }
  }

  //*********************************************************************
  //                           Get Statistics
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("stat"))) {
    try {
      handleClientGetStatistics();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientGetStatistics");
    }
  }

  //*********************************************************************
  //                            Get Status
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("info"))) {
    try {
      handleClientGetStatus();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientGetStatus");
    }
  }

  //*********************************************************************
  //                           Get Channel ID
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("chid")) ||
           m_pClientItem->CommandStartsWith(("getchid"))) {
    try {
      handleClientGetChannelID();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientGetChannelID");
    }
  }

  //*********************************************************************
  //                          Set Channel GUID
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("sgid")) ||
           m_pClientItem->CommandStartsWith(("setguid"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_SETGUID)) {
      try {
        handleClientSetChannelGUID();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientSetChannelGUID");
      }
    }
  }

  //*********************************************************************
  //                          Get Channel GUID
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("ggid")) ||
           m_pClientItem->CommandStartsWith(("getguid"))) {
    try {
      handleClientGetChannelGUID();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientGetChannelGUID");
    }
  }

  //*********************************************************************
  //                           Get Version
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("version")) ||
           m_pClientItem->CommandStartsWith(("vers"))) {
    try {
      handleClientGetVersion();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientGetVersion");
    }
  }

  //*********************************************************************
  //                           Set Filter
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("sflt")) ||
           m_pClientItem->CommandStartsWith(("setfilter"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_SETFILTER)) {
      try {
        handleClientSetFilter();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientSetFilter");
      }
    }
  }

  //*********************************************************************
  //                           Set Mask
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("smsk")) ||
           m_pClientItem->CommandStartsWith(("setmask"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_SETFILTER)) {
      try {
        handleClientSetMask();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientSetMask");
      }
    }
  }

  //*********************************************************************
  //                             Help
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("help"))) {
    try {
      handleClientHelp();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientHelp");
    }
  }

  //*********************************************************************
  //                             Restart
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("restart"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_RESTART)) {
      try {
        handleClientRestart();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientRestart");
      }
    }
  }

  //*********************************************************************
  //                         Client/interface
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("client")) ||
           m_pClientItem->CommandStartsWith(("interface"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_INTERFACE)) {
      try {
        handleClientInterface();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientInterface");
      }
    }
  }

  //*********************************************************************
  //                               Test
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("test"))) {
    if (checkPrivilege(VSCP_USER_RIGHT_ALLOW_TEST)) {
      try {
        handleClientTest();
      }
      catch (...) {
        drvlog::error("TCPIP: Exception occurred handleClientTest");
      }
    }
  }

  //*********************************************************************
  //                             WhatCanYouDo
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("wcyd")) ||
           m_pClientItem->CommandStartsWith(("whatcanyoudo"))) {
    try {
      handleClientCapabilityRequest();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientCapabilityRequest");
    }
  }

  //*********************************************************************
  //                             Measurement
  //*********************************************************************

  else if (m_pClientItem->CommandStartsWith(("measurement"))) {
    try {
      handleClientMeasurement();
    }
    catch (...) {
      drvlog::error("TCPIP: Exception occurred handleClientMeasurement");
    }
  }

  //*********************************************************************
  //                                What?
  //*********************************************************************
  else {
    write(MSG_UNKNOWN_COMMAND, strlen(MSG_UNKNOWN_COMMAND));
  }

  m_pClientItem->m_lastCommand = m_pClientItem->m_currentCommand;
  return VSCP_TCPIP_RV_OK;

} // clientcommand

///////////////////////////////////////////////////////////////////////////////
// handleClientMeasurement
//
// format,level,vscp-measurement-type,value,unit,guid,sensoridx,zone,subzone,dest-guid
//
// format                   float|string|0|1 - float=0, string=1.
// level                    level2|1|level1|0  1 = VSCP Level I event, 2 = VSCP
// Level II event. vscp-measurement-type    A valid vscp measurement type. value
// A floating point value. (use $ prefix for variable followed by name) unit
// Optional unit for this type. Default = 0. guid                     Optional
// GUID (or "-"). Default is "-". sensoridx                Optional sensor
// index. Default is 0. zone                     Optional zone. Default is 0.
// subzone                  Optional subzone- Default is 0.
// dest-guid                Optional destination GUID. For Level I over Level
// II.
//

void
CTcpipSession::handleClientMeasurement(void)
{
  std::string str;
  double value = 0;
  cguid guid;     // Initialized to zero
  cguid destguid; // Initialized to zero
  long level = VSCP_LEVEL2;
  long unit  = 0;
  long vscptype;
  long sensoridx   = 0;
  long zone        = 0;
  long subzone     = 0;
  long eventFormat = 0; // float
  uint8_t data[VSCP_MAX_DATA];
  uint16_t sizeData;

  // Check object pointer
  if (NULL == m_pObj) {
    write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
    return;
  }

  // Must be connected
  if (!isOpen())
    return;

  if (NULL == m_pClientItem) {
    write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
    return;
  }

  std::deque<std::string> tokens;
  vscp_split(tokens, m_pClientItem->m_currentCommand, ",");

  // * * * event format * * *

  // Get event format (float | string | 0 | 1 - float=0, string=1.)
  if (tokens.empty()) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  str = tokens.front();
  tokens.pop_front();

  vscp_trim(str);
  vscp_makeUpper(str);

  // Handle float=0
  if ('0' == str[0]) {
    eventFormat = 0;
  }
  // Handle string=1
  else if ('1' == str[0]) {
    eventFormat = 1;
  }
  else if (str == "STRING") {
    eventFormat = 1;
  }
  else if (str == "FLOAT") {
    eventFormat = 0;
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // * * * Level * * *

  if (tokens.empty()) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  str = tokens.front();
  tokens.pop_front();

  vscp_trim(str);
  vscp_makeUpper(str);

  if ('0' == str[0]) {
    level = VSCP_LEVEL1;
  }
  else if ('1' == str[0]) {
    level = VSCP_LEVEL2;
  }
  else if (str == "LEVEL1") {
    level = VSCP_LEVEL1;
  }
  else if (str == "LEVEL2") {
    level = VSCP_LEVEL2;
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // * * * vscp-measurement-type * * *
  if (tokens.empty()) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  str = tokens.front();
  tokens.pop_front();
  vscptype = vscp_readStringValue(str);

  // * * * value * * *
  if (tokens.empty()) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  str = tokens.front();
  tokens.pop_front();
  vscp_trim(str);

  value = std::stod(str);

  // * * * unit * * *

  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    unit = vscp_readStringValue(str);
  }

  // * * * guid * * *

  if (!tokens.empty()) {

    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);

    // If empty set to default.
    if (0 == str.length())
      str = "-";
    guid.getFromString(str);
  }

  // * * * sensor index * * *

  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);

    sensoridx = vscp_readStringValue(str);
  }

  // * * * zone * * *

  if (!tokens.empty()) {

    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);

    zone = vscp_readStringValue(str);
    ;
    zone &= 0xff;
  }

  // * * * subzone * * *

  if (!tokens.empty()) {

    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);

    subzone = vscp_readStringValue(str);
    subzone &= 0xff;
  }

  // * * * destguid * * *

  if (!tokens.empty()) {

    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);

    // If empty set to default.
    if (0 == str.length())
      str = ("-");
    destguid.getFromString(str);
  }

  // Range checks
  if (VSCP_LEVEL1 == level) {
    if (unit > 3)
      unit = 0;
    if (sensoridx > 7)
      unit = 0;
    if (vscptype > 512)
      vscptype -= 512;
  }
  else { // VSCP_LEVEL2
    if (unit > 255)
      unit &= 0xff;
    if (sensoridx > 255)
      sensoridx &= 0xff;
  }

  if (1 == level) { // Level I

    if (0 == eventFormat) {

      // * * * Floating point * * *

      if (vscp_convertFloatToFloatEventData(data,
                                            &sizeData,
                                            (float)value,
                                            (uint8_t)unit,
                                            (uint8_t)sensoridx)) {
        if (sizeData > 8)
          sizeData = 8;

        vscpEvent* pEvent = new vscpEvent;
        if (NULL == pEvent) {
          write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
          return;
        }

        pEvent->pdata     = NULL;
        pEvent->head      = VSCP_PRIORITY_NORMAL;
        pEvent->timestamp = 0; // Let interface fill in
                               // Will fill in date/time block also
        guid.writeGUID(pEvent->GUID);
        pEvent->sizeData = sizeData;
        if (sizeData > 0) {
          pEvent->pdata = new uint8_t[sizeData];
          memcpy(pEvent->pdata, data, sizeData);
        }
        pEvent->vscp_class = VSCP_CLASS1_MEASUREMENT;
        pEvent->vscp_type  = (uint16_t)vscptype;

        // send the event
        if (!m_pObj->addEvent2SendQueue(pEvent)) {
          vscp_deleteEvent_v2(&pEvent);
          write(MSG_UNABLE_TO_SEND_EVENT, strlen(MSG_UNABLE_TO_SEND_EVENT));
          return;
        }

        vscp_deleteEvent_v2(&pEvent);
      }
      else {
        write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
      }
    }
    else {

      // * * * String * * *

      vscpEvent* pEvent = new vscpEvent;
      if (NULL == pEvent) {
        write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
        return;
      }

      pEvent->pdata = NULL;

      if (!vscp_makeStringMeasurementEvent(pEvent,
                                           value,
                                           (uint8_t)unit,
                                           (uint8_t)sensoridx)) {
        write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
      }

      // TODO have to send also
    }
  }
  else { // Level II

    if (0 == eventFormat) { // float and Level II

      // * * * Floating point * * *

      vscpEvent* pEvent = new vscpEvent;
      if (NULL == pEvent) {
        write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
        return;
      }

      pEvent->pdata = NULL;

      pEvent->obid      = 0;
      pEvent->head      = VSCP_PRIORITY_NORMAL;
      pEvent->timestamp = 0; // Let interface fill in timestamp
                             // Will fill in date/time block also
      guid.writeGUID(pEvent->GUID);
      pEvent->head       = 0;
      pEvent->vscp_class = VSCP_CLASS2_MEASUREMENT_FLOAT;
      pEvent->vscp_type  = (uint16_t)vscptype;
      pEvent->sizeData   = 12;

      data[0] = (uint8_t)sensoridx;
      data[1] = (uint8_t)zone;
      data[2] = (uint8_t)subzone;
      data[3] = (uint8_t)unit;

      memcpy(data + 4, (uint8_t*)&value, 8); // copy in double
      uint64_t temp = VSCP_UINT64_SWAP_ON_LE(*(data + 4));
      memcpy(data + 4, (void*)&temp, 8);

      // Copy in data
      pEvent->pdata = new uint8_t[4 + 8];
      if (NULL == pEvent->pdata) {
        write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
        delete pEvent;
        return;
      }

      memcpy(pEvent->pdata, data, 4 + 8);

      // send the event
      if (!m_pObj->addEvent2SendQueue(pEvent)) {
        vscp_deleteEvent_v2(&pEvent);
        write(MSG_UNABLE_TO_SEND_EVENT, strlen(MSG_UNABLE_TO_SEND_EVENT));
        return;
      }

      vscp_deleteEvent_v2(&pEvent);
    }
    else { // string & Level II

      // * * * String * * *

      vscpEvent* pEvent = new vscpEvent;
      pEvent->pdata     = NULL;

      pEvent->obid      = 0;
      pEvent->head      = VSCP_PRIORITY_NORMAL;
      pEvent->timestamp = 0; // Let interface fill in
                             // Will fill in date/time block also
      guid.writeGUID(pEvent->GUID);
      pEvent->head       = 0;
      pEvent->vscp_class = VSCP_CLASS2_MEASUREMENT_STR;
      pEvent->vscp_type  = (uint16_t)vscptype;
      pEvent->sizeData   = 12;

      std::string strValue = vscp_str_format("%f", value);

      data[0] = (uint8_t)sensoridx;
      data[1] = (uint8_t)zone;
      data[2] = (uint8_t)subzone;
      data[3] = (uint8_t)unit;

      pEvent->pdata = new uint8_t[4 + strValue.length()];
      if (NULL == pEvent->pdata) {
        write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
        delete pEvent;
        return;
      }
      memcpy(data + 4, strValue.c_str(),
             strValue.length()); // copy in double

      // send the event
      if (!m_pObj->addEvent2SendQueue(pEvent)) {
        vscp_deleteEvent_v2(&pEvent);
        write(MSG_UNABLE_TO_SEND_EVENT, strlen(MSG_UNABLE_TO_SEND_EVENT));
        return;
      }

      vscp_deleteEvent_v2(&pEvent);
    }
  }

  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientCapabilityRequest
//

void
CTcpipSession::handleClientCapabilityRequest(void)
{
  std::string str;
  uint64_t capabilities = getCapabilities();

  str = vscp_str_format("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\r\n",
                        (capabilities >> 56) & 0xff,
                        (capabilities >> 48) & 0xff,
                        (capabilities >> 40) & 0xff,
                        (capabilities >> 32) & 0xff,
                        (capabilities >> 24) & 0xff,
                        (capabilities >> 16) & 0xff,
                        (capabilities >> 8) & 0xff,
                        (capabilities >> 0) & 0xff);
  write(str.c_str(), str.length());
  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// isVerified
//

bool
CTcpipSession::isVerified(void)
{
  // Check object
  if (NULL == m_pObj) {
    return false;
  }

  // Must be connected
  if (!isOpen())
    return false;

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// checkPrivilege
//

bool
CTcpipSession::checkPrivilege(unsigned long reqiredPrivilege)
{
  // Check objects
  if (NULL == m_pObj) {
    return false;
  }

  // Must be connected
  if (!isOpen()) {
    return false;
  }

  // Must be authenticated
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return false;
  }

  // Must be accredited
  if (NULL == m_pClientItem->m_pUserItem) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return false;
  }

  // Check the privileges
  if (!(m_pClientItem->m_pUserItem->getUserRights() & reqiredPrivilege)) {
    write(MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
    return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSend
//

void
CTcpipSession::handleClientSend(void)
{
  vscpEvent event;
  memset(&event, 0, sizeof(event));

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Set timestamp block for event
  vscp_setEventDateTimeBlockToNow(&event); // TODO - change to UTC

  if (NULL == m_pObj) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  if (NULL == m_pClientItem) {
    write(MSG_INTERNAL_ERROR, strlen(MSG_INTERNAL_ERROR));
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  std::string str;
  std::deque<std::string> tokens;
  vscp_split(tokens, m_pClientItem->m_currentCommand, ",");

  // If first character is $ user request us to send content from
  // a variable

  if (!tokens.empty()) {
    // Get Head
    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);
    event.head = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Class
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    event.vscp_class = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Type
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    event.vscp_type = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get OBID  -  Kept here to be compatible with receive
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    event.obid = vscp_readStringValue(str);
    if (0 == event.obid) {
      event.obid = m_pClientItem->m_clientID;
    }
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get date/time - can be empty
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);
    if (str.length()) {
      vscpdatetime dt;
      if (dt.set(str)) {
        event.year   = dt.getYear();
        event.month  = dt.getMonth();
        event.day    = dt.getDay();
        event.hour   = dt.getHour();
        event.minute = dt.getMinute();
        event.second = dt.getSecond();
      }
      else {
        vscp_setEventDateTimeBlockToNow(&event);
      }
    }
    else {
      // set current time
      vscp_setEventDateTimeBlockToNow(&event);
    }
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Timestamp - can be empty
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);
    if (str.length()) {
      event.timestamp = vscp_readStringValue(str);
    }
    else {
      event.timestamp = vscp_makeTimeStamp();
    }
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get GUID
  std::string strGUID;
  if (!tokens.empty()) {

    strGUID = tokens.front();
    tokens.pop_front();

    // Check if i/f GUID should be used
    if ('-' == strGUID[0]) {
      // Copy in the i/f GUID
      m_pClientItem->m_guid.writeGUID(event.GUID);
    }
    else {
      vscp_setEventGuidFromString(&event, strGUID);

      // Check if i/f GUID should be used
      if (true == vscp_isGUIDEmpty(event.GUID)) {
        // Copy in the i/f GUID
        m_pClientItem->m_guid.writeGUID(event.GUID);
      }
    }
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Handle data
  if (VSCP_MAX_DATA < tokens.size()) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  event.sizeData = (uint16_t)tokens.size();

  if (event.sizeData > 0) {

    unsigned int index = 0;

    event.pdata = new uint8_t[event.sizeData];

    if (NULL == event.pdata) {
      write(MSG_INTERNAL_MEMORY_ERROR, strlen(MSG_INTERNAL_MEMORY_ERROR));
      return;
    }

    while (!tokens.empty() && (event.sizeData > index)) {
      str = tokens.front();
      tokens.pop_front();
      event.pdata[index++] = vscp_readStringValue(str);
    }

    if (!tokens.empty()) {
      write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));

      delete[] event.pdata;
      event.pdata = NULL;
      return;
    }
  }
  else {
    // No data
    event.pdata = NULL;
  }

  // Check if we are allowed to send CLASS1.PROTOCOL events
  if ((VSCP_CLASS1_PROTOCOL == event.vscp_class) &&
      !checkPrivilege(VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

    std::string strErr = vscp_str_format(
      ("[TCP/IP srv] User [{%s}] not allowed to send event class=%d "
       "type=%d.\n"),
      m_pClientItem->m_pUserItem->getUserName().c_str(),
      event.vscp_class,
      event.vscp_type);
    drvlog::error("{}", strErr);
    write(MSG_MOT_ALLOWED_TO_SEND_EVENT, strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

    if (NULL != event.pdata) {
      delete[] event.pdata;
      event.pdata = NULL;
    }

    return;
  }

  // Check if we are allowed top send CLASS1.PROTOCOL events
  if ((VSCP_CLASS1_PROTOCOL == event.vscp_class) &&
      !checkPrivilege(VSCP_CLASS2_LEVEL1_PROTOCOL)) {

    std::string strErr = vscp_str_format(
      ("[TCP/IP srv] User [{}] not allowed to send event class={} "
       "type={}.\n"),
      m_pClientItem->m_pUserItem->getUserName().c_str(),
      event.vscp_class,
      event.vscp_type);
    drvlog::error("{}", strErr);
    write(MSG_MOT_ALLOWED_TO_SEND_EVENT, strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

    if (NULL != event.pdata) {
      delete[] event.pdata;
      event.pdata = NULL;
    }

    return;
  }

  // Check if we are allowed top send CLASS2.PROTOCOL events
  if ((VSCP_CLASS2_PROTOCOL == event.vscp_class) &&
      !checkPrivilege(VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

    std::string strErr = vscp_str_format(
      ("[TCP/IP srv] User [%s] not allowed to send event class=%d "
       "type=%d."),
      m_pClientItem->m_pUserItem->getUserName().c_str(),
      event.vscp_class,
      event.vscp_type);
    drvlog::error("{}", strErr);
    write(MSG_MOT_ALLOWED_TO_SEND_EVENT, strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

    if (NULL != event.pdata) {
      delete[] event.pdata;
      event.pdata = NULL;
    }

    return;
  }

  // Check if we are allowed top send CLASS2.HLO events
  if ((VSCP_CLASS2_HLO == event.vscp_class) &&
      !checkPrivilege(VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

    std::string strErr = vscp_str_format(
      ("[TCP/IP srv] User [{}] not allowed to send event class={} "
       "type={}."),
      (const char*)m_pClientItem->m_pUserItem->getUserName().c_str(),
      event.vscp_class,
      event.vscp_type);
    drvlog::error("{}", strErr);
    write(MSG_MOT_ALLOWED_TO_SEND_EVENT, strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

    if (NULL != event.pdata) {
      delete[] event.pdata;
      event.pdata = NULL;
    }

    return;
  }

  // Check if this user is allowed to send this event
  if (!m_pClientItem->m_pUserItem->isUserAllowedToSendEvent(event.vscp_class,
                                                            event.vscp_type)) {

    std::string strErr = vscp_str_format(
      "[TCP/IP srv] User [{}] not allowed to send event class={} type={}.",
      (const char*)m_pClientItem->m_pUserItem->getUserName().c_str(),
      event.vscp_class,
      event.vscp_type);
    drvlog::error("{}", strErr);
    write(MSG_MOT_ALLOWED_TO_SEND_EVENT, strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

    if (NULL != event.pdata) {
      delete[] event.pdata;
      event.pdata = NULL;
    }

    return;
  }

  vscpEvent* pNewEvent = new vscpEvent;
  memset(pNewEvent, 0, sizeof(vscpEvent));
  bool bCopied = vscp_copyEvent(pNewEvent, &event);
  vscp_deleteEvent(&event); // The queue gets its own copy of the data

  // send event
  if (!bCopied || !m_pObj->addEvent2ReceiveQueue(pNewEvent)) {
    vscp_deleteEvent_v2(&pNewEvent); // Deallocate event
    write(MSG_BUFFER_FULL, strlen(MSG_BUFFER_FULL));
    return;
  }

  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientReceive
//

void
CTcpipSession::handleClientReceive(void)
{
  unsigned short cnt = 0; // # of messages to read

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  std::string str;
  cnt = vscp_readStringValue(m_pClientItem->m_currentCommand);

  if (!cnt) {
    cnt = 1; // No arg is "read one"
  }

  // Read cnt messages
  while (cnt) {

    std::string strOut;

    if (!m_pClientItem->m_bOpen) {
      write(MSG_NO_MSG, strlen(MSG_NO_MSG));
      return;
    }
    else {
      if (!sendOneEventFromQueue()) {
        return;
      }
    }

    cnt--;

  } // while

  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// sendOneEventFromQueue
//

bool
CTcpipSession::sendOneEventFromQueue(bool bStatusMsg)
{
  std::string strOut;

  // Must be connected
  if (!isOpen()) {
    return false;
  }

  if (m_pClientItem->m_clientInputQueue.size()) {

    vscpEvent* pqueueEvent;
    pthread_mutex_lock(&m_pClientItem->m_mutexClientInputQueue);
    {
      pqueueEvent = m_pClientItem->m_clientInputQueue.front();
      m_pClientItem->m_clientInputQueue.pop_front();
    }
    pthread_mutex_unlock(&m_pClientItem->m_mutexClientInputQueue);

    // [[clientid == obid]] is used to detect our own events
    if (m_pObj->m_bReceiveOwnEvents || (pqueueEvent->obid != m_pClientItem->m_clientID)) {
      vscp_convertEventToString(strOut, pqueueEvent);
      strOut += ("\r\n");
      write(strOut.c_str(), strlen(strOut.c_str()));
    }

    vscp_deleteEvent_v2(&pqueueEvent);
  }
  else {
    if (bStatusMsg) {
      write(MSG_NO_MSG, strlen(MSG_NO_MSG));
    }

    return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientDataAvailable
//

void
CTcpipSession::handleClientDataAvailable(void)
{
  char outbuf[1024];

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  snprintf(outbuf,
           sizeof(outbuf),
           "%zd\r\n%s",
           m_pClientItem->m_clientInputQueue.size(),
           MSG_OK);
  write(outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientClearInputQueue
//

void
CTcpipSession::handleClientClearInputQueue(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  pthread_mutex_lock(&m_pClientItem->m_mutexClientInputQueue);
  std::deque<vscpEvent*>::iterator iter;
  for (iter = m_pClientItem->m_clientInputQueue.begin();
       iter != m_pClientItem->m_clientInputQueue.end();
       ++iter) {
    vscpEvent* pEvent = *iter;
    vscp_deleteEvent_v2(&pEvent);
  }
  m_pClientItem->m_clientInputQueue.clear();
  pthread_mutex_unlock(&m_pClientItem->m_mutexClientInputQueue);

  write(MSG_QUEUE_CLEARED, strlen(MSG_QUEUE_CLEARED));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetStatistics
//

void
CTcpipSession::handleClientGetStatistics(void)
{
  char outbuf[1024];

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  snprintf(outbuf,
           sizeof(outbuf),
           "%lu,%lu,%lu,%lu,%lu,%lu,%lu\r\n%s",
           m_pClientItem->m_statistics.cntBusOff,
           m_pClientItem->m_statistics.cntBusWarnings,
           m_pClientItem->m_statistics.cntOverruns,
           m_pClientItem->m_statistics.cntReceiveData,
           m_pClientItem->m_statistics.cntReceiveFrames,
           m_pClientItem->m_statistics.cntTransmitData,
           m_pClientItem->m_statistics.cntTransmitFrames,
           MSG_OK);

  write(outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetStatus
//

void
CTcpipSession::handleClientGetStatus(void)
{
  char outbuf[1024];

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  snprintf(outbuf,
           sizeof(outbuf),
           "%lu,%lu,%lu,\"%s\"\r\n%s",
           m_pClientItem->m_status.channel_status,
           m_pClientItem->m_status.lasterrorcode,
           m_pClientItem->m_status.lasterrorsubcode,
           m_pClientItem->m_status.lasterrorstr,
           MSG_OK);

  write(outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetChannelID
//

void
CTcpipSession::handleClientGetChannelID(void)
{
  char outbuf[1024];

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  snprintf(outbuf,
           sizeof(outbuf),
           "%lu\r\n%s",
           (unsigned long)m_pClientItem->m_clientID,
           MSG_OK);

  write(outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSetChannelGUID
//

void
CTcpipSession::handleClientSetChannelGUID(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  vscp_trim(m_pClientItem->m_currentCommand);

  m_pClientItem->m_guid.getFromString(m_pClientItem->m_currentCommand);
  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetChannelGUID
//

void
CTcpipSession::handleClientGetChannelGUID(void)
{
  std::string strBuf;

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  m_pClientItem->m_guid.toString(strBuf);
  strBuf += std::string("\r\n");
  strBuf += std::string(MSG_OK);

  write(strBuf);
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetVersion
//

void
CTcpipSession::handleClientGetVersion(void)
{
  char outbuf[1024];

  // Must be connected
  if (!isOpen()) {
    return;
  }

  snprintf(outbuf,
           sizeof(outbuf),
           "%d,%d,%d,%d\r\n%s",
           MAJOR_VERSION,
           MINOR_VERSION,
           RELEASE_VERSION,
           BUILD_VERSION,
           MSG_OK);

  write(outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSetFilter
//

void
CTcpipSession::handleClientSetFilter(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  std::string str;
  vscp_trim(m_pClientItem->m_currentCommand);
  std::deque<std::string> tokens;
  vscp_split(tokens, m_pClientItem->m_currentCommand, ",");

  // Get priority
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    m_pClientItem->m_filter.filter_priority = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Class
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    m_pClientItem->m_filter.filter_class = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Type
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    m_pClientItem->m_filter.filter_type = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get GUID
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    vscp_getGuidFromStringToArray(m_pClientItem->m_filter.filter_GUID, str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSetMask
//

void
CTcpipSession::handleClientSetMask(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Must be accredited to do this
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
    return;
  }

  std::string str;
  vscp_trim(m_pClientItem->m_currentCommand);
  std::deque<std::string> tokens;
  vscp_split(tokens, m_pClientItem->m_currentCommand, ",");

  // Get priority
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    m_pClientItem->m_filter.mask_priority = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Class
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    m_pClientItem->m_filter.mask_class = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get Type
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    m_pClientItem->m_filter.mask_type = vscp_readStringValue(str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  // Get GUID
  if (!tokens.empty()) {
    str = tokens.front();
    tokens.pop_front();
    vscp_getGuidFromStringToArray(m_pClientItem->m_filter.mask_GUID, str);
  }
  else {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  write(MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientUser
//

void
CTcpipSession::handleClientUser(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  if (m_pClientItem->bAuthenticated) {
    write(MSG_OK, strlen(MSG_OK));
    return;
  }

  m_pClientItem->m_UserName = m_pClientItem->m_currentCommand;
  vscp_trim(m_pClientItem->m_UserName);
  if (m_pClientItem->m_UserName.empty()) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  write(MSG_USENAME_OK, strlen(MSG_USENAME_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientPassword
//

bool
CTcpipSession::handleClientPassword(void)
{
  // Must be connected
  if (!isOpen()) {
    return false;
  }

  if (m_pClientItem->bAuthenticated) {
    write(MSG_OK, strlen(MSG_OK));
    return true;
  }

  // Must have username before password can be entered.
  if (0 == m_pClientItem->m_UserName.length()) {
    write(MSG_NEED_USERNAME, strlen(MSG_NEED_USERNAME));
    return true;
  }

  std::string strPassword = m_pClientItem->m_currentCommand;
  vscp_trim(strPassword);

  if (strPassword.empty()) {
    m_pClientItem->m_UserName = ("");
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return false;
  }

  pthread_mutex_lock(&m_pObj->m_mutex_UserList);
  m_pClientItem->m_pUserItem =
    m_pObj->m_userList.validateUser(m_pClientItem->m_UserName, strPassword);
  pthread_mutex_unlock(&m_pObj->m_mutex_UserList);

  if (NULL == m_pClientItem->m_pUserItem) {

    std::string strErr =
      vscp_str_format(("[TCP/IP srv] User [%s][%s] not allowed to connect.\n"),
                      (const char*)m_pClientItem->m_UserName.c_str(),
                      (const char*)strPassword.c_str());
    drvlog::error("{}", strErr);
    write(MSG_PASSWORD_ERROR, strlen(MSG_PASSWORD_ERROR));
    return false;
  }

  // Get remote address
  std::string remoteaddr = getRemoteAddress();

  // Check if this user is allowed to connect from this location. The user
  // list holds IPv4 rules, so an IPv6 peer must be IPv4 mapped to match.
  uint32_t remote_ip4 = 0;
  if (!m_conn->rem.is_ip6) {
    remote_ip4 = m_conn->rem.addr.ip4;
  }
  else {
    static const uint8_t v4mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (0 == memcmp(m_conn->rem.addr.ip, v4mapped, sizeof(v4mapped))) {
      memcpy(&remote_ip4, m_conn->rem.addr.ip + 12, 4);
    }
  }
  pthread_mutex_lock(&m_pObj->m_mutex_UserList);
  bool bValidHost = (1 == m_pClientItem->m_pUserItem->isAllowedToConnect(remote_ip4));
  pthread_mutex_unlock(&m_pObj->m_mutex_UserList);

  if (!bValidHost) {
    std::string strErr =
      vscp_str_format(("[TCP/IP srv] Host [%s] not allowed to connect.\n"),
                      (const char*)remoteaddr.c_str());
    drvlog::error("{}", strErr);
    write(MSG_INVALID_REMOTE_ERROR, strlen(MSG_INVALID_REMOTE_ERROR));
    return false;
  }

  // Copy in the user filter
  memcpy(&m_pClientItem->m_filter,
         m_pClientItem->m_pUserItem->getUserFilter(),
         sizeof(vscpEventFilter));

  std::string strErr =
    vscp_str_format(("[TCP/IP srv] Host [%s] User [%s] allowed to connect.\n"),
                    (const char*)remoteaddr.c_str(),
                    (const char*)m_pClientItem->m_UserName.c_str());
  drvlog::info("{}", strErr);
  m_pClientItem->bAuthenticated = true;
  write(MSG_OK, strlen(MSG_OK));

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleChallenge
//

void
CTcpipSession::handleChallenge(void)
{
  std::string str;

  // Must be connected
  if (!isOpen()) {
    return;
  }

  vscp_trim(m_pClientItem->m_currentCommand);

  memset(m_pClientItem->m_sid, 0, sizeof(m_pClientItem->m_sid));
  if (!m_pObj->generateSessionId(m_pClientItem->m_currentCommand.c_str(),
                                 m_pClientItem->m_sid)) {
    write(MSG_FAILED_TO_GENERATE_SID, strlen(MSG_FAILED_TO_GENERATE_SID));
    return;
  }

  str = std::string("+OK - ") + std::string(m_pClientItem->m_sid) +
        std::string("\r\n");
  write(str);
}

///////////////////////////////////////////////////////////////////////////////
// handleClientRcvLoop
//

void
CTcpipSession::handleClientRcvLoop(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  write(MSG_RECEIVE_LOOP, strlen(MSG_RECEIVE_LOOP));
  m_bReceiveLoop = true; // Mark connection as being in receive loop

  m_pClientItem->m_readBuffer = "";
  return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientTest
//

void
CTcpipSession::handleClientTest(void)
{
  write(MSG_OK, strlen(MSG_OK));
  return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientRestart
//

void
CTcpipSession::handleClientRestart(void)
{
  write(MSG_COMMAND_NOT_SUPPORTED, strlen(MSG_COMMAND_NOT_SUPPORTED));
#ifndef WIN32
  // sleep(1);
  // kill(getpid(), SIGUSR2);
#else
  Sleep(1000);
#endif

  return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientShutdown
//

void
CTcpipSession::handleClientShutdown(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  drvlog::debug("tcp/ip client requested shutdown!!!");
  if (!m_pClientItem->bAuthenticated) {
    write(MSG_OK, strlen(MSG_OK));
  }

  write(MSG_COMMAND_NOT_SUPPORTED, strlen(MSG_COMMAND_NOT_SUPPORTED));

#ifndef WIN32
  // sleep(1);
  // kill(getpid(), SIGUSR1);
#endif
}

///////////////////////////////////////////////////////////////////////////////
// handleClientRemote
//

void
CTcpipSession::handleClientRemote(void)
{
  return;
}

// -----------------------------------------------------------------------------
//                            I N T E R F A C E
// -----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface
//
// list     List interfaces.
// unique   Acquire selected interface uniquely. Full format is INTERFACE UNIQUE
// id normal   Normal access to interfaces. Full format is INTERFACE NORMAL id
// close    Close interfaces. Full format is INTERFACE CLOSE id

void
CTcpipSession::handleClientInterface(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  if (m_pClientItem->CommandStartsWith(("list"))) {
    handleClientInterface_List();
  }
  else if (m_pClientItem->CommandStartsWith(("unique"))) {
    handleClientInterface_Unique();
  }
  else if (m_pClientItem->CommandStartsWith(("normal"))) {
    handleClientInterface_Normal();
  }
  else if (m_pClientItem->CommandStartsWith(("close"))) {
    handleClientInterface_Close();
  }
  else {
    handleClientInterface_List();
  }
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_List
//

void
CTcpipSession::handleClientInterface_List(void)
{
  std::string strGUID;
  std::string strBuf;

  // Display Interface List
  pthread_mutex_lock(&m_pObj->m_clientList.m_mutexItemList);

  std::deque<CClientItem*>::iterator it;
  for (it = m_pObj->m_clientList.m_itemList.begin();
       it != m_pObj->m_clientList.m_itemList.end();
       ++it) {

    CClientItem* pItem = *it;

    pItem->m_guid.toString(strGUID);
    strBuf = vscp_str_format("%d,", pItem->m_clientID);
    strBuf += vscp_str_format("%d,", pItem->m_type);
    strBuf += strGUID;
    strBuf += std::string(",");
    strBuf += pItem->m_strDeviceName;
    strBuf += std::string(" | Started at ");
    strBuf += pItem->m_dtutc.getISODateTime();
    strBuf += std::string("\r\n");

    write(strBuf);
  }

  write(MSG_OK, strlen(MSG_OK));

  pthread_mutex_unlock(&m_pObj->m_clientList.m_mutexItemList);
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_Unique
//

void
CTcpipSession::handleClientInterface_Unique(void)
{
  unsigned char ifGUID[16];
  memset(ifGUID, 0, 16);

  // Must be connected
  if (!isOpen()) {
    return;
  }

  // Get GUID
  vscp_trim(m_pClientItem->m_currentCommand);
  vscp_getGuidFromStringToArray(ifGUID, m_pClientItem->m_currentCommand);

  // Add the client to the Client List
  // TODO

  write(MSG_INTERFACE_NOT_FOUND, strlen(MSG_INTERFACE_NOT_FOUND));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_Normal
//

void
CTcpipSession::handleClientInterface_Normal(void)
{
  // TODO
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_Close
//

void
CTcpipSession::handleClientInterface_Close(void)
{
  // TODO
}

// -----------------------------------------------------------------------------
//                          E N D   I N T E R F A C E
// -----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// handleClientHelp
//

void
CTcpipSession::handleClientHelp(void)
{
  // Must be connected
  if (!isOpen()) {
    return;
  }

  vscp_trim(m_pClientItem->m_currentCommand);

  if (0 == m_pClientItem->m_currentCommand.length()) {

    std::string str = "Help for the VSCP tcp/ip interface\r\n";
    str += "=============================================================="
           "======\r\n";
    str += "To get more information about a specific command issue 'HELP "
           "command'\r\n";
    str += "+                 - Repeat last command.\r\n";
    str += "+n                - Repeat command 'n' (0 is last).\r\n";
    str += "++                - List repeatable commands.\r\n";
    str += "NOOP              - No operation. Does nothing.\r\n";
    str += "QUIT              - Close the connection.\r\n";
    str += "USER 'username'   - Username for login. \r\n";
    str += "PASS 'password'   - Password for login.  \r\n";
    str += "CHALLENGE 'token' - Get session id.  \r\n";
    str += "SEND 'event'      - Send an event.   \r\n";
    str += "RETR 'count'      - Retrive n events from input queue.   \r\n";
    str += "RCVLOOP           - Will retrieve events in an endless loop until "
           "the connection is closed by the client or QUITLOOP is sent.\r\n";
    str += "QUITLOOP          - Terminate RCVLOOP.\r\n";
    str += "CDTA/CHKDATA      - Check if there is data in the input "
           "queue.\r\n";
    str += "CLRA/CLRALL       - Clear input queue.\r\n";
    str += "STAT              - Get statistical information.\r\n";
    str += "INFO              - Get status info.\r\n";
    str += "CHID              - Get channel id.\r\n";
    str += "SGID/SETGUID      - Set GUID for channel.\r\n";
    str += "GGID/GETGUID      - Get GUID for channel.\r\n";
    str += "VERS/VERSION      - Get VSCP daemon version.\r\n";
    str += "SFLT/SETFILTER    - Set incoming event filter.\r\n";
    str += "SMSK/SETMASK      - Set incoming event mask.\r\n";
    str += "HELP [command]    - This command.\r\n";
    str += "TEST              - Do test sequence. Only used for "
           "debugging.\r\n";
    str += "SHUTDOWN          - Shutdown the daemon.\r\n";
    str += "RESTART           - Restart the daemon.\r\n";
    str += "INTERFACE         - Interface handling. \r\n";
    str += "WCYD/WHATCANYOUDO - Check server capabilities. \r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("+")) {
    std::string str = "'+' repeats the last given command.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("noop")) {
    std::string str =
      "'NOOP' Does absolutely nothing but giving a success in return.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("quit"))) {
    std::string str = "'QUIT' Quit a session with the VSCP daemon and "
                      "closes the m_connection.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("user"))) {
    std::string str =
      "'USER' Used to login to the system together with PASS. Connection "
      "will be closed if bad credentials are given.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("pass"))) {
    std::string str =
      "'PASS' Used to login to the system together with USER. Connection "
      "will be closed if bad credentials are given.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("quit"))) {
    std::string str = "'QUIT' Quit a session with the VSCP daemon and "
                      "closes the m_connection.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("send"))) {
    std::string str = "'SEND event'.\r\nThe event is given as "
                      "'head,class,type,obid,datetime,time-stamp,GUID,"
                      "data1,data2,data3....' \r\n";
    str += "Normally set 'head' and 'obid' to zero. \r\nIf timestamp is set to "
           "zero it will be set by the server. \r\nIf GUID is given as '-' ";
    str += "the GUID of the interface will be used. \r\nThe GUID should "
           "be given on the form MSB-byte:MSB-byte-1:MSB-byte-2. \r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("retr"))) {
    std::string str = "'RETR count' - Retrieve one (if no argument) or "
                      "'count' event(s). ";
    str += "Events are retrived on the form "
           "head,class,type,obid,datetime,time-stamp,GUID,data0,data1,"
           "data2,...........\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("rcvloop")) {
    std::string str = "'RCVLOOP' - Enter the receive loop and receive "
                      "events continuously or until ";
    str += "terminated with 'QUITLOOP'. Events are retrived on the form "
           "head,class,type,obid,time-stamp,GUID,data0,data1,data2,......."
           "....\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("quitloop"))) {
    std::string str = "'QUITLOOP' - End 'RCVLOOP' event receives.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("cdta") ||
           m_pClientItem->CommandStartsWith("chkdata")) {
    std::string str = "'CDTA' or 'CHKDATA' - Check if there is events in "
                      "the input queue.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("clra")) ||
           m_pClientItem->CommandStartsWith(("clrall"))) {
    std::string str = "'CLRA' or 'CLRALL' - Clear input queue.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("stat"))) {
    std::string str = "'STAT' - Get statistical information.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("info")) {
    std::string str = "'INFO' - Get status information.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("chid") ||
           m_pClientItem->CommandStartsWith("getchid")) {
    std::string str = "'CHID' or 'GETCHID' - Get channel id.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("sgid") ||
           m_pClientItem->CommandStartsWith("setguid")) {
    std::string str = "'SGID' or 'SETGUID' - Set GUID for channel.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("ggid") ||
           m_pClientItem->CommandStartsWith("getguid")) {
    std::string str = ("'GGID' or 'GETGUID' - Get GUID for channel.\r\n");
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("vers") ||
           m_pClientItem->CommandStartsWith("version")) {
    std::string str = "'VERS' or 'VERSION' - Get version of VSCP daemon.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("sflt") ||
           m_pClientItem->CommandStartsWith("setfilter")) {
    std::string str = "'SFLT' or 'SETFILTER' - Set filter for channel. ";
    str += "The format is 'filter-priority, filter-class, filter-type, "
           "filter-GUID' \r\n";
    str += "Example:  \r\nSETFILTER "
           "1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:"
           "00\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("smsk") ||
           m_pClientItem->CommandStartsWith("setmask")) {
    std::string str = "'SMSK' or 'SETMASK' - Set mask for channel. ";
    str += "The format is 'mask-priority, mask-class, mask-type, "
           "mask-GUID' \r\n";
    str += "Example:  \r\nSETMASK "
           "0x0f,0xffff,0x00ff,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:"
           "00:00 \r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith(("help"))) {
    std::string str = "'HELP [command]' This command. Gives help about "
                      "available commands and the usage.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("test")) {
    std::string str = "'TEST [sequency]' Test command for debugging.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("shutdown")) {
    std::string str =
      "'SHUTDOWN' Shutdown the daemon (not supported here).\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("restart")) {
    std::string str = "'RESTART' Restart the daemon (not supported here).\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("interface")) {
    std::string str = "'INTERFACE' Handle interfaces on the daemon.\r\n";
    str += "'INTERFACE list'.\r\n";
    str += "'INTERFACE close'.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else if (m_pClientItem->CommandStartsWith("wcyd") ||
           m_pClientItem->CommandStartsWith("whatcanyoudo")) {
    std::string str = "'WCYD/WHATCANYOUDO' Return the VSCP server "
                      "capabilities 64-bit array.\r\n";
    write((const char*)str.c_str(), str.length());
  }
  else {
    std::string str = vscp_str_format("The command '%s' is not available\r\n",
                                      m_pClientItem->m_currentCommand.c_str());
    write((const char*)str.c_str(), str.length());
  }

  write(MSG_OK, strlen(MSG_OK));
  return;
}


// ----------------------------------------------------------------------------
//                            B I N A R Y   M O D E
// ----------------------------------------------------------------------------
//
// After the text command BINARY the connection carries records
// [0x55][version:3 | length:13, big-endian][frame], see the VSCP general
// binary protocol. Plain records are version 0, authenticated records
// version 1.
// If the driver is configured with binary encryption every frame is a
// version 1 authenticated frame (AES-CBC + HMAC-SHA-256), and any record
// that fails authentication, or is not authenticated, closes the
// connection. Without binary encryption only plain frames are accepted.
//

namespace {
const uint8_t BINARY_SYNC_BYTE             = 0x55;
const size_t BINARY_PREFIX_LENGTH          = 3;
const size_t BINARY_MAX_RECORD_LENGTH      = 0x1fff; // 13-bit length
const uint8_t BINARY_VERSION_PLAIN         = 0;
const uint8_t BINARY_VERSION_AUTHENTICATED = 1;
}

///////////////////////////////////////////////////////////////////////////////
// getCapabilities
//

uint64_t
CTcpipSession::getCapabilities(void) const
{
  uint64_t capabilities = VSCP_SERVER_CAPABILITY_TCPIP | VSCP_SERVER_CAPABILITY_IP6 | VSCP_SERVER_CAPABILITY_IP4 |
                          VSCP_SERVER_CAPABILITY_SSL | VSCP_SERVER_CAPABILITY_TWO_CONNECTIONS;
  switch (m_pObj->getBinaryEncryption()) {
    case VSCP_ENCRYPTION_AES128:
      capabilities |= VSCP_SERVER_CAPABILITY_AES128;
      break;
    case VSCP_ENCRYPTION_AES192:
      capabilities |= VSCP_SERVER_CAPABILITY_AES192;
      break;
    case VSCP_ENCRYPTION_AES256:
      capabilities |= VSCP_SERVER_CAPABILITY_AES256;
      break;
    default:
      break;
  }
  return capabilities;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientBinary
//

void
CTcpipSession::handleClientBinary(void)
{
  // Must be logged in
  if (!isVerified()) {
    return;
  }

  if (!m_pObj->isBinaryEnabled()) {
    write(MSG_COMMAND_NOT_SUPPORTED, strlen(MSG_COMMAND_NOT_SUPPORTED));
    return;
  }

  if (m_bReceiveLoop) {
    write(MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
    return;
  }

  crcInit();
  write(MSG_BINARY_MODE, strlen(MSG_BINARY_MODE));

  m_bBinaryMode = true;
  m_bBinaryOpen = false; // Events are queued until OPEN
  m_binaryInput.clear();

  drvlog::debug("[TCP/IP srv] Client {} entered binary mode{}",
                getRemoteAddress(),
                m_pObj->isBinaryAuthenticated() ? " (authenticated encryption)" : "");
}

///////////////////////////////////////////////////////////////////////////////
// onBinaryData
//

void
CTcpipSession::onBinaryData(const uint8_t* buf, size_t len)
{
  m_binaryInput.insert(m_binaryInput.end(), buf, buf + len);

  size_t offset = 0;
  while (isOpen() && m_bBinaryMode && (offset < m_binaryInput.size())) {

    // Resync: skip anything before the sync byte
    if (BINARY_SYNC_BYTE != m_binaryInput[offset]) {
      auto sync = std::find(m_binaryInput.begin() + offset, m_binaryInput.end(), BINARY_SYNC_BYTE);
      drvlog::warn("[TCP/IP srv] Skipped {} bytes before binary sync byte from {}.",
                   (size_t)(sync - (m_binaryInput.begin() + offset)),
                   getRemoteAddress());
      offset = (size_t)(sync - m_binaryInput.begin());
      continue;
    }

    if ((m_binaryInput.size() - offset) < BINARY_PREFIX_LENGTH) {
      break; // Wait for the rest of the prefix
    }

    const uint16_t word   = (uint16_t)((m_binaryInput[offset + 1] << 8) | m_binaryInput[offset + 2]);
    const uint8_t version = (uint8_t)(word >> 13);
    const size_t length   = word & BINARY_MAX_RECORD_LENGTH;
    const uint8_t expectedVersion =
      m_pObj->isBinaryAuthenticated() ? BINARY_VERSION_AUTHENTICATED : BINARY_VERSION_PLAIN;
    if ((0 == length) || (version != expectedVersion)) {
      drvlog::warn("[TCP/IP srv] Invalid binary record (version {}, length {}) from {}. Closing.",
                   version,
                   length,
                   getRemoteAddress());
      close();
      return;
    }

    if ((m_binaryInput.size() - offset) < (BINARY_PREFIX_LENGTH + length)) {
      break; // Wait for the rest of the record
    }

    std::vector<uint8_t> frame(m_binaryInput.begin() + offset + BINARY_PREFIX_LENGTH,
                               m_binaryInput.begin() + offset + BINARY_PREFIX_LENGTH + length);
    offset += BINARY_PREFIX_LENGTH + length;

    if (m_pObj->isBinaryAuthenticated()) {
      // Only authentic version 1 frames with the configured algorithm
      std::vector<uint8_t> plain(length);
      size_t plainLen = 0;
      if ((m_pObj->getBinaryEncryption() == (frame[0] & 0x0f)) &&
          (0 != (plainLen = vscp_decryptFrameV1(plain.data(),
                                                plain.size(),
                                                frame.data(),
                                                frame.size(),
                                                m_pObj->getBinaryAesKey(),
                                                m_pObj->getBinaryHmacKey())))) {
        plain.resize(plainLen);
        plain[0] &= 0xf0; // Decrypted: handle as the plain frame it now is
        frame.swap(plain);
        OPENSSL_cleanse(plain.data(), plain.size());
      }
      else {
        OPENSSL_cleanse(plain.data(), plain.size());
        drvlog::warn("[TCP/IP srv] Binary record from {} failed authentication. Closing.", getRemoteAddress());
        close();
        return;
      }
    }
    else if (frame[0] & 0x0f) {
      // Encrypted frames need configured keys; never fall back
      drvlog::warn("[TCP/IP srv] Encrypted binary record from {} but binary encryption is not configured. Closing.",
                   getRemoteAddress());
      close();
      return;
    }

    if (!handleBinaryFrame(frame)) {
      close();
      return;
    }
  }

  m_binaryInput.erase(m_binaryInput.begin(), m_binaryInput.begin() + offset);

  // TEXT switched back to text mode: the rest is text
  if (isOpen() && !m_bBinaryMode && !m_binaryInput.empty()) {
    m_strResponse.assign(m_binaryInput.begin(), m_binaryInput.end());
    m_binaryInput.clear();
    onTextData();
  }
}

///////////////////////////////////////////////////////////////////////////////
// handleBinaryFrame
//

bool
CTcpipSession::handleBinaryFrame(const std::vector<uint8_t>& frame)
{
  if (frame.empty()) {
    return false;
  }

  const uint8_t type = frame[0] & 0xf0;

  if ((0x00 == type) || (0x10 == type)) {
    return handleBinaryEvent(frame);
  }

  if (VSCP_BINARY_PACKET_TYPE_COMMAND == type) {
    return handleBinaryCommand(frame);
  }

  if (VSCP_BINARY_PACKET_TYPE_RESPONSE == type) {
    // Replies from the client, normally event confirmations for events we
    // sent. Nothing to do.
    return true;
  }

  drvlog::debug("[TCP/IP srv] Ignoring binary frame of unknown type {:#x} from {}", type, getRemoteAddress());
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleBinaryEvent
//

bool
CTcpipSession::handleBinaryEvent(const std::vector<uint8_t>& frame)
{
  // Header (35) + type byte + data size (2 in header) + CRC (2)
  if (frame.size() < 38) {
    return sendBinaryReply(VSCP_BINARY_CMD_EVENT_CONFIRM, VSCP_ERROR_INVALID_FRAME);
  }

  const uint8_t confirmArg[] = { 0, 0, frame[1], frame[2], frame[frame.size() - 2], frame[frame.size() - 1] };

  const size_t sizeData = ((size_t)frame[34] << 8) | frame[35];
  vscpEvent event;
  memset(&event, 0, sizeof(event));
  if ((sizeData > VSCP_LEVEL2_MAXDATA) || (frame.size() != (sizeData + 38)) ||
      !vscp_getEventFromFrame(&event, frame.data(), frame.size())) { // Also checks the CRC
    vscp_deleteEvent(&event);
    return sendBinaryReply(VSCP_BINARY_CMD_EVENT_CONFIRM, VSCP_ERROR_INVALID_FRAME, confirmArg, sizeof(confirmArg));
  }

  int rv = checkSendRights(&event);
  if (VSCP_ERROR_SUCCESS != rv) {
    drvlog::error("[TCP/IP srv] User [{}] not allowed to send event class={} type={}.",
                  m_pClientItem->m_pUserItem ? m_pClientItem->m_pUserItem->getUserName() : std::string("?"),
                  event.vscp_class,
                  event.vscp_type);
    vscp_deleteEvent(&event);
    return sendBinaryReply(VSCP_BINARY_CMD_EVENT_CONFIRM, (uint16_t)rv, confirmArg, sizeof(confirmArg));
  }

  // As for the text SEND command: our id, and our GUID if none is given
  event.obid = m_pClientItem->m_clientID;
  if (vscp_isGUIDEmpty(event.GUID)) {
    m_pClientItem->m_guid.writeGUID(event.GUID);
  }
  if (0 == event.timestamp) {
    event.timestamp = vscp_makeTimeStamp();
  }

  vscpEvent* pNewEvent = new (std::nothrow) vscpEvent;
  if (nullptr == pNewEvent) {
    vscp_deleteEvent(&event);
    return sendBinaryReply(VSCP_BINARY_CMD_EVENT_CONFIRM, VSCP_ERROR_MEMORY, confirmArg, sizeof(confirmArg));
  }
  memset(pNewEvent, 0, sizeof(vscpEvent));
  bool bCopied = vscp_copyEvent(pNewEvent, &event);
  vscp_deleteEvent(&event);

  if (!bCopied || !m_pObj->addEvent2ReceiveQueue(pNewEvent)) {
    vscp_deleteEvent_v2(&pNewEvent);
    return sendBinaryReply(VSCP_BINARY_CMD_EVENT_CONFIRM, VSCP_ERROR_TRM_FULL, confirmArg, sizeof(confirmArg));
  }

  m_pClientItem->m_statistics.cntTransmitFrames++;
  return sendBinaryReply(VSCP_BINARY_CMD_EVENT_CONFIRM, VSCP_ERROR_SUCCESS, confirmArg, sizeof(confirmArg));
}

///////////////////////////////////////////////////////////////////////////////
// handleBinaryCommand
//

bool
CTcpipSession::handleBinaryCommand(const std::vector<uint8_t>& frame)
{
  // [type][command:2][argument...][crc:2]
  if ((frame.size() < 5) || crcFast(frame.data() + 1, (int)(frame.size() - 1))) {
    drvlog::warn("[TCP/IP srv] Invalid binary command frame from {}. Closing.", getRemoteAddress());
    return false;
  }

  const uint16_t command = ((uint16_t)frame[1] << 8) | frame[2];
  const uint8_t* arg     = frame.data() + 3;
  const size_t arg_len   = frame.size() - 5;

  switch (command) {

    case VSCP_BINARY_CMD_NOOP:
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS);

    case VSCP_BINARY_CMD_QUIT:
      sendBinaryReply(command, VSCP_ERROR_SUCCESS);
      close();
      return true;

    case VSCP_BINARY_CMD_OPEN:
      m_bBinaryOpen = true;
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS);

    case VSCP_BINARY_CMD_CLOSE:
      m_bBinaryOpen = false;
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS);

    case VSCP_BINARY_CMD_RETR: {
      if (m_bBinaryOpen) {
        // Events are sent as they arrive
        return sendBinaryReply(command, VSCP_ERROR_NOT_SUPPORTED);
      }
      size_t count = 1;
      if (arg_len >= 2) {
        count = ((size_t)arg[0] << 8) | arg[1];
        if (0 == count) {
          count = 1;
        }
      }
      if (count > VSCP_BINARY_RETR_MAX) {
        count = VSCP_BINARY_RETR_MAX;
      }
      size_t sent = 0;
      while (sent < count) {
        vscpEvent* pEvent = popEvent();
        if (nullptr == pEvent) {
          break;
        }
        bool ok = sendBinaryEvent(pEvent);
        vscp_deleteEvent_v2(&pEvent);
        if (!ok) {
          return false;
        }
        sent++;
      }
      return sendBinaryReply(command, sent ? VSCP_ERROR_SUCCESS : VSCP_ERROR_RCV_EMPTY);
    }

    case VSCP_BINARY_CMD_CHKDATA: {
      uint32_t count = 0;
      if (!m_bBinaryOpen) {
        pthread_mutex_lock(&m_pClientItem->m_mutexClientInputQueue);
        count = (uint32_t)m_pClientItem->m_clientInputQueue.size();
        pthread_mutex_unlock(&m_pClientItem->m_mutexClientInputQueue);
      }
      const uint8_t reply[] = { (uint8_t)(count >> 24), (uint8_t)(count >> 16), (uint8_t)(count >> 8), (uint8_t)count };
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS, reply, sizeof(reply));
    }

    case VSCP_BINARY_CMD_CLEAR: {
      pthread_mutex_lock(&m_pClientItem->m_mutexClientInputQueue);
      for (vscpEvent* pEvent : m_pClientItem->m_clientInputQueue) {
        vscp_deleteEvent_v2(&pEvent);
      }
      m_pClientItem->m_clientInputQueue.clear();
      pthread_mutex_unlock(&m_pClientItem->m_mutexClientInputQueue);
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS);
    }

    case VSCP_BINARY_CMD_VERSION: {
      const uint8_t reply[] = { 0,
                                MAJOR_VERSION,
                                0,
                                MINOR_VERSION,
                                0,
                                RELEASE_VERSION,
                                (uint8_t)((uint32_t)BUILD_VERSION >> 24),
                                (uint8_t)((uint32_t)BUILD_VERSION >> 16),
                                (uint8_t)((uint32_t)BUILD_VERSION >> 8),
                                (uint8_t)BUILD_VERSION };
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS, reply, sizeof(reply));
    }

    case VSCP_BINARY_CMD_WCYD: {
      const uint64_t capabilities = getCapabilities();
      uint8_t reply[8];
      for (int i = 0; i < 8; i++) {
        reply[i] = (uint8_t)(capabilities >> (56 - 8 * i));
      }
      return sendBinaryReply(command, VSCP_ERROR_SUCCESS, reply, sizeof(reply));
    }

    case VSCP_BINARY_CMD_TEXT:
      // Leaving an authenticated binary session for plain text would be a
      // downgrade, so it is only allowed without binary encryption
      if (m_pObj->isBinaryAuthenticated()) {
        return sendBinaryReply(command, VSCP_ERROR_NOT_SUPPORTED);
      }
      if (!sendBinaryReply(command, VSCP_ERROR_SUCCESS)) {
        return false;
      }
      m_bBinaryMode = false;
      m_bBinaryOpen = false;
      return true;

    case VSCP_BINARY_CMD_USER:
    case VSCP_BINARY_CMD_PASS:
    case VSCP_BINARY_CMD_CHALLENGE:
      // Login is done in text mode before BINARY
    default:
      return sendBinaryReply(command, VSCP_ERROR_NOT_SUPPORTED);
  }
}

///////////////////////////////////////////////////////////////////////////////
// sendBinaryFrame
//

bool
CTcpipSession::sendBinaryFrame(const uint8_t* frame, size_t len)
{
  if (!isOpen() || (nullptr == frame) || (0 == len)) {
    return false;
  }

  std::vector<uint8_t> record;

  if (m_pObj->isBinaryAuthenticated()) {
    record.resize(BINARY_PREFIX_LENGTH + len + 48);
    const size_t innerLen = vscp_encryptFrameV1(record.data() + BINARY_PREFIX_LENGTH,
                                                record.size() - BINARY_PREFIX_LENGTH,
                                                frame,
                                                len,
                                                m_pObj->getBinaryAesKey(),
                                                m_pObj->getBinaryHmacKey(),
                                                nullptr, // Random IV
                                                m_pObj->getBinaryEncryption());
    if ((0 == innerLen) || (innerLen > BINARY_MAX_RECORD_LENGTH)) {
      drvlog::error("[TCP/IP srv] Failed to encrypt binary frame for {}", getRemoteAddress());
      return false;
    }
    const uint16_t word = (uint16_t)((BINARY_VERSION_AUTHENTICATED << 13) | innerLen);
    record.resize(BINARY_PREFIX_LENGTH + innerLen);
    record[0] = BINARY_SYNC_BYTE;
    record[1] = (uint8_t)(word >> 8);
    record[2] = (uint8_t)word;
  }
  else {
    if (len > BINARY_MAX_RECORD_LENGTH) {
      return false;
    }
    record.reserve(BINARY_PREFIX_LENGTH + len);
    record.push_back(BINARY_SYNC_BYTE);
    record.push_back((uint8_t)(len >> 8)); // Version 0
    record.push_back((uint8_t)len);
    record.insert(record.end(), frame, frame + len);
  }

  return write((const char*)record.data(), record.size());
}

///////////////////////////////////////////////////////////////////////////////
// sendBinaryReply
//

bool
CTcpipSession::sendBinaryReply(uint16_t command, uint16_t error, const uint8_t* arg, size_t arg_len)
{
  std::vector<uint8_t> frame(1 + 2 + 2 + arg_len + 2);
  if (VSCP_ERROR_SUCCESS != vscp_writeReplyToFrame(frame.data(), frame.size(), command, error, arg, arg_len)) {
    return false;
  }
  return sendBinaryFrame(frame.data(), frame.size());
}

///////////////////////////////////////////////////////////////////////////////
// sendBinaryEvent
//

bool
CTcpipSession::sendBinaryEvent(const vscpEvent* pEvent)
{
  vscpEvent* pev = (vscpEvent*)pEvent;
  const size_t size = vscp_getFrameSizeFromEvent(pev);
  if (0 == size) {
    return true; // Skip an event that can not be framed
  }
  std::vector<uint8_t> frame(size);
  if (!vscp_writeEventToFrame(frame.data(), frame.size(), 0, pEvent)) {
    return true;
  }
  if (!sendBinaryFrame(frame.data(), frame.size())) {
    return false;
  }
  m_pClientItem->m_statistics.cntReceiveFrames++;
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// popEvent
//

vscpEvent*
CTcpipSession::popEvent(void)
{
  while (true) {
    vscpEvent* pEvent = nullptr;
    pthread_mutex_lock(&m_pClientItem->m_mutexClientInputQueue);
    if (!m_pClientItem->m_clientInputQueue.empty()) {
      pEvent = m_pClientItem->m_clientInputQueue.front();
      m_pClientItem->m_clientInputQueue.pop_front();
    }
    pthread_mutex_unlock(&m_pClientItem->m_mutexClientInputQueue);

    if (nullptr == pEvent) {
      return nullptr;
    }

    // [[clientid == obid]] is used to detect our own events
    if (m_pObj->m_bReceiveOwnEvents || (pEvent->obid != m_pClientItem->m_clientID)) {
      return pEvent;
    }
    vscp_deleteEvent_v2(&pEvent);
  }
}

///////////////////////////////////////////////////////////////////////////////
// checkSendRights
//

int
CTcpipSession::checkSendRights(const vscpEvent* pEvent)
{
  if (!m_pClientItem->bAuthenticated || (nullptr == m_pClientItem->m_pUserItem)) {
    return VSCP_ERROR_NOT_AUTHORIZED;
  }

  const uint64_t rights = m_pClientItem->m_pUserItem->getUserRights();

  if ((VSCP_CLASS1_PROTOCOL == pEvent->vscp_class) && !(rights & VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {
    return VSCP_ERROR_NOT_AUTHORIZED;
  }
  if ((VSCP_CLASS2_PROTOCOL == pEvent->vscp_class) && !(rights & VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {
    return VSCP_ERROR_NOT_AUTHORIZED;
  }
  if ((VSCP_CLASS2_HLO == pEvent->vscp_class) && !(rights & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {
    return VSCP_ERROR_NOT_AUTHORIZED;
  }
  if (!m_pClientItem->m_pUserItem->isUserAllowedToSendEvent(pEvent->vscp_class, pEvent->vscp_type)) {
    return VSCP_ERROR_NOT_AUTHORIZED;
  }

  return VSCP_ERROR_SUCCESS;
}
