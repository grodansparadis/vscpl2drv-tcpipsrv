// tcpipsrv.cpp: implementation of the CTcpipSrv class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2020 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include "tcpipsrv.h"

#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <ctype.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <expat.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include <iostream>
#include <fstream>      
#include <list>
#include <map>
#include <string>

#include <json.hpp>  // Needs C++11  -std=c++11
#include <mustache.hpp>

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

// Buffer for XML parser
#define XML_BUFF_SIZE 50000

// Forward declaration
void*
tcpipListenThread(void* pData);

//////////////////////////////////////////////////////////////////////
// CTcpipSrv
//

CTcpipSrv::CTcpipSrv()
{
    m_bQuit = false;

    vscp_clearVSCPFilter(&m_rxfilter);  // Accept all events
    vscp_clearVSCPFilter(&m_txfilter);  // Send all events

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);

    pthread_mutex_init(&m_mutex_UserList, NULL);
    
}

//////////////////////////////////////////////////////////////////////
// ~CTcpipSrv
//

CTcpipSrv::~CTcpipSrv()
{
    close();

    sem_destroy(&m_semSendQueue);
    sem_destroy(&m_semReceiveQueue);

    pthread_mutex_destroy(&m_mutexSendQueue);
    pthread_mutex_destroy(&m_mutexReceiveQueue);

    pthread_mutex_destroy(&m_mutex_UserList);

    // Close syslog channel
    closelog();
}


//////////////////////////////////////////////////////////////////////
// open
//
//

bool
CTcpipSrv::open(std::string& path, const cguid& guid)
{
    // Set GUID
    m_guid = guid;

    // Save path to config file
    m_path = path;

    // Read configuration file
    if (!doLoadConfig()) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to load configuration file [%s]",
               path.c_str());
        return false;
    }

    if (!startTcpipSrvThread()) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to start server.");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CTcpipSrv::close(void)
{
    // Do nothing if already terminated
    if (m_bQuit)
        return;

    m_bQuit = true;     // terminate the thread
    sleep(1);           // Give the thread some time to terminate
}


///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
CTcpipSrv::doLoadConfig(void)
{
    try {
        std::ifstream in(m_path, std::ifstream::in);
        in >> m_j_config;
    }
    catch (json::parse_error) {
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse JSON configuration.");
        return false;
    }

    if (!readEncryptionKey(m_j_config.value("vscpkeyfile", ""))) {
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] WARNING!!! Default key will be used.");
        // Not secure of course but something...
        m_vscpkey = "Carpe diem quam minimum credula postero";
    }

    // Add users
    if (!m_j_config["users"].is_array()) {
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse JSON configuration.");
        return false;
    }

    for (json::iterator it = m_j_config["users"].begin(); it != m_j_config["users"].end(); ++it) {
        std::cout << (*it).dump() << '\n';

        vscpEventFilter receive_filter;
        vscp_readFilterFromString(&receive_filter, (*it).value("filter", ""));
        vscp_readMaskFromString(&receive_filter, (*it).value("mask", ""));

        if (!m_userList.addUser((*it).value("name", ""),
                                    (*it).value("password", ""),
                                    (*it).value("fullname", ""),
                                    (*it).value("note", ""),
                                    m_vscpkey,
                                    &receive_filter,
                                    (*it).value("privilege", "user"),
                                    (*it).value("allowfrom", ""),
                                    (*it).value("allowevents", ""),
                                    (*it).value("flags", 0))) {
            syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to add client %s.",(*it).dump().c_str());
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CTcpipSrv::doSaveConfig(void)
{
    if (m_j_config.value("enable-write", false)) {

    }
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CTcpipSrv::handleHLO(vscpEvent* pEvent)
{
    char buf[3000];     // Working buffer
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent || (NULL == pEvent->pdata)) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] HLO handler: NULL event pointer.");
        return false;
    }

    // CHLO hlo;
    // if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
    //     syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse HLO.");
    //     return false;
    // }

    // Make HLO response event
    ex.obid = 0;
    ex.head = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex);              // Set time to current time
    ex.vscp_class = VSCP_CLASS2_PROTOCOL;
    ex.vscp_type = VSCP2_TYPE_HLO_RESPONSE;
    m_guid.writeGUID(ex.GUID);

    switch (hlo.m_op) {

        case HLO_OP_NOOP:

            // Send positive response
            json j_response;
            j_response["op"] = "vscp-reply";
            j_response["name"] = "noop";
            j_response["result"] = "OK";
            j_response["description"] = "NOOP commaned executed correctly.";

            memset(ex.data, 0, sizeof(ex.data));
            ex.sizeData = strlen(buf);
            memcpy(ex.data, buf, ex.sizeData);

            // Put event in receive queue
            return eventExToReceiveQueue(ex);

        case HLO_OP_READ_VAR:
            // if ("REMOTE-HOST" == hlo.m_name) {
            //     sprintf(buf,
            //             HLO_READ_VAR_REPLY_TEMPLATE,
            //             "remote-host",
            //             "OK",
            //             VSCP_REMOTE_VARIABLE_CODE_STRING,
            //             vscp_convertToBase64(m_hostRemote).c_str());
            // } else if ("REMOTE-PORT" == hlo.m_name) {
            //     char ibuf[80];
            //     sprintf(ibuf, "%d", m_portRemote);
            //     sprintf(buf,
            //             HLO_READ_VAR_REPLY_TEMPLATE,
            //             "remote-port",
            //             "OK",
            //             VSCP_REMOTE_VARIABLE_CODE_INTEGER,
            //             vscp_convertToBase64(ibuf).c_str());
            // } else if ("REMOTE-USER" == hlo.m_name) {
            //     sprintf(buf,
            //             HLO_READ_VAR_REPLY_TEMPLATE,
            //             "remote-user",
            //             "OK",
            //             VSCP_REMOTE_VARIABLE_CODE_INTEGER,
            //             vscp_convertToBase64(m_usernameRemote).c_str());
            // } else if ("REMOTE-PASSWORD" == hlo.m_name) {
            //     sprintf(buf,
            //             HLO_READ_VAR_REPLY_TEMPLATE,
            //             "remote-password",
            //             "OK",
            //             VSCP_REMOTE_VARIABLE_CODE_INTEGER,
            //             vscp_convertToBase64(m_passwordRemote).c_str());
            // } else if ("TIMEOUT-RESPONSE" == hlo.m_name) {
            //     char ibuf[80];
            //     sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
            //     sprintf(buf,
            //             HLO_READ_VAR_REPLY_TEMPLATE,
            //             "timeout-response",
            //             "OK",
            //             VSCP_REMOTE_VARIABLE_CODE_LONG,
            //             vscp_convertToBase64(ibuf).c_str());
            // }
            break;

        case HLO_OP_WRITE_VAR:
            // if ("REMOTE-HOST" == hlo.m_name) {
            //     if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
            //         // Wrong variable type
            //         sprintf(buf,
            //                 HLO_READ_VAR_ERR_REPLY_TEMPLATE,
            //                 "remote-host",
            //                 ERR_VARIABLE_WRONG_TYPE,
            //                 "Variable type should be string.");
            //     } else {
            //         m_hostRemote = hlo.m_value;
            //         sprintf(buf,
            //                 HLO_READ_VAR_REPLY_TEMPLATE,
            //                 "enable-sunrise",
            //                 "OK",
            //                 VSCP_REMOTE_VARIABLE_CODE_STRING,
            //                 vscp_convertToBase64(m_hostRemote).c_str());
            //     }
            // } else if ("REMOTE-PORT" == hlo.m_name) {
            //     if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
            //         // Wrong variable type
            //         sprintf(buf,
            //                 HLO_READ_VAR_ERR_REPLY_TEMPLATE,
            //                 "remote-port",
            //                 ERR_VARIABLE_WRONG_TYPE,
            //                 "Variable type should be integer.");
            //     } else {                    
            //         m_portRemote = vscp_readStringValue(hlo.m_value);
            //         char ibuf[80];
            //         sprintf(ibuf, "%d", m_portRemote);
            //         sprintf(buf,
            //                 HLO_READ_VAR_REPLY_TEMPLATE,
            //                 "remote-port",
            //                 "OK",
            //                 VSCP_REMOTE_VARIABLE_CODE_INTEGER,
            //                 vscp_convertToBase64(ibuf).c_str());
            //     }
            // } else if ("REMOTE-USER" == hlo.m_name) {
            //     if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
            //         // Wrong variable type
            //         sprintf(buf,
            //                 HLO_READ_VAR_ERR_REPLY_TEMPLATE,
            //                 "remote-port",
            //                 ERR_VARIABLE_WRONG_TYPE,
            //                 "Variable type should be string.");
            //     } else {
            //         m_usernameRemote = hlo.m_value;
            //         sprintf(buf,
            //                 HLO_READ_VAR_REPLY_TEMPLATE,
            //                 "remote-user",
            //                 "OK",
            //                 VSCP_REMOTE_VARIABLE_CODE_STRING,
            //                 vscp_convertToBase64(m_usernameRemote).c_str());
            //     }
            // } else if ("REMOTE-PASSWORD" == hlo.m_name) {
            //     if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
            //         // Wrong variable type
            //         sprintf(buf,
            //                 HLO_READ_VAR_ERR_REPLY_TEMPLATE,
            //                 "remote-password",
            //                 ERR_VARIABLE_WRONG_TYPE,
            //                 "Variable type should be string.");
            //     } else {
            //         m_passwordRemote = hlo.m_value;
            //         sprintf(buf,
            //                 HLO_READ_VAR_REPLY_TEMPLATE,
            //                 "remote-password!",
            //                 "OK",
            //                 VSCP_REMOTE_VARIABLE_CODE_STRING,
            //                 vscp_convertToBase64(m_passwordRemote).c_str());
            //     }
            // } else if ("TIMEOUT-RESPONSE¤" == hlo.m_name) {
            //     if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
            //         // Wrong variable type
            //         sprintf(buf,
            //                 HLO_READ_VAR_ERR_REPLY_TEMPLATE,
            //                 "timeout-response",
            //                 ERR_VARIABLE_WRONG_TYPE,
            //                 "Variable type should be uint32.");
            //     } else {                    
            //         m_responseTimeout = vscp_readStringValue(hlo.m_value);
            //         char ibuf[80];
            //         sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
            //         sprintf(buf,
            //                 HLO_READ_VAR_REPLY_TEMPLATE,
            //                 "timeout-response",
            //                 "OK",
            //                 VSCP_REMOTE_VARIABLE_CODE_UINT32,
            //                 vscp_convertToBase64(ibuf).c_str());
            //     }
            // }
            break;

        // Save configuration
        case HLO_OP_SAVE:
            doSaveConfig();
            break;

        // Load configuration
        case HLO_OP_LOAD:
            doLoadConfig();
            break;

        // Connect tyo remote host
        case HLO_OP_LOCAL_CONNECT:
            break;    

        // Disconnect from remote host
        case HLO_OP_LOCAL_DISCONNECT:
            break;
  
        default:
            break;
    };

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CTcpipSrv::eventExToReceiveQueue(vscpEventEx& ex)
{
    vscpEvent* pev = new vscpEvent();
    if (!vscp_convertEventExToEvent(pev, &ex)) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to convert event from ex to ev.");
        vscp_deleteEvent(pev);
        return false;
    }
    
    if (NULL != pev) {
        if (vscp_doLevel2Filter(pev, &m_rxfilter)) {
            pthread_mutex_lock(&m_mutexReceiveQueue);
            m_receiveList.push_back(pev);            
            pthread_mutex_unlock(&m_mutexReceiveQueue);
            sem_post(&m_semReceiveQueue);
        } else {
            vscp_deleteEvent(pev);
        }
    } else {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Unable to allocate event storage.");
    }
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//
//

bool
CTcpipSrv::addEvent2SendQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexSendQueue);
    m_sendList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semSendQueue);
    pthread_mutex_unlock(&m_mutexSendQueue);
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//
//  Send event to host
//

bool
CTcpipSrv::addEvent2ReceiveQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexReceiveQueue);
    m_receiveList.push_back((vscpEvent*)pEvent);    
    pthread_mutex_unlock(&m_mutexReceiveQueue);
    sem_post(&m_semReceiveQueue);
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventToClient
//

bool
CTcpipSrv::sendEventToClient(CClientItem* pClientItem, const vscpEvent* pEvent)
{
    // Must be valid pointers
    if (NULL == pClientItem) {
        syslog(LOG_ERR, "sendEventToClient - Pointer to clientitem is null");
        return false;
    }
    if (NULL == pEvent) {
        syslog(LOG_ERR, "sendEventToClient - Pointer to event is null");
        return false;
    }

    // Check if filtered out - if so do nothing here
    if (!vscp_doLevel2Filter(pEvent, &pClientItem->m_filter)) {
        if (m_j_config["enable-debug"].get<bool>()) {
            syslog(LOG_DEBUG, "sendEventToClient - Filtered out");
        }
        return false;
    }

    // If the client queue is full for this client then the
    // client will not receive the message
    if (pClientItem->m_clientInputQueue.size() > m_j_config.value("maxoutque", MAX_ITEMS_IN_QUEUE)) {
        if (m_j_config["enable-debug"].get<bool>()) {
            syslog(LOG_DEBUG, "sendEventToClient - overrun");
        }
        // Overrun
        pClientItem->m_statistics.cntOverruns++;
        return false;
    }

    // Create a new event
    vscpEvent* pnewvscpEvent = new vscpEvent;
    if (NULL != pnewvscpEvent) {

        // Copy in the new event
        if (!vscp_copyEvent(pnewvscpEvent, pEvent)) {
            vscp_deleteEvent_v2(&pnewvscpEvent);
            return false;
        }

        // Add the new event to the input queue
        pthread_mutex_lock(&pClientItem->m_mutexClientInputQueue);
        pClientItem->m_clientInputQueue.push_back(pnewvscpEvent);
        pthread_mutex_unlock(&pClientItem->m_mutexClientInputQueue);
        sem_post(&pClientItem->m_semClientInputQueue);
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

bool
CTcpipSrv::sendEventAllClients(const vscpEvent* pEvent)
{
    CClientItem* pClientItem;
    std::deque<CClientItem*>::iterator it;

    if (NULL == pEvent) {
        syslog(LOG_ERR, "sendEventAllClients - No event to send");
        return false;
    }

    pthread_mutex_lock(&m_clientList.m_mutexItemList);
    for (it = m_clientList.m_itemList.begin();
         it != m_clientList.m_itemList.end();
         ++it) {
        pClientItem = *it;

        if (NULL != pClientItem) {
            if (m_j_config["enable-debug"].get<bool>()) {
                syslog(LOG_DEBUG,
                       "Send event to client [%s]",
                       pClientItem->m_strDeviceName.c_str());
            }
            if (!sendEventToClient(pClientItem, pEvent)) {
                syslog(LOG_ERR, "sendEventAllClients - Failed to send event");
            }
        }
    }

    pthread_mutex_unlock(&m_clientList.m_mutexItemList);

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// startTcpWorkerThread
//

bool
CTcpipSrv::startTcpipSrvThread(void)
{
    if (__VSCP_DEBUG_TCP) {
        syslog(LOG_DEBUG, "Controlobject: Starting TCP/IP interface...");
    }

    // Create the tcp/ip server data object
    m_ptcpipSrvObject = (tcpipListenThreadObj*)new tcpipListenThreadObj(this);
    if (NULL == m_ptcpipSrvObject) {
        syslog(LOG_ERR,
               "Controlobject: Failed to allocate storage for tcp/ip.");
    }

    // Set the port to listen for connections on
    m_ptcpipSrvObject->setListeningPort(m_j_config["interface"].get<std::string>());

    if (pthread_create(&m_tcpipListenThread,
                       NULL,
                       tcpipListenThread,
                       m_ptcpipSrvObject)) {
        delete m_ptcpipSrvObject;
        m_ptcpipSrvObject = NULL;
        syslog(LOG_ERR,
               "Controlobject: Unable to start the tcp/ip listen thread.");
        return false;
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// stopTcpWorkerThread
//

bool
CTcpipSrv::stopTcpipSrvThread(void)
{
    // Tell the thread it's time to quit
    m_ptcpipSrvObject->m_nStopTcpIpSrv = VSCP_TCPIP_SRV_STOP;

    if (__VSCP_DEBUG_TCP) {
        syslog(LOG_DEBUG, "Controlobject: Terminating TCP thread.");
    }

    pthread_join(m_tcpipListenThread, NULL);
    delete m_ptcpipSrvObject;
    m_ptcpipSrvObject = NULL;

    if (__VSCP_DEBUG_TCP) {
        syslog(LOG_DEBUG, "Controlobject: Terminated TCP thread.");
    }

    return true;
}

//////////////////////////////////////////////////////////////////////////////
// addClient
//

bool
CTcpipSrv::addClient(CClientItem* pClientItem, uint32_t id)
{
    // Check pointer
    if ( NULL == pClientItem ) {
        return false;
    }

    // Add client to client list
    if (!m_clientList.addClient(pClientItem, id)) {
        return false;
    }

    // Set GUID for interface
    pClientItem->m_guid = m_guid;

    // Fill in client id
    pClientItem->m_guid.setNicknameID(0);
    pClientItem->m_guid.setClientID(pClientItem->m_clientID);

    return true;
}

//////////////////////////////////////////////////////////////////////////////
// addClient - GUID (for drivers with set GUID)
//

bool
CTcpipSrv::addClient(CClientItem* pClientItem, cguid& guid)
{
    // Check pointer
    if ( NULL == pClientItem ) {
        return false;
    }

    // Add client to client list
    if (!m_clientList.addClient(pClientItem, guid)) {
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////////////
// removeClient
//

void
CTcpipSrv::removeClient(CClientItem* pClientItem)
{
    // Do not try to handle invalid clients
    if (NULL == pClientItem)
        return;

    // Remove the client
    m_clientList.removeClient(pClientItem);
}

/////////////////////////////////////////////////////////////////////////////
// generateSessionId
//

bool
CTcpipSrv::generateSessionId(const char* pKey, char* psid)
{
    char buf[8193];

    // Check pointers
    if (NULL == pKey)
        return false;
    if (NULL == psid)
        return false;

    if (strlen(pKey) > 256)
        return false;

    // Generate a random session ID
    time_t t;
    t = time(NULL);
    snprintf(buf, sizeof(buf),
            "__%s_%X%X%X%X_be_hungry_stay_foolish_%X%X",
            pKey,
            (unsigned int)rand(),
            (unsigned int)rand(),
            (unsigned int)rand(),
            (unsigned int)t,
            (unsigned int)rand(),
            1337);

    vscp_md5(psid, (const unsigned char*)buf, strlen(buf));

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CTcpipSrv::readEncryptionKey(const std::string& path)
{
    try {
        std::ifstream in(path, std::ifstream::in);
        std::stringstream strStream;
        strStream << in.rdbuf();
        m_vscpkey = strStream.str();
    }
    catch (...) {
        syslog(LOG_ERR,
                "[vscpl2drv-tcpipsrv] Failed to read encryption key file [%s]",
                m_path.c_str());
        return false;
    }

    return true;
}