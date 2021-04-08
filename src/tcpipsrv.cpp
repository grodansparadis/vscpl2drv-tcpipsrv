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

#ifdef WIN32
#include "StdAfx.h"
#endif

#include "tcpipsrv.h"
#include <limits.h>

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#else
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

#include <sys/types.h>

#ifdef WIN32
#else
#include <syslog.h>
#include <unistd.h>
#include <net/if.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#endif

#include <ctype.h>
#include <sys/types.h>
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

#include <json.hpp>  // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <iostream>
#include <fstream>      
#include <list>
#include <map>
#include <string>

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

// Buffer for XML parser
//#define XML_BUFF_SIZE 50000

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
#ifndef WIN32    
    closelog();
#endif    
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
#ifndef WIN32        
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to load configuration file [%s]",
               path.c_str());
#endif               
        return false;
    }

    if (!startTcpipSrvThread()) {
#ifndef WIN32        
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to start server.");
#endif               
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
#ifndef WIN32    
    sleep(1);           // Give the thread some time to terminate
#else
    Sleep(1000);    
#endif    
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
#ifndef WIN32        
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse JSON configuration.");
#endif        
        return false;
    }

    if (!readEncryptionKey(m_j_config.value("vscp-key-file", ""))) {
#ifndef WIN32        
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] WARNING!!! Default key will be used.");
#endif        
        // Not secure of course but something...
        m_vscpkey = "Carpe diem quam minimum credula postero";
    }

    // Add users
    if (!m_j_config["users"].is_array()) {
#ifndef WIN32        
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse JSON configuration.");
#endif        
        return false;
    }

    for (json::iterator it = m_j_config["users"].begin(); it != m_j_config["users"].end(); ++it) {
        std::cout << (*it).dump() << '\n';

        vscpEventFilter receive_filter;
        vscp_readFilterFromString(&receive_filter, (*it).value("filter", ""));
        vscp_readMaskFromString(&receive_filter, (*it).value("mask", ""));

        if (!m_userList.addUser((*it).value("name", ""),
                                    (*it).value("password", ""),
                                    (*it).value("full-name", ""),
                                    (*it).value("note", ""),
                                    m_vscpkey,
                                    &receive_filter,
                                    (*it).value("privilege", "user"),
                                    (*it).value("allow-from", ""),
                                    (*it).value("allow-events", ""),
                                    (*it).value("flags", 0))) {
#ifndef WIN32                                        
            syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to add client %s.",(*it).dump().c_str());
#endif            
        }
    }

    vscpEvent ev;
    ev.vscp_class = VSCP_CLASS2_HLO;
    ev.vscp_type = VSCP2_TYPE_HLO_COMMAND;

    std::string jj = "{\"op\" : 1, \"name\": \"\"}";
    json j;
    j["op"] = "noop";
    j["arg"]["currency"] = "USD";
    j["arg"]["value"] = 42.99;
    j["arr"] = json::array();
    j["arr"][0]["ettan"] = 1;
    j["arr"][0]["tvan"] = 2;
    j["arr"][1]["ettan"] = 1;
    j["arr"][1]["tvan"] = 2;
    j["arr"][2]["ettan"] = 1;
    j["arr"][2]["tvan"] = 2;
    printf("%s\n",j.dump().c_str());


    json aa;
    aa["ettan"] = 55;
    aa["tva"] = 66;
    j["arr"][1] = aa;
    j["arr"][3] = aa;
    printf("%s\n",j.dump().c_str());
    j["arr"].erase(1);


    printf("%s\n",j.dump().c_str());


    ev.pdata = new uint8_t[200];

    memset(ev.pdata, 0, sizeof(ev.pdata));
    for ( int i=0; i<16; i++) {
        ev.pdata[i] = 11 * i;
    }
    ev.pdata[16] = 0x20;  // JSON, no encryption
    memcpy(ev.pdata+17, j.dump().c_str(), j.dump().length());
    ev.sizeData = 16 + 1 + (uint16_t)j.dump().length();

    handleHLO(&ev);

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
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent || (NULL == pEvent->pdata)) {
#ifndef WIN32        
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] HLO handler: NULL event pointer.");
#endif               
        return false;
    }

    // > 18  pos 0-15 = GUID, 16 type >> 4, encryption & 0x0f
    // JSON if type = 2
    // JSON from 17 onwards

    //CHLO hlo;
    //if (!hlo.parseHLO(j, pEvent )) {
#ifndef WIN32        
    //     syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse HLO.");
#endif    
    //     return false;
    // }

    // Must be HLO command event
    if ((pEvent->vscp_class != VSCP_CLASS2_HLO) &&
        (pEvent->vscp_type != VSCP2_TYPE_HLO_COMMAND)) {
        return false;
    }

    // Get GUID / encryption / type 
    cguid hlo_guid(pEvent->pdata);
    uint8_t hlo_encryption = pEvent->pdata[16] & 0x0f;
    uint8_t hlo_type = (pEvent->pdata[16] >> 4) & 0x0f;

    char buf[512];
    memset(buf,0,sizeof(buf));
    memcpy(buf, (pEvent->pdata + 17), pEvent->sizeData);
    auto j = json::parse(buf);
    printf("%s\n", j.dump().c_str());

    if (m_j_config["users"].is_array()) {
        printf("Yes it's an array %zu - %s\n", 
                    m_j_config["users"].size(),
                    m_j_config["users"][0]["name"].get<std::string>().c_str());
    }

    // Must be an operation
    if (!j["op"].is_string() || 
             j["op"].is_null()) {
#ifndef WIN32                 
        syslog(LOG_ERR,"[vscpl2drv-tcpipsrv] HLO-command: Missing op [%s]",j.dump().c_str());         
#endif
        return false;
    }

    if (j["arg"].is_object() && 
             !j["arg"].is_null()) {
        printf("Argument is object\n");
    }

    if (j["arg"].is_string() && 
             !j["arg"].is_null()) {
        printf("Argument is string\n");
    }

    if (j["arg"].is_number() && 
             !j["arg"].is_null()) {
        printf("Argument is number\n");
    }

    // Make HLO response event
    ex.obid = 0;
    ex.head = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex);              // Set time to current time
    ex.vscp_class = VSCP_CLASS2_PROTOCOL;
    ex.vscp_type = VSCP2_TYPE_HLO_RESPONSE;
    m_guid.writeGUID(ex.GUID);

    json j_response;

    if ( j.value("op","") == "noop") {
        // Send positive response            
        j_response["op"] = "vscp-reply";
        j_response["name"] = "noop";
        j_response["result"] = "OK";
        j_response["description"] = "NOOP commaned executed correctly.";

        memset(ex.data, 0, sizeof(ex.data));
        ex.sizeData = (uint16_t)strlen(buf);
        memcpy(ex.data, buf, ex.sizeData);        
    }
    else if ( j.value("op","") == "readvar") {
        readVariable(ex, j);
    }
    else if ( j.value("op","") == "writevar") {
        writeVariable(ex, j);
    }
    else if ( j.value("op","") == "delvar") {
        deleteVariable(ex, j);
    }
    else if ( j.value("op","") == "load") {
        doLoadConfig();
    }
    else if ( j.value("op","") == "save") {
        doSaveConfig();
    }
    else if ( j.value("op","") == "stop") {
        stop();
    }
    else if ( j.value("op","") == "start") {
        start();
    }
    else if ( j.value("op","") == "restart") {
        restart();
    }

    // Put event in receive queue
    return eventExToReceiveQueue(ex);

}

///////////////////////////////////////////////////////////////////////////////
// readVariable
//

bool
CTcpipSrv::readVariable(vscpEventEx& ex, const json& json_req)
{
    json j;

    j["op"] = "readvar";
    j["result"] = VSCP_ERROR_SUCCESS;
    j["arg"]["name"] = j.value("name","");

    if ("enable-debug" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
        j["arg"]["value"] = m_j_config.value("enable-debug", false);
    } else if ("enable-write" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
        j["arg"]["value"] = m_j_config.value("enable-write", false);
    } else if ("interface" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("interface", ""));
    } else if ("vscp-key-file" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("vscp-key-file", ""));
    } else if ("max-out-queue" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("max-out-queue", 0);
    } else if ("max-in-queue" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("max-in-queue", 0);
    } else if ("encryption" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("encryption", ""));
    } else if ("ssl-certificate" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-certificate", ""));
    } else if ("ssl-certificate-chain" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-certificate-chain", ""));
    } else if ("ssl-ca-path" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-ca-path", ""));
    } else if ("ssl-ca-file" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-ca-file", ""));
    } else if ("ssl-verify-depth" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("ssl-verify-depth", 9);
    } else if ("ssl-default-verify-paths" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-default-verify-paths", ""));
    } else if ("ssl-cipher-list" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-cipher-list", ""));
    } else if ("ssl-protocol-version" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("ssl-protocol-version", 3);
    } else if ("ssl-short-trust" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
        j["arg"]["value"] = m_j_config.value("ssl-short-trust", false);
    } else if ("user-count" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = 9;
    } else if ("users" == j.value("name","")) {
        
        if (!m_j_config["users"].is_array()) {
#ifndef WIN32            
            syslog(LOG_WARNING,"[vscpl2drv-tcpipsrv] 'users' must be of type array.");
#endif            
            j["result"] = VSCP_ERROR_SUCCESS;
            goto abort;
        }
        
        int index = j.value("index",0);  // get index
        if (index >= m_j_config["users"].size()) {
            // Index to large
#ifndef WIN32            
            syslog(LOG_WARNING,"[vscpl2drv-tcpipsrv] index of array is to large [%u].", 
                index >= m_j_config["users"].size());
#endif                
            j["result"] = VSCP_ERROR_INDEX_OOB;
            goto abort;
        }

        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_JSON;
        j["arg"]["value"] = m_j_config["users"][index].dump();

    } else {
        j["result"] = VSCP_ERROR_MISSING;
#ifndef WIN32        
        syslog(LOG_ERR,"Variable [] is unknown.");
#endif        
    }

 abort:

    memset(ex.data, 0, sizeof(ex.data));
    ex.sizeData = (uint16_t)j.dump().length();
    memcpy(ex.data, j.dump().c_str(), ex.sizeData);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// writeVariable
//

bool
CTcpipSrv::writeVariable(vscpEventEx& ex, const json& json_req)
{
    json j;

    j["op"] = "writevar";
    j["result"] = VSCP_ERROR_SUCCESS;
    j["arg"]["name"] = j.value("name","");

    if ("enable-debug" == j.value("name","")) {
        
        // arg should be boolean
        if (!j["arg"].is_boolean() ||
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;
        }
        
        // set new value
        m_j_config["enable-debug"] = j["arg"].get<bool>();
        
        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
        j["arg"]["value"] = m_j_config.value("enable-debug", false);

    } else if ("enable-write" == j.value("name","")) {
        
        // arg should be boolean
        if (!j["arg"].is_boolean() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["enable-write"] = j["arg"].get<bool>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
        j["arg"]["value"] = m_j_config.value("enable-write", false);

    } else if ("interface" == j.value("name","")) {
        
        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["interface"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config["interface"]);

    } else if ("vscp-key-file" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["vscp-key-file"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("vscp-key-file", ""));

    } else if ("max-out-queue" == j.value("name","")) {

        // arg should be number
        if (!j["arg"].is_number() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["max-out-queue"] = j["arg"].get<int>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("max-out-queue", 0);

    } else if ("max-in-queue" == j.value("name","")) {

        // arg should be number
        if (!j["arg"].is_number() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["max-in-queue"] = j["arg"].get<int>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("max-in-queue", 0);

    } else if ("encryption" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["encryption"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("encryption", ""));

    } else if ("ssl-certificate" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-certificate"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-certificate", ""));

    } else if ("ssl-certificate-chain" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-certificate-chain"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-certificate-chain", ""));

    } else if ("ssl-ca-path" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-ca-path"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-ca-path", ""));

    } else if ("ssl-ca-file" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-ca-file"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-ca-file", ""));

    } else if ("ssl-verify-depth" == j.value("name","")) {
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("ssl-verify-depth", 9);
    } else if ("ssl-default-verify-paths" == j.value("name","")) {
        
        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-default-verify-paths"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-default-verify-paths", ""));

    } else if ("ssl-cipher-list" == j.value("name","")) {

        // arg should be string
        if (!j["arg"].is_string() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-cipher-list"] = j["arg"].get<std::string>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
        j["arg"]["value"] = vscp_convertToBase64(m_j_config.value("ssl-cipher-list", ""));

    } else if ("ssl-protocol-version" == j.value("name","")) {
        
        // arg should be number
        if (!j["arg"].is_number() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-protocol-version"] = j["arg"].get<bool>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_INTEGER;
        j["arg"]["value"] = m_j_config.value("ssl-protocol-version", 3);

    } else if ("ssl-short-trust" == j.value("name","")) {

        // arg should be boolean
        if (!j["arg"].is_boolean() || 
             j["arg"].is_null()) {
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;         
        }
        // set new value
        m_j_config["ssl-short-trust"] = j["arg"].get<bool>();

        // report back
        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
        j["arg"]["value"] = m_j_config.value("ssl-short-trust", false);

    } else if ("users" == j.value("name","")) {
        
        // users must be array
        if (!m_j_config["users"].is_array()) {
#ifndef WIN32            
            syslog(LOG_WARNING,"[vscpl2drv-tcpipsrv] 'users' must be of type array.");
#endif            
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;
        }

        // Must be object
        if (!m_j_config["args"].is_object()) {
#ifndef WIN32            
            syslog(LOG_WARNING,"[vscpl2drv-tcpipsrv] The user info must be an object.");
#endif            
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;
        }

        int index = j.value("index",0);  // get index
        if (index >= m_j_config["users"].size()) {
            // Index to large
#ifndef WIN32            
            syslog(LOG_WARNING, 
                        "[vscpl2drv-tcpipsrv] index of array is to large [%u].",
                        index >= m_j_config["users"].size());
#endif                        
            j["result"] = VSCP_ERROR_INDEX_OOB;
            goto abort;
        }

        m_j_config["users"][index] = j["args"];

        j["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_JSON;
        j["arg"]["value"] = m_j_config["users"][index].dump();

    } else {
        j["result"] = VSCP_ERROR_MISSING;
#ifndef WIN32        
        syslog(LOG_ERR,"Variable [] is unknown.");
#endif        
    }

 abort:

    memset(ex.data, 0, sizeof(ex.data));
    ex.sizeData = (uint16_t)j.dump().length();
    memcpy(ex.data, j.dump().c_str(), ex.sizeData);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// deleteVariable
//

bool
CTcpipSrv::deleteVariable(vscpEventEx& ex, const json& json_reg)
{
    json j;

    j["op"] = "deletevar";
    j["result"] = VSCP_ERROR_SUCCESS;
    j["arg"]["name"] = j.value("name","");

    if ("users" == j.value("name","")) {
        
        // users must be array
        if (!m_j_config["users"].is_array()) {
#ifndef WIN32            
            syslog(LOG_WARNING,"[vscpl2drv-tcpipsrv] 'users' must be of type array.");
#endif            
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;
        }

        // Must be object
        if (!m_j_config["args"].is_object()) {
#ifndef WIN32            
            syslog(LOG_WARNING,"[vscpl2drv-tcpipsrv] The user info must be an object.");
#endif            
            j["result"] = VSCP_ERROR_INVALID_TYPE;
            goto abort;
        }

        int index = j.value("index",0);  // get index
        if (index >= m_j_config["users"].size()) {
            // Index to large
#ifndef WIN32            
            syslog(LOG_WARNING, 
                        "[vscpl2drv-tcpipsrv] index of array is to large [%u].",
                        index >= m_j_config["users"].size());
#endif                        
            j["result"] = VSCP_ERROR_INDEX_OOB;
            goto abort;
        }

        m_j_config["users"].erase(index);

    } else {
        j["result"] = VSCP_ERROR_MISSING;
#ifndef WIN32        
        syslog(LOG_WARNING, "[vscpl2drv-tcpipsrv] Variable [%s] is unknown.", j.value("name", "").c_str());
#endif        
    }

abort:

    memset(ex.data, 0, sizeof(ex.data));
    ex.sizeData = (uint16_t)j.dump().length();
    memcpy(ex.data, j.dump().c_str(), ex.sizeData);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// stop
//

bool
CTcpipSrv::stop(void)
{
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// start
//

bool
CTcpipSrv::start(void)
{
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// restart
//

bool
CTcpipSrv::restart(void)
{
    if (!stop()) {
#ifndef WIN32        
        syslog(LOG_WARNING, "[vscpl2drv-tcpipsrv] Failed to stop VSCP tcp/ip server.");
#endif        
    }

    if (!start()) {
#ifndef WIN32        
        syslog(LOG_WARNING, "[vscpl2drv-tcpipsrv] Failed to start VSCP tcp/ip server.");
#endif        
    }

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
#ifndef WIN32        
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to convert event from ex to ev.");
#endif               
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
#ifndef WIN32        
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Unable to allocate event storage.");
#endif               
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
#ifndef WIN32        
        syslog(LOG_ERR, "sendEventToClient - Pointer to clientitem is null");
#endif        
        return false;
    }
    if (NULL == pEvent) {
#ifndef WIN32        
        syslog(LOG_ERR, "sendEventToClient - Pointer to event is null");
#endif        
        return false;
    }

    // Check if filtered out - if so do nothing here
    if (!vscp_doLevel2Filter(pEvent, &pClientItem->m_filter)) {
        if (m_j_config["enable-debug"].get<bool>()) {
#ifndef WIN32            
            syslog(LOG_DEBUG, "sendEventToClient - Filtered out");
#endif            
        }
        return false;
    }

    // If the client queue is full for this client then the
    // client will not receive the message
    if (pClientItem->m_clientInputQueue.size() > m_j_config.value("max-out-queue", MAX_ITEMS_IN_QUEUE)) {
        if (m_j_config["enable-debug"].get<bool>()) {
#ifndef WIN32            
            syslog(LOG_DEBUG, "sendEventToClient - overrun");
#endif            
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
#ifndef WIN32        
        syslog(LOG_ERR, "sendEventAllClients - No event to send");
#endif        
        return false;
    }

    pthread_mutex_lock(&m_clientList.m_mutexItemList);
    for (it = m_clientList.m_itemList.begin();
         it != m_clientList.m_itemList.end();
         ++it) {
        pClientItem = *it;

        if (NULL != pClientItem) {
            if (m_j_config["enable-debug"].get<bool>()) {
#ifndef WIN32                
                syslog(LOG_DEBUG,
                       "Send event to client [%s]",
                       pClientItem->m_strDeviceName.c_str());
#endif                       
            }
            if (!sendEventToClient(pClientItem, pEvent)) {
#ifndef WIN32                
                syslog(LOG_ERR, "sendEventAllClients - Failed to send event");
#endif                
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
#ifndef WIN32        
        syslog(LOG_DEBUG, "Controlobject: Starting TCP/IP interface...");
#endif        
    }

    // Create the tcp/ip server data object
    m_ptcpipSrvObject = (tcpipListenThreadObj*)new tcpipListenThreadObj(this);
    if (NULL == m_ptcpipSrvObject) {
#ifndef WIN32        
        syslog(LOG_ERR,
               "Controlobject: Failed to allocate storage for tcp/ip.");
#endif               
    }

    // Set the port to listen for connections on
    m_ptcpipSrvObject->setListeningPort(m_j_config["interface"].get<std::string>());

    if (pthread_create(&m_tcpipListenThread,
                       NULL,
                       tcpipListenThread,
                       m_ptcpipSrvObject)) {
        delete m_ptcpipSrvObject;
        m_ptcpipSrvObject = NULL;
#ifndef WIN32        
        syslog(LOG_ERR,
               "Controlobject: Unable to start the tcp/ip listen thread.");
#endif               
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
#ifndef WIN32        
        syslog(LOG_DEBUG, "Controlobject: Terminating TCP thread.");
#endif        
    }

    pthread_join(m_tcpipListenThread, NULL);
    delete m_ptcpipSrvObject;
    m_ptcpipSrvObject = NULL;

    if (__VSCP_DEBUG_TCP) {
#ifndef WIN32        
        syslog(LOG_DEBUG, "Controlobject: Terminated TCP thread.");
#endif        
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
#ifndef WIN32        
        syslog(LOG_ERR,
                "[vscpl2drv-tcpipsrv] Failed to read encryption key file [%s]",
                m_path.c_str());
#endif                
        return false;
    }

    return true;
}