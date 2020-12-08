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
//#include "clientlist.h"

#include <list>
#include <map>
#include <string>

// Buffer for XML parser
#define XML_BUFF_SIZE 50000

// Forward declaration
void*
workerThreadReceive(void* pData);

void*
workerThreadSend(void* pData);

void*
tcpipListenThread(void* pData); 

//////////////////////////////////////////////////////////////////////
// CTcpipSrv
//

CTcpipSrv::CTcpipSrv()
{
    m_bDebug = false;
    m_bAllowWrite = false;
    m_bQuit = false;

    // Default TCP/IP interface settings
    m_strTcpInterfaceAddress = "9598";
    m_encryptionTcpip        = 0;
    m_tcpip_ssl_certificate.clear();
    m_tcpip_ssl_certificate_chain.clear();
    m_tcpip_ssl_verify_peer = 0; // no=0, optional=1, yes=2
    m_tcpip_ssl_ca_path.clear();
    m_tcpip_ssl_ca_file.clear();
    m_tcpip_ssl_verify_depth         = 9;
    m_tcpip_ssl_default_verify_paths = false;
    m_tcpip_ssl_cipher_list.clear();
    m_tcpip_ssl_protocol_version = 0;
    m_tcpip_ssl_short_trust      = false;

    vscp_clearVSCPFilter(&m_rxfilter); // Accept all events
    vscp_clearVSCPFilter(&m_txfilter); // Send all events
    m_responseTimeout = TCPIP_DEFAULT_INNER_RESPONSE_TIMEOUT;

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);
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

    // Close syslog channel
    closelog();
}

// ----------------------------------------------------------------------------

/*
    XML configuration
    -----------------

        You can open TCP/IP interfaces on several ports or on
        on a specific port or on every interface of the computer
        Default 9598 will listen on all interfaces while
        "127.0.0.1:9598" only will listen on the specified interface.
        To specify several interfaces just enter them with a space
        between them.
        
        interface  - Set port and interface to listen on as a comma
                     separated list.
        encryption - Set VSCP AES encryption for interface. aes128, ase192, 
                     aes256 are valid values.
        ssl_certificate - Path to SSL certificat PEM format file. If empty the
                          TLS system will not be initialised.
                          Common path: /etc/vscp/certs/server.pem 
        ssl_certificate_chain - Path to an SSL certificate chain file. As a default, 
                                the ssl_certificate file is used.
        ssl_verify_peer       - [yes/no] Enable clients certificate verification by the 
                                server. Default: no
        ssl_ca_path           - Name of a directory containing trusted CA certificates. 
                                Each file in the directory must contain only a single 
                                CA certificate. The files must be named by the subject 
                                name’s hash and an extension of “.0”. If there is more 
                                than one certificate with the same subject name they 
                                should have extensions ".0", ".1", ".2" and so on 
                                respectively.
        ssl_ca_file           - Path to a .pem file containing trusted certificates. 
                                The file may contain more than one certificate.
        ssl_verify_depth      - Sets maximum depth of certificate chain. If clients certificate 
                                chain is longer than the depth set here connection is refused.
                                Default: 9
        ssl_default_verify_paths - [yes/no] Loads default trusted certificates locations set at 
                                   openssl compile time. Default is yes
        ssl_cipher_list       - List of ciphers to present to the client. 
                                Entries should be separated by colons, commas or spaces.
                                
                                Example:
                                ALL           All available ciphers
                                ALL:!eNULL    All ciphers excluding NULL ciphers
                                AES128:!MD5   AES 128 with digests other than MD5
                                
                                See https://www.openssl.org/docs/man1.1.0/man1/ciphers.html
                                in OpenSSL documentation for full list of options and additional 
                                examples.
        ssl_protocol_version  - Sets the minimal accepted version of SSL/TLS protocol according to 
                                the table:

                                SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2 	0 (default)
                                SSL3+TLS1.0+TLS1.1+TLS1.2 	1
                                TLS1.0+TLS1.1+TLS1.2 	        2
                                TLS1.1+TLS1.2 	                3
                                TLS1.2 	                        4

                                More recent versions of OpenSSL include support for TLS version 1.3. 
                                To use TLS1.3 only, set ssl_protocol_version to 5.
        ssl_short_trust       - [yes/no] Enables the use of short lived certificates. This will allow for the 
                                certificates and keys specified in ssl_certificate, ssl_ca_file and 
                                ssl_ca_path to be exchanged and reloaded while the server is running.

                                In an automated environment it is advised to first write the new pem file 
                                to a different filename and then to rename it to the configured pem file 
                                name to increase performance while swapping the certificate.

                                Disk IO performance can be improved when keeping the certificates and keys 
                                stored on a tmpfs (linux) on a system with very high throughput.  

                                Default: no                       

    <setup interface="9598"
            encryption="aes256"
            ssl_certificate=""
            ssl_certificate_chain=""
            ssl_verify_peer="false"
            ssl_ca_path=""
            ssl_ca_file=""
            ssl_verify_depth="9"
            ssl_default_verify_paths="true"
            ssl_cipher_list="DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256"
            ssl_protocol_version="3"
            ssl_short_trust="false" >

        <!--
            Holds information about one (at least) or more users
            Use vscp-mkpassword to generate a new password
            Privilege is "admin" or "user" or comma seperated list
            Same information is used for accessing the daemon
            through the TCP/IP interface as through the web-interface
        -->
            <users>
                <user name="user"                
                    password="D35967DEE4CFFB214124DFEEA7778BB0;582BCA078604C925852CDDEE0A8475556DEAA6DC6EFB004A353094900C97D3DE"
                    privilege="user"
                    allowfrom=""
                    filter=""
                    events=""
                    fullname="Sample user"
                    note="A normal user. username="user" password='secret'" />
                <user name="udp"                
                    password="D35967DEE4CFFB214124DFEEA7778BB0;582BCA078604C925852CDDEE0A8475556DEAA6DC6EFB004A353094900C97D3DE"
                    privilege="udp"
                    allowfrom=""
                    filter=""
                    events=""
                    fullname="UDP user"
                    note="A normal user. username="user" password='secret'"
            />
            </users>

     </setup>
*/

// ----------------------------------------------------------------------------

static int depth_config_parser = 0;
static bool bConfigFound = false;
static bool bUserConfigFound = false;


void
startSetupParser(void* data, const char* name, const char** attr)
{
    CTcpipSrv* pObj = (CTcpipSrv*)data;
    if (NULL == pObj) {
        return;
    }

    if ((0 == strcmp(name, "config")) && (0 == depth_config_parser)) {

        bConfigFound = true;

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "debug")) {
                if (!attribute.empty()) {
                    if ( "true" == attribute ) {
                        pObj->m_bDebug = true;
                    }
                    else {
                        pObj->m_bDebug = false;
                    }
                }
            }
            else if (0 == strcasecmp(attr[i], "write")) {
                if (!attribute.empty()) {
                    if ( "true" == attribute ) {
                        pObj->m_bAllowWrite = true;
                    }
                    else {
                        pObj->m_bAllowWrite = false;
                    }
                }
            }
            else if (0 == vscp_strcasecmp(attr[i], "interface")) {
                vscp_startsWith(attribute, "tcp://", &attribute);
                vscp_trim(attribute);
                pObj->m_strTcpInterfaceAddress = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_certificate")) {
                pObj->m_tcpip_ssl_certificate = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_verify_peer")) {
                pObj->m_tcpip_ssl_verify_peer = vscp_readStringValue(attribute);
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_certificate_chain")) {
                pObj->m_tcpip_ssl_certificate_chain = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_ca_path")) {
                pObj->m_tcpip_ssl_ca_path = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_ca_file")) {
                pObj->m_tcpip_ssl_ca_file = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_verify_depth")) {
                pObj->m_tcpip_ssl_verify_depth =
                  vscp_readStringValue(attribute);
            }
            else if (0 ==
                     vscp_strcasecmp(attr[i], "ssl_default_verify_paths")) {
                if (0 == vscp_strcasecmp(attribute.c_str(), "true")) {
                    pObj->m_tcpip_ssl_default_verify_paths = true;
                }
                else {
                    pObj->m_tcpip_ssl_default_verify_paths = false;
                }
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_cipher_list")) {
                pObj->m_tcpip_ssl_cipher_list = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_protocol_version")) {
                pObj->m_tcpip_ssl_verify_depth =
                  vscp_readStringValue(attribute);
            }
            else if (0 == vscp_strcasecmp(attr[i], "ssl_short_trust")) {
                if (0 == vscp_strcasecmp(attribute.c_str(), "true")) {
                    pObj->m_tcpip_ssl_short_trust = true;
                }
                else {
                    pObj->m_tcpip_ssl_short_trust = false;
                }       
            } else if (0 == strcasecmp(attr[i], "rxfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_rxfilter,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpipsrv] Unable to read "
                               "event receive filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "rxmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_rxfilter,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpipsrv] Unable to read "
                               "event receive mask.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_txfilter,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpipsrv] Unable to read "
                               "event transmit filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_txfilter,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpipsrv] Unable to read "
                               "event transmit mask.");
                    }
                }
            } else if (0 == strcmp(attr[i], "response-timeout")) {
                if (!attribute.empty()) {
                    pObj->m_responseTimeout = vscp_readStringValue(attribute);
                }
            }
        }
    }
    else if (bConfigFound && (1 == depth_config_parser) &&
             (0 == vscp_strcasecmp(name, "users"))) {
        bUserConfigFound = true;
    }
    else if (bConfigFound && 
              bUserConfigFound &&
              (0 == strcmp(name, "user")) &&
              (2 == depth_config_parser) ) {

        vscpEventFilter VSCPFilter;
        bool bFilterPresent = false;
        bool bMaskPresent   = false;
        std::string name;
        std::string md5;
        std::string privilege;
        std::string allowfrom;
        std::string allowevent;
        std::string fullname;
        std::string note;

        vscp_clearVSCPFilter(&VSCPFilter); // Allow all frames

        for (int i=0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == vscp_strcasecmp(attr[i], "name")) {
                name = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "password")) {
                md5 = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "fullname")) {
                fullname = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "note")) {
                note = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "privilege")) {
                privilege = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "allowfrom")) {
                allowfrom = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "allowevent")) {
                allowevent = attribute;
            }
            else if (0 == vscp_strcasecmp(attr[i], "filter")) {
                if (attribute.length()) {
                    if (vscp_readFilterFromString(&VSCPFilter, attribute)) {
                        bFilterPresent = true;
                    }
                }
            }
            else if (0 == vscp_strcasecmp(attr[i], "mask")) {
                if (attribute.length()) {
                    if (vscp_readMaskFromString(&VSCPFilter, attribute)) {
                        bMaskPresent = true;
                    }
                }
            }            
        }

        if (bFilterPresent && bMaskPresent) {
            pObj->m_userList.addUser(name,
                                        md5,
                                        fullname,
                                        note,
                                        "123.com",
                                        &VSCPFilter,
                                        privilege,
                                        allowfrom,
                                        allowevent,
                                        0);
        }
        else {
            pObj->m_userList.addUser(name,
                                        md5,
                                        fullname,
                                        note,
                                        "123.com",
                                        NULL,
                                        privilege,
                                        allowfrom,
                                        allowevent,
                                        0);
        }
    }

    depth_config_parser++;
}

void
endSetupParser(void* data, const char* name)
{
    depth_config_parser--;

    if (1 == depth_config_parser &&
        (0 == vscp_strcasecmp(name, "config"))) {
        bConfigFound = false;
    }
    if (bConfigFound && (1 == depth_config_parser) &&
             (0 == vscp_strcasecmp(name, "user"))) {
        bUserConfigFound = false;
    }
}

// ----------------------------------------------------------------------------

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

    m_bQuit = true; // terminate the thread
    sleep(1);       // Give the thread some time to terminate
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void* data, const char* name, const char** attr)
{
    CHLO* pObj = (CHLO*)data;
    if (NULL == pObj)
        return;

    if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_config_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "op")) {
                if (!attribute.empty()) {
                    pObj->m_op = vscp_readStringValue(attribute);
                    vscp_makeUpper(attribute);
                    if (attribute == "VSCP-NOOP") {
                        pObj->m_op = HLO_OP_NOOP;
                    } else if (attribute == "VSCP-READVAR") {
                        pObj->m_op = HLO_OP_READ_VAR;
                    } else if (attribute == "VSCP-WRITEVAR") {
                        pObj->m_op = HLO_OP_WRITE_VAR;
                    } else if (attribute == "VSCP-LOAD") {
                        pObj->m_op = HLO_OP_LOAD;
                    } else if (attribute == "VSCP-SAVE") {
                        pObj->m_op = HLO_OP_SAVE;
                    } else if (attribute == "CALCULATE") {
                        pObj->m_op = HLO_OP_SAVE;
                    } else {
                        pObj->m_op = HLO_OP_UNKNOWN;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "name")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    pObj->m_name = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "type")) {
                if (!attribute.empty()) {
                    pObj->m_varType = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "value")) {
                if (!attribute.empty()) {
                    if (vscp_base64_std_decode(attribute)) {
                        pObj->m_value = attribute;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "full")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if ("TRUE" == attribute) {
                        pObj->m_bFull = true;
                    } else {
                        pObj->m_bFull = false;
                    }
                }
            }
        }
    }

    depth_hlo_parser++;
}

void
endHLOParser(void* data, const char* name)
{
    depth_hlo_parser--;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

bool
CTcpipSrv::parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo)
{
    // Check pointers
    if (NULL == inbuf) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-tcpipsrv] HLO parser: HLO in-buffer pointer is NULL.");
        return false;
    }

    if (NULL == phlo) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] HLO parser: HLO obj pointer is NULL.");
        return false;
    }

    if (!size) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] HLO parser: HLO buffer size is zero.");
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    // Copy in the HLO object
    memcpy(buf, inbuf, size);

    if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed parse XML setup.");
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
CTcpipSrv::doLoadConfig(void)
{
    FILE* fp;
    
    fp = fopen(m_path.c_str(), "r");
    if (NULL == fp) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to open configuration file [%s]",
               m_path.c_str());
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startSetupParser, endSetupParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    size_t file_size = 0;
    file_size = fread(buf, sizeof(char), XML_BUFF_SIZE, fp);

    if (!XML_ParseBuffer(xmlParser, file_size, file_size == 0)) {
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed parse XML setup.");
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

#define TEMPLATE_SAVE_CONFIG                                                   \
    "<setup "                                                                  \
    " host=\"%s\" "                                                            \
    " port=\"%d\" "                                                            \
    " user=\"%s\" "                                                            \
    " password=\"%s\" "                                                        \
    " rxfilter=\"%s\" "                                                        \
    " rxmask=\"%s\" "                                                          \
    " txfilter=\"%s\" "                                                        \
    " txmask=\"%s\" "                                                          \
    " responsetimeout=\"%lu\" "                                                \
    "/>"

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CTcpipSrv::doSaveConfig(void)
{
    char buf[2048]; // Working buffer

    std::string strRxFilter, strRxMask;
    std::string strTxFilter, strTxMask;
    vscp_writeFilterToString( strRxFilter, &m_rxfilter );
    vscp_writeFilterToString( strRxMask, &m_rxfilter );
    vscp_writeFilterToString( strTxFilter, &m_txfilter );
    vscp_writeFilterToString( strTxMask, &m_txfilter );

    sprintf( buf, 
        TEMPLATE_SAVE_CONFIG,
        m_hostRemote.c_str(),
        m_portRemote,
        m_usernameRemote.c_str(),
        m_passwordRemote.c_str(),
        strRxFilter.c_str(),
        strRxMask.c_str(),
        strTxFilter.c_str(),
        strTxMask.c_str(),
        (long unsigned int)m_responseTimeout );

    FILE* fp;
    
    fp = fopen(m_path.c_str(), "w");
    if (NULL == fp) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to open configuration file [%s] for write",
               m_path.c_str());
        return false;
    }

    if ( strlen(buf) != fwrite( buf, sizeof(char), strlen(buf), fp ) ) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] Failed to write configuration file [%s] ",
               m_path.c_str());
        fclose (fp);       
        return false;
    }

    fclose(fp);
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CTcpipSrv::handleHLO(vscpEvent* pEvent)
{
    char buf[512]; // Working buffer
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpipsrv] HLO handler: NULL event pointer.");
        return false;
    }

    CHLO hlo;
    if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
        syslog(LOG_ERR, "[vscpl2drv-tcpipsrv] Failed to parse HLO.");
        return false;
    }

    ex.obid = 0;
    ex.head = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_PROTOCOL;
    ex.vscp_type = VSCP2_TYPE_HLO_COMMAND;
    m_guid.writeGUID(ex.GUID);

    switch (hlo.m_op) {

        case HLO_OP_NOOP:
            // Send positive response
            sprintf(buf,
                    HLO_CMD_REPLY_TEMPLATE,
                    "noop",
                    "OK",
                    "NOOP commaned executed correctly.");

            memset(ex.data, 0, sizeof(ex.data));
            ex.sizeData = strlen(buf);
            memcpy(ex.data, buf, ex.sizeData);

            // Put event in receive queue
            return eventExToReceiveQueue(ex);

        case HLO_OP_READ_VAR:
            if ("REMOTE-HOST" == hlo.m_name) {
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-host",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_STRING,
                        vscp_convertToBase64(m_hostRemote).c_str());
            } else if ("REMOTE-PORT" == hlo.m_name) {
                char ibuf[80];
                sprintf(ibuf, "%d", m_portRemote);
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-port",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                        vscp_convertToBase64(ibuf).c_str());
            } else if ("REMOTE-USER" == hlo.m_name) {
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-user",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                        vscp_convertToBase64(m_usernameRemote).c_str());
            } else if ("REMOTE-PASSWORD" == hlo.m_name) {
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-password",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                        vscp_convertToBase64(m_passwordRemote).c_str());
            } else if ("TIMEOUT-RESPONSE" == hlo.m_name) {
                char ibuf[80];
                sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "timeout-response",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_LONG,
                        vscp_convertToBase64(ibuf).c_str());
            }
            break;

        case HLO_OP_WRITE_VAR:
            if ("REMOTE-HOST" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-host",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be string.");
                } else {
                    m_hostRemote = hlo.m_value;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "enable-sunrise",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_hostRemote).c_str());
                }
            } else if ("REMOTE-PORT" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-port",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be integer.");
                } else {                    
                    m_portRemote = vscp_readStringValue(hlo.m_value);
                    char ibuf[80];
                    sprintf(ibuf, "%d", m_portRemote);
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "remote-port",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                            vscp_convertToBase64(ibuf).c_str());
                }
            } else if ("REMOTE-USER" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-port",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be string.");
                } else {
                    m_usernameRemote = hlo.m_value;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "remote-user",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_usernameRemote).c_str());
                }
            } else if ("REMOTE-PASSWORD" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-password",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be string.");
                } else {
                    m_passwordRemote = hlo.m_value;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "remote-password!",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_passwordRemote).c_str());
                }
            } else if ("TIMEOUT-RESPONSE¤" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "timeout-response",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be uint32.");
                } else {                    
                    m_responseTimeout = vscp_readStringValue(hlo.m_value);
                    char ibuf[80];
                    sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "timeout-response",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_UINT32,
                            vscp_convertToBase64(ibuf).c_str());
                }
            }
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
            sem_post(&m_semReceiveQueue);
            pthread_mutex_unlock(&m_mutexReceiveQueue);
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

bool
CTcpipSrv::addEvent2SendQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexSendQueue);
    m_sendList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semSendQueue);
    pthread_mutex_lock(&m_mutexSendQueue);
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
    m_ptcpipSrvObject->setListeningPort(m_strTcpInterfaceAddress);

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
    sprintf(buf,
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

//////////////////////////////////////////////////////////////////////
// Send worker thread
//

void*
workerThreadSend(void* pData)
{
    bool bRemoteConnectionLost = false;

    CTcpipSrv* pObj = (CTcpipSrv*)pData;
    if (NULL == pObj) {
        return NULL;
    }

retry_send_connect:

    // Open remote interface
    if (VSCP_ERROR_SUCCESS !=
        pObj->m_srvRemoteSend.doCmdOpen(pObj->m_hostRemote,
                                    pObj->m_portRemote,
                                    pObj->m_usernameRemote,
                                    pObj->m_passwordRemote)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char*)"Error while opening remote VSCP TCP/IP "
                            "interface. Terminating!");

        // Give the server some time to become active
        for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME;
             loopcnt++) {
            sleep(1);
            if (pObj->m_bQuit)
                return NULL;
        }

        goto retry_send_connect;
    }

    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char*)"Connect to remote VSCP TCP/IP interface [SEND].");

    // Find the channel id
    pObj->m_srvRemoteSend.doCmdGetChannelID(&pObj->txChannelID);

    while (!pObj->m_bQuit) {

        // Make sure the remote connection is up
        if (!pObj->m_srvRemoteSend.isConnected()) {

            if (!bRemoteConnectionLost) {
                bRemoteConnectionLost = true;
                pObj->m_srvRemoteSend.doCmdClose();
                syslog(LOG_ERR,
                       "%s %s ",
                       VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                       (const char*)"Lost connection to remote host [SEND].");
            }

            // Wait before we try to connect again
            sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

            if (VSCP_ERROR_SUCCESS !=
                pObj->m_srvRemoteSend.doCmdOpen(pObj->m_hostRemote,
                                            pObj->m_portRemote,
                                            pObj->m_usernameRemote,
                                            pObj->m_passwordRemote)) {
                syslog(LOG_ERR,
                       "%s %s ",
                       VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                       (const char*)"Reconnected to remote host [SEND].");

                // Find the channel id
                pObj->m_srvRemoteSend.doCmdGetChannelID(&pObj->txChannelID);

                bRemoteConnectionLost = false;
            }

            continue;
        }

        if ((-1 == vscp_sem_wait(&pObj->m_semSendQueue, 500)) &&
            errno == ETIMEDOUT) {
            continue;
        }

        // Check if there is event(s) to send
        if (pObj->m_sendList.size()) {

            // Yes there are data to send
            pthread_mutex_lock(&pObj->m_mutexSendQueue);
            vscpEvent* pEvent = pObj->m_sendList.front();
            // Check if event should be filtered away
            if (!vscp_doLevel2Filter(pEvent, &pObj->m_txfilter)) {
                pthread_mutex_unlock(&pObj->m_mutexSendQueue);
                continue;
            }
            pObj->m_sendList.pop_front();
            pthread_mutex_unlock(&pObj->m_mutexSendQueue);

            // Only HLO object event is of interst to us
            if ((VSCP_CLASS2_PROTOCOL == pEvent->vscp_class) &&
                (VSCP2_TYPE_HLO_COMMAND == pEvent->vscp_type)) {
                pObj->handleHLO(pEvent);
            }

            if (NULL == pEvent)
                continue;

            // Yes there are data to send
            // Send it out to the remote server

            pObj->m_srvRemoteSend.doCmdSend(pEvent);
            vscp_deleteEvent_v2(&pEvent);
        }
    }

    // Close the channel
    pObj->m_srvRemoteSend.doCmdClose();

    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char*)"Disconnect from remote VSCP TCP/IP interface [SEND].");

    return NULL;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread Receive - CWrkReceiveTread
//////////////////////////////////////////////////////////////////////

void*
workerThreadReceive(void* pData)
{
    bool bRemoteConnectionLost = false;
    __attribute__((unused)) bool bActivity = false;

    CTcpipSrv* pObj = (CTcpipSrv*)pData;
    if (NULL == pObj)
        return NULL;

retry_receive_connect:

    if (pObj->m_bDebug) {
        printf("Open receive channel host = %s port = %d\n",
                pObj->m_hostRemote.c_str(), 
                pObj->m_portRemote);
    }

    // Open remote interface
    if (VSCP_ERROR_SUCCESS !=
        pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
                                            pObj->m_portRemote,
                                            pObj->m_usernameRemote,
                                            pObj->m_passwordRemote)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char*)"Error while opening remote VSCP TCP/IP "
                            "interface. Terminating!");

        // Give the server some time to become active
        for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME;
             loopcnt++) {
            sleep(1);
            if (pObj->m_bQuit)
                return NULL;
        }

        goto retry_receive_connect;
    }

    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char*)"Connect to remote VSCP TCP/IP interface [RECEIVE].");

    // Set receive filter
    if (VSCP_ERROR_SUCCESS !=
        pObj->m_srvRemoteReceive.doCmdFilter(&pObj->m_rxfilter)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char*)"Failed to set receiving filter.");
    }

    // Enter the receive loop
    pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

    __attribute__((unused)) vscpEventEx eventEx;
    while (!pObj->m_bQuit) {

        // Make sure the remote connection is up
        if (!pObj->m_srvRemoteReceive.isConnected() ||
            ((vscp_getMsTimeStamp() - pObj->m_srvRemoteReceive.getlastResponseTime()) >
             (VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME * 1000))) {

            if (!bRemoteConnectionLost) {

                bRemoteConnectionLost = true;
                pObj->m_srvRemoteReceive.doCmdClose();
                syslog(LOG_ERR, "%s %s ", VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                            (const char*)"Lost connection to remote host [Receive].");
            }

            // Wait before we try to connect again
            sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

            if (VSCP_ERROR_SUCCESS !=
                pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
                                                    pObj->m_portRemote,
                                                    pObj->m_usernameRemote,
                                                    pObj->m_passwordRemote)) {
                syslog(LOG_ERR,
                       "%s %s ",
                       VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                       (const char*)"Reconnected to remote host [Receive].");
                bRemoteConnectionLost = false;
            }

            // Enter the receive loop
            pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

            continue;
        }

        // Check if remote server has something to send to us
        vscpEvent* pEvent = new vscpEvent;
        if (NULL != pEvent) {

            pEvent->sizeData = 0;
            pEvent->pdata = NULL;

            if (CANAL_ERROR_SUCCESS ==
                pObj->m_srvRemoteReceive.doCmdBlockingReceive(pEvent)) {

                // Filter is handled at server side. We check so we don't
                // receive things we send ourself.
                if (pObj->txChannelID != pEvent->obid) {
                    pthread_mutex_lock(&pObj->m_mutexReceiveQueue);
                    pObj->m_receiveList.push_back(pEvent);
                    sem_post(&pObj->m_semReceiveQueue);
                    pthread_mutex_unlock(&pObj->m_mutexReceiveQueue);
                } else {
                    vscp_deleteEvent(pEvent);
                }

            } else {
                vscp_deleteEvent(pEvent);
            }
        }
    }

    // Close the channel
    pObj->m_srvRemoteReceive.doCmdClose();

    syslog(
      LOG_ERR,
      "%s %s ",
      VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
      (const char*)"Disconnect from remote VSCP TCP/IP interface [RECEIVE].");

    return NULL;
}
