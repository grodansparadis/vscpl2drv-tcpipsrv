// devicethread.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// Copyright © 2000-2026 Ake Hedman, Grodans Paradis AB
// <info@grodansparadis.com>
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

#if !defined(DEVICETHREAD_H__7D80016B_5EFD_40D5_94E3_6FD9C324CC7B__INCLUDED_)
#define DEVICETHREAD_H__7D80016B_5EFD_40D5_94E3_6FD9C324CC7B__INCLUDED_

void *
deviceThread(void *pData);

void *
deviceLevel1ReceiveThread(void *pData);
void *
deviceLevel1WriteThread(void *pData);

void *
deviceLevel2ReceiveThread(void *pData);
void *
deviceLevel2WriteThread(void *pData);


#endif
