/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * mod_qos.h: Quality of service module for Apache Web Server.
 *
 * The Apache Web Servers requires threads and processes to serve
 * requests. Each TCP connection to the web server occupies one
 * thread or process. Sometimes, a server gets too busy to serve
 * every request due the lack of free processes or threads.
 *
 * This module implements control mechanisms that can provide
 * different priority to different requests.
 *
 * See http://mod-qos.sourceforge.net/ for further
 * details.
 *
 * Copyright (C) 2021 Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __MOD_QOS_H__
#define __MOD_QOS_H__

/**************************************************************************
 * Hooks 
 **************************************************************************/
#if !defined(WIN32)
#define QOS_DECLARE(type)            type
#define QOS_DECLARE_NONSTD(type)     type
#define QOS_DECLARE_DATA
#elif defined(QOS_DECLARE_STATIC)
#define QOS_DECLARE(type)            type __stdcall
#define QOS_DECLARE_NONSTD(type)     type
#define QOS_DECLARE_DATA
#elif defined(QOS_DECLARE_EXPORT)
#define QOS_DECLARE(type)            __declspec(dllexport) type __stdcall
#define QOS_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define QOS_DECLARE_DATA             __declspec(dllexport)
#else
#define QOS_DECLARE(type)            __declspec(dllimport) type __stdcall
#define QOS_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define QOS_DECLARE_DATA             __declspec(dllimport)
#endif

#define QOS_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(qos,name,fn,pre,succ,order)

/**
 * mod_qos.h header file defining hooks for path/query
 * decoding (used by QS_Deny* and QS_Permit* rules).
 *
 * Define QS_MOD_EXT_HOOKS in order to enable these hooks
 * within mod_qos.c.
 */

/* hook to decode/unescape the path portion of the request uri */
APR_DECLARE_EXTERNAL_HOOK(qos, QOS, apr_status_t, path_decode_hook,
                          (request_rec *r, char **path, int *len))
/* hook to decode/unescape the query portion of the request uri */
APR_DECLARE_EXTERNAL_HOOK(qos, QOS, apr_status_t, query_decode_hook,
                          (request_rec *r, char **query, int *len))

#endif /* __MOD_QOS_H__ */
