/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id: http.h 1346 2008-04-21 23:04:40Z acv $ */
/** @file http.h
    @brief HTTP IO functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"

/**@brief Callback for libhttpd, main entry point for captive portal */
void http_callback_404(httpd *webserver, request *r);
/**@brief Callback for libhttpd */
void http_callback_wifidog(httpd *webserver, request *r);
/**@brief Callback for libhttpd */
void http_callback_about(httpd *webserver, request *r);
/**@brief Callback for libhttpd */
void http_callback_status(httpd *webserver, request *r);
/**@brief Callback for libhttpd, main entry point post login for auth confirmation */
void http_callback_auth(httpd *webserver, request *r);

#define MULTI_CLIENT_ENABLED 1

/** @brief Sends a HTML page to web browser */
void send_http_page(request *r, const char *title, const char* message);
#if MULTI_CLIENT_ENABLED
/** @brief Sends a HTML page to web browser with a known gw_id (multi-client)*/
void send_http_page_gw(request *r, const char *title, const char* message, char *gw_id);
#endif

/** @brief Sends a redirect to the web browser */
void http_send_redirect(request *r, char *url, char *text);
#if MULTI_CLIENT_ENABLED
/** @brief Sends a redirect to the web browser with an known gw_id (multi-client)*/
void http_send_redirect_gw(request *r, char *url, char *text, char *gw_id);
#endif
/** @brief Convenience function to redirect the web browser to the authe server */
void http_send_redirect_to_auth(request *r, char *urlFragment, char *text, char* gw_id);

#if MULTI_CLIENT_ENABLED
/** @brief Looks up an gw-id based on mac of a user/device */
char *multi_client_lookup_gw_by_mac(char *mac, char *buf);
/** @brief Looks up an gw-id based on mac of a user/device */
char *multi_client_lookup_gw_by_ip(char *ip, char *buf);

#endif

#endif /* _HTTP_H_ */
