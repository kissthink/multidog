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

/* $Id: auth.c 1373 2008-09-30 09:27:40Z wichert $ */
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>


#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;

/* Defined in util.c */
extern long served_this_session;

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_client_timeout_check(const void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;

        /*open named pipes to/from mysql server*/
	FILE * mysql_request = fopen("/tmp/wifidog_mysql_request_fifo","w");
	FILE * mysql_response = fopen("/tmp/wifidog_mysql_response_fifo","r");
//	char mysql_buf[256];

/*
	// set response fifo nonblocking,..
	int fd=fileno(mysql_response);
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK); //!!?? write ahelper function for this, as we might have to change this quite often,..

	debug(LOG_DEBUG,"mysql filedescriptors request: %d response: %d", fileno(mysql_request),fd);

	// empty the response fifo
	while (NULL != fgets(mysql_buf, sizeof(mysql_buf), mysql_response) ) {
		debug(LOG_DEBUG,"unexpected mysql response: %s", mysql_buf);
	}
	
	// test mysql with a simple query
	fputs("SELECT 1;\n", mysql_request);
	fflush(mysql_request);
	sleep(1); //!!?? write a helper functions that waits up to timeout for an response, or use a timeout instead of nonblocking?, or use blocking(together with column header it would be ok)
	if ( NULL == fgets(mysql_buf, sizeof(mysql_buf), mysql_response) ){
		fputs("\nexit\n", mysql_request);
	        fflush(mysql_request);
		debug(LOG_ERR,"mysql does not work: reverting to http-reauthentication");
		mysql_request = NULL;
		mysql_response = NULL;
	}
	else debug(LOG_DEBUG,"mysql response was: %s",mysql_buf);
*/

	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	
		debug(LOG_DEBUG, "Running fw_counter()");
	
		fw_sync_with_authserver(mysql_request, mysql_response);
	}
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(request *r, char *gw_id)
{
	t_client	*client;
	t_authresponse	auth_response;
	char	*mac,
		*token;
	char *urlFragment = NULL;
	s_config	*config = NULL;
	t_auth_serv	*auth_server = NULL;

	LOCK_CLIENT_LIST();

	client = client_list_find_by_ip(r->clientAddr);

	if (client == NULL) {
		debug(LOG_ERR, "Could not find client for %s", r->clientAddr);
		UNLOCK_CLIENT_LIST();
		return;
	}
	
	mac = safe_strdup(client->mac);
	token = safe_strdup(client->token);
	
	UNLOCK_CLIENT_LIST();
	
	/* 
	 * At this point we've released the lock while we do an HTTP request since it could
	 * take multiple seconds to do and the gateway would effectively be frozen if we
	 * kept the lock.
	 */
	auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, r->clientAddr, mac, token, 0, 0, gw_id);
	
	LOCK_CLIENT_LIST();
	
	/* can't trust the client to still exist after n seconds have passed */
	client = client_list_find(r->clientAddr, mac);
	
	if (client == NULL) {
		debug(LOG_ERR, "Could not find client node for %s (%s)", r->clientAddr, mac);
		UNLOCK_CLIENT_LIST();
		free(token);
		free(mac);
		return;
	}
	
	free(token);
	free(mac);

	/* Prepare some variables we'll need below */
	config = config_get_config();
	auth_server = get_auth_server();

	switch(auth_response.authcode) {

	case AUTH_ERROR:
		/* Error talking to central server */
		debug(LOG_ERR, "Got %d from central server authenticating token %s from %s at %s", auth_response, client->token, client->ip, client->mac);
		send_http_page(r, "Error!", "Error: We did not get a valid answer from the central server");
		break;

	case AUTH_DENIED:
		/* Central server said invalid token */
		debug(LOG_INFO, "Got DENIED from central server authenticating token %s from %s at %s - redirecting them to denied message", client->token, client->ip, client->mac);
		safe_asprintf(&urlFragment, "%smessage=%s",
			auth_server->authserv_msg_script_path_fragment,
			GATEWAY_MESSAGE_DENIED
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal", gw_id);
		//set connection logged out (xperimental)
		//snprintf(,client->token, client->ip, client->mac)	
		/*{
			char mysqlCmd[256];
			sprintf(mysqlCmd,"echo \"DELETE FROM connections WHERE token='%s';\"|mysql -uauthpuppy -pauthpuppydev authpuppy > /tmp/wifidog_deauth_mysql_result",client->token);
			debug(LOG_WARNING,"issuing this would help: %s",mysqlCmd);
			//system(mysqlCmd);//kills wifidog somehow *g
		}*/
		free(urlFragment);
		
		//for race conditions, remove from firewall
		fw_deny(client->ip, client->mac, client->fw_connection_state);
		//experimental delete client from list
                client_list_delete(client);

		break;

    case AUTH_VALIDATION:
		/* They just got validated for X minutes to check their email */
		debug(LOG_INFO, "Got VALIDATION from central server authenticating token %s from %s at %s"
				"- adding to firewall and redirecting them to activate message", client->token,
				client->ip, client->mac);
		client->fw_connection_state = FW_MARK_PROBATION;
		fw_allow(client->ip, client->mac, FW_MARK_PROBATION);
		safe_asprintf(&urlFragment, "%smessage=%s",
			auth_server->authserv_msg_script_path_fragment,
			GATEWAY_MESSAGE_ACTIVATE_ACCOUNT
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to activate message", gw_id);
		free(urlFragment);
	    break;

    case AUTH_ALLOWED:
		/* Logged in successfully as a regular account */
		debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
				"adding to firewall and redirecting them to portal", client->token, client->ip, client->mac);
		client->fw_connection_state = FW_MARK_KNOWN;
		fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
        served_this_session++;
		safe_asprintf(&urlFragment, "%sgw_id=%s",
			auth_server->authserv_portal_script_path_fragment,
			gw_id
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal", gw_id);
		free(urlFragment);
	    break;

    case AUTH_VALIDATION_FAILED:
		 /* Client had X minutes to validate account by email and didn't = too late */
		debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
				"- redirecting them to failed_validation message", client->token, client->ip, client->mac);
		safe_asprintf(&urlFragment, "%smessage=%s",
			auth_server->authserv_msg_script_path_fragment,
			GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to failed validation message", gw_id);
		free(urlFragment);
	    break;

    default:
		debug(LOG_WARNING, "I don't know what the validation code %d means for token %s from %s at %s - sending error message", auth_response.authcode, client->token, client->ip, client->mac);
		send_http_page(r, "Internal Error", "We can not validate your request at this time");
	    break;

	}

	UNLOCK_CLIENT_LIST();
	return;
}


