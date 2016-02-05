/*
* Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vconf.h>

#include "softap.h"

#define DISABLE_REASON_TEXT_LEN	64
#define COMMON_STR_BUF_LEN	32

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data);

softap_h sa = NULL;

static int test_softap_create(void)
{
	softap_create(&sa);

	return 1;
}

static int test_softap_destroy(void)
{
	//TODO
	softap_destroy(sa);
	return 1;
}

int main(int argc, char **argv)
{
	GMainLoop *mainloop;

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif
	mainloop = g_main_loop_new(NULL, false);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread, NULL);
	printf("Test Thread created...\n");
	g_main_loop_run(mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv;
	char a[10];

	printf("Event received from stdin\n");

	rv = read(0, a, 10);

	if (rv <= 0 || a[0] == '0')
		exit(1);

	if (a[0] == '\n' || a[0] == '\r') {
		printf("\n\n Network Connection API Test App\n\n");
		printf("Options..\n");
		printf("1       - SoftAP create and set callbacks\n");
		printf("2       - SoftAP destroy\n");
		printf("0       - Exit \n");
		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
	case '1':
		rv = test_softap_create();
		break;
	case '2':
		rv = test_softap_destroy();
		break;
	}

	if (rv == 1)
		printf("Operation succeeded!\n");
	else
		printf("Operation failed!\n");

	return true;
}
