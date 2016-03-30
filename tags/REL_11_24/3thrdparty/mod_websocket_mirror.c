/**
 * additional test handler for mod_websocket
 * (to test our mod_qos test scripts)
 */

#include <string.h>
#include "websocket_plugin.h"

static size_t CALLBACK mirror_on_message(void *plugin_private,
					 const WebSocketServer *server,
					 const int type, 
					 unsigned char *buffer,
					 const size_t buffer_size) {
  unsigned char buf[buffer_size+1];
  int i;
  memset(buf, 0, buffer_size+1);
  for(i = 0; i < buffer_size; i++) {
    buf[i] = buffer[buffer_size-i-1];
  }
  return server->send(server, type, buf, buffer_size);
}

static WebSocketPlugin s_plugin = {
  sizeof(WebSocketPlugin),
  WEBSOCKET_PLUGIN_VERSION_0,
  NULL, /* destroy */
  NULL, /* on_connect */
  mirror_on_message,
  NULL /* on_disconnect */
};

extern EXPORT WebSocketPlugin * CALLBACK mirror_init() {
  return &s_plugin;
}
