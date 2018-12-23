#ifndef _HEADERS_TPACP_H_
#define _HEADERS_TPACP_H_


int tpcap_create(void **handle);
int tpcap_delete(void *handle);
int tpcap_load(void *handle, const char *path);
void tpcap_print(void *handle);




#endif /* end of _HEADERS_TPACP_H_ */
