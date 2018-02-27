#define MAX_OUTSTANDING_ATR 32

typedef struct atr_response {
	timer_t timerid;
	struct sockaddr_storage *client_addr;
	int socket;
	char *response;
	size_t response_size;
	short in_use;
	short to_be_freed;
} atr_response;


int makeTimer(int index, ldns_pkt *atr_pkt, struct sockaddr_storage *client_addr, int socket);
void send_atr(int index);
int get_first_free(void);
static void timerHandler(int sig, siginfo_t *si, void *uc);
void clearTimer(int index);
void clean_atr(void);
