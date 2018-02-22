#include <signal.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>

#include <evldns.h>

#include "atr_handler.h"

atr_response atr_responses[MAX_OUTSTANDING_ATR];

/******
 * Send delayed (atr) packet
 **********/
void send_atr(index) {
	int socket;
	struct sockaddr_storage *client_addr;
	ssize_t len_sent;
	uint8_t *dns_message;
	size_t size;

	socket = atr_responses[index].socket;	
	dns_message = atr_responses[index].response;
	client_addr = atr_responses[index].client_addr;
	size = 	atr_responses[index].response_size;

	// printf("ZZZZZZZZZZZ in send_atr, print packet\n");
	// ldns_pkt_print(stdout, (ldns_pkt *)dns_message);

	//send the message
	len_sent = sendto(socket, (char *)dns_message, size, 0 , (struct sockaddr *)client_addr, sizeof(struct sockaddr_storage));
	if (len_sent==-1) {
		printf("Error: send atr sendto: %s\n", strerror(errno));
		fflush(stdout);
		exit(-1);
	}
}

/******************************************************************
 * Act on ATR send timer. Disarm timer and send truncated response
 ******************************************************************/
static void timerHandler(int sig, siginfo_t *si, void *uc )
{
	int index = si->si_value.sival_int;	

	// send the delayed response
	send_atr(index);
	
	// delete the timer
	clearTimer(index);

	// and flags items to be cleared
	atr_responses[index].to_be_freed = 1;
	fflush(stdout);
}

/*************************************************************
 * Create timer for ATR delayed send
 *************************************************************/
int makeTimer(int index, ldns_pkt *atr_pkt, struct sockaddr_storage *client_addr, int socket)
{
	struct sigevent te;
	struct itimerspec its;
	struct sigaction sa;
	int sigNo = SIGRTMIN;
	timer_t timerID;
	int res;
		
	// Store the data for sending once the timer expires
	uint8_t *dns_message;
	size_t size;
	
	/* Set up signal handler. */
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = timerHandler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sigNo, &sa, NULL) == -1) {
			perror("sigaction");
			return 1;
	}

	// Create timer
	te.sigev_notify = SIGEV_SIGNAL;
	te.sigev_signo = sigNo;
	te.sigev_value.sival_int = index;
	res = timer_create(CLOCK_REALTIME, &te, &timerID);
	if (res != 0) {
		printf("ERROR: timer_create %s\n", strerror(errno));
	}

	res = ldns_pkt2wire(&dns_message, atr_pkt, &size); //Allocs storage for packet
	if (size == 0) {
		printf("===========================SIZE ldns_pkt2wire failed\n");
	}

	atr_responses[index].socket = socket;
	atr_responses[index].response = dns_message;
	atr_responses[index].response_size = size;	
	atr_responses[index].client_addr = client_addr;
	atr_responses[index].timerid = timerID;

	// Set and enable alarm
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 10 * 1000000; // 10 ms delay for ATR packets
	res = timer_settime(timerID, 0, &its, NULL);
	if (res != 0) {
		printf("ERROR: timer_settime %s\n", strerror(errno));
	}
	
	// struct itimerspec curr_value;
	// timer_gettime(timerID, &curr_value);
	// printf("Timer interval: %d %d",curr_value.it_interval.tv_sec, curr_value.it_interval.tv_nsec);
	// printf("Timer remainder: %d %d",curr_value.it_value.tv_sec, curr_value.it_value.tv_nsec);
	// int t;
	// while(t=curr_value.it_value.tv_nsec != 0) {
	// 	if  (! t%10) {
	// 		printf("Remaining time: %d\n");
	// 	}
	// }
	return 0;
}

/****************************************
 * Clear a timer
 ***************************************/
int clearTimer(int index)
{
	timer_t timerID = atr_responses[index].timerid;
	timer_delete(timerID);
}

/*********************************************************************
 * get_first_free()
 * Execute from main thread, never from the within the signal handler
 *********************************************************************/
int get_first_free() {
	int i;
	int counter = 0;
	
	// basic linear search for an available slot
	for (i=0; i < MAX_OUTSTANDING_ATR; i++) {
		// printf("Scanning %d\n", i);
		if (atr_responses[i].in_use == 0) {
			atr_responses[i].in_use = 1;
			atr_responses[i].to_be_freed = 0;
			// printf("Got index:%d\n",i);
			return i;
		} else {
			counter++;
			if (counter > 20) {
				// printf("Cleaning\n");
				clean_atr();
				counter = 0;
			}
		}
	}
	return -1;
}

/*********************************************************************
 * clean_atr
 * Execute from main thread, never from the within the signal handler
 *********************************************************************/
int clean_atr() {
	int j;
	int counter = 0;
	
	// If we couldn't find a free slot, cleanup the to_be_freed entries
	// this is not efficient but it works for now
	for (j = MAX_OUTSTANDING_ATR-1; j >= 0 ; j--) {
		if (atr_responses[j].to_be_freed == 1) {
			// printf("Cleaning %d\n", j);
			
			free(atr_responses[j].client_addr);
			free(atr_responses[j].response);
			atr_responses[j].in_use = 0;
			atr_responses[j].to_be_freed = 0;
			counter++;
			if (counter > 19) { // Free 19 at a time
				break;
			}
		}
	}
	// printf("cleaned %d entries\n", counter);
	return;
}

