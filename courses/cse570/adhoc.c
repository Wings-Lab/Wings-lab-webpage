#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MYPORT "4950"    /* the port users will be connecting to */
#define SERVERPORT 4950	/* the port users will be connecting to */
#define MAXBUFLEN 100	
#define SLEEPTIME 100 /* for getting location fingerprints, in millis */
#define BCAST_THREAD_SLEEP 100
#define LISTEN_THREAD_SLEEP 100

/* get the corresponding ip address */
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr); /* ipv6, just a checking,u wud probably never need it :D */
}


/* The threadScan function scans the set of access points in your surroundings and dump its
   address and signal strength in the location.txt file. New data will be appended to the file
   and it wont be overwritten, but for you convinience, you can keep separate sets of location
   traces per experiment */
void *threadScan(void *arg){

 while(1) {
	 system("date >> dump_loc.txt"); /* log system date, that is timestamp for the location */

	 char command[50];
	 strcpy(command, "iwlist ");
	 strcat(command, (char*)arg);
	 strcat(command, " scanning | grep -E \"Address|Signal\" >> dump_loc.txt");
	 system(command);  /* format "iwlist interface_name scanning" */

/* "iwlist interface scanning", where interface could be eth0 or wlan or ath0, depening on your machine,
    it will scan the access points around, extra information per AP is also available. iwlist command
    belongs to the set of wireless-tools for linux, for details see,
    http://en.wikipedia.org/wiki/Wireless_tools_for_Linux 
    if you dont have wireless tools, install it, apt-get install wireless-tools 
*/
 
sleep(SLEEPTIME); /* a timegap between each fingerprint */
 }

}


/* Function fo broadcasting the packets */
void *threadBcast(void *arg)
{
	int sockfd;
	struct sockaddr_in their_addr; // connector's address information
	struct hostent *he;
	int numbytes;
	int broadcast = 1;

	char* ipaddress;
	ipaddress = (char*)arg;
	int sent = 0;

	if ((he=gethostbyname(ipaddress)) == NULL) {  // get the host info
		perror("gethostbyname");
		exit(1);
	}
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	// this call is what allows broadcast packets to be sent:
	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast,
		sizeof broadcast) == -1) {
		perror("setsockopt (SO_BROADCAST)");
		exit(1);
	}

	their_addr.sin_family = AF_INET;	 // host byte order
	their_addr.sin_port = htons(SERVERPORT); // short, network byte order
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);
	
	while(1){

		FILE* fp = fopen("dump_bcast.txt", "a+");
		sent++;
		numbytes = sendto(sockfd, "data", strlen("data"), 0, (struct sockaddr *)&their_addr, sizeof their_addr);
		/*printf("sent %d bytes to %s %d\n", numbytes,inet_ntoa(their_addr.sin_addr),sent); */ /*debug er jonno*/
		 
		/* Preparing the output, we will only give the timestamps of the broadcast */
		 time_t rawtime;
		 struct tm * timeinfo;
	         time ( &rawtime );
		 timeinfo = localtime ( &rawtime );
		 //printf ( "Time: %s \n", asctime (timeinfo) ); /*apatato dorkar nei eta debar*/
		int i = strlen(asctime(timeinfo));
		int j;
		char enc[100];
		strcpy(enc, asctime(timeinfo));

		fprintf(fp, "%s ", enc);	/* printing timestamps end here*/
		fprintf(fp, "%d \n", sent);	/* sent end */
		fclose(fp);
		sleep(BCAST_THREAD_SLEEP);
	}

	close(sockfd);
	return 0;
 }


/* Function to listen for packets */
void *threadListen(void *arg)
{

    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;
    struct sockaddr_storage their_addr;
    char buf[MAXBUFLEN];
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];

    int received = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(servinfo);
    printf("listener: waiting to receive ...\n");
    addr_len = sizeof their_addr;

    while(1){

        FILE* fp = fopen("dump_list.txt", "a+");

  	if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
       	 perror("recvfrom");
       	 exit(1);
  	}
	received++;
	buf[numbytes] = '\0';

		 time_t rawtime;	/* time information begins */
		 struct tm * timeinfo;
	         time ( &rawtime );
		 timeinfo = localtime ( &rawtime );
		
			char enc[100];
			strcpy(enc, asctime(timeinfo));

			fprintf(fp, "%s ", enc);
			fprintf(fp, "%d ", received); /* received information ends */
			strcpy(enc, inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s));
			fprintf(fp, "%s \n", enc ); /* sender info */
		
		fclose(fp);
		sleep(LISTEN_THREAD_SLEEP);
	}

    close(sockfd);
    return 0;
}


int main(int argc, char* argv[])
{
	
	if (argc != 3) {
		fprintf(stderr,"usage: ./a.out broadcast_address wireless_interface\n");
		exit(1);
	}

	/* so we will be using three threads running the three above defined functions
           for location scanning, broadcasting data and receiving data */
	pthread_t pth1, pth2, pth3;	// this is our thread identifier
	pthread_create(&pth1,NULL,threadBcast, argv[1]); /* arg[1] is the broadcast address of your ad-hoc network, maybe something like 10.42.43.255 */
	pthread_create(&pth2,NULL,threadListen,"listen");
	pthread_create(&pth3,NULL,threadScan, argv[2]); /* arg[2] is your wireless interface, just do a ifconfig and check it out. */
	pthread_join(pth1,NULL);
	pthread_join(pth2,NULL);
	pthread_join(pth3,NULL);
	return 0;
}
