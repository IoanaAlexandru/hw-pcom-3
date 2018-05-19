#ifndef TEMA3_DNSCLIENT_H
#define TEMA3_DNSCLIENT_H

#define BUFLEN 512
#define MAX_IPS 20
#define MAX_NAME_LEN 256
#define MAX_QUERY_LEN 20
#define MAX_RDATA_LEN 50

#define CONF_FILE "dns_servers.conf"
#define MSG_LOG "message.log"
#define DNS_LOG "dns.log"

#define TIMEOUT_SEC 5
#define TIMEOUT_USEC 0

/* -- Query & Resource Record Type: -- */
// #define A     1   /* IPv4 address */
// #define NS    2   /* Authoritative name server */
// #define CNAME 5   /* Canonical name for an alias */
// #define MX    15  /* Mail exchange */
// #define SOA   6   /* Start of a zone of Authority */
// #define TXT   16  /* Text strings */

enum query_type {
  A = 1,
  NS = 2,
  CNAME = 5,
  MX = 15,
  SOA = 6,
  TXT = 16,
  PTR = 0,
  NONE = -1
};

enum domain_type { NAME = 1, IP = 2, INVALID = -1 };

enum error_status { NOERROR, NORESPONSE, SENDERROR, RECVERROR, NOSERVER };

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <memory.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <zconf.h>

/* -- Define DNS message format -- */
/* Header section format */
/**                             1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                       ID                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode   |AA|TC|RD|RA|   Z   |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct {
  // schimba (LITTLE/BIG ENDIAN) folosind htons/ntohs
  unsigned short id; // identification number

  // LITTLE -> BIG ENDIAN: inversare ’manuala’ ptr byte-ul 1 din flag-uri
  unsigned char rd :1; // recursion desired
  unsigned char tc :1; // truncated message
  unsigned char aa :1; // authoritive answer
  unsigned char opcode :4; // purpose of message
  unsigned char qr :1; // query/response flag: 0=query; 1=response

  // LITTLE -> BIG ENDIAN: inversare ’manuala’ ptr byte-ul 2 din flag-uri
  unsigned char rcode :4;
  unsigned char z :3;
  unsigned char ra :1;

  // schimba (LITTLE/BIG ENDIAN) folosind htons/ntohs
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
} dns_header_t;

/* Question section format */
/**
1 1 1 1 1 1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct {
  //qname variabil
  unsigned short qtype;
  unsigned short qclass;
} dns_question_t;

/* Resource record format */
/**
1 1 1 1 1 1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                     NAME                      /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     TYPE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct {
  //name variabil
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short rdlength;
  //rdata variabil;
} dns_rr_t;


// dnsutils.c
char **get_conf_data(int *conf_size);
enum query_type get_query_type(char *type);
enum domain_type get_domain_type(char *type);
dns_header_t init_header();
dns_question_t init_question(unsigned short qtype);
char* toQNAME(char *name);
dns_header_t get_header(char *buf);
void get_qtype_string(char *type, unsigned short qtype);
void get_qclass_string(char *class, unsigned short qclass);
int decompress_string(char *src, char *dest, int offset);
dns_question_t get_question(char *buf);
dns_rr_t get_rr(char *buf);
char *get_rdata(char *buf, dns_rr_t rr, int offset);

// parseutils.c
void log_msg(char *msg, size_t len);
dns_header_t parse_answer(char *ans, char *server);
void print_header(dns_header_t header);


static inline void error(char *msg) {
  fprintf(stderr, "%s", msg);
  exit(1);
}

#endif  // TEMA3_DNSCLIENT_H