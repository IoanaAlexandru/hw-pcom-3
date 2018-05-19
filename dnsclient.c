//
// Copyright Ioana Alexandru 2018.
//

#include "dnsclient.h"

int main(int argc, char *argv[]) {
  // Checking arguments validity
  if (argc < 3) {
    fprintf(stderr, "Usage: %s name/ip query_type\n", argv[0]);
    exit(0);
  }

  char domain[MAX_NAME_LEN];
  strcpy(domain, argv[1]);

  enum domain_type domain_t = get_domain_type(domain);
  enum query_type query = get_query_type(argv[2]);

  if (domain_t == -1)
    error("Please enter a valid IP or domain name!\n");
  if (query == -1)
    error("Please enter a valid query type!\n");

  if (query == TXT && domain_t != NAME)
    error("The TXT query requires a domain name\n");
  if (query == PTR && domain_t != IP)
    error("The PTR query requires an IP\n");

  // Retrieving DNS server information from the CONF_FILE
  int conf_size;
  char **data = get_conf_data(&conf_size);

  // Opening UDP socket
  int sockUDP = socket(PF_INET, SOCK_DGRAM, 0);
  if (sockUDP < 0)
    error("ERROR opening socket!\n");

  // Initialising header
  dns_header_t header = init_header();

  // Initialising question
  char *qname = toQNAME(domain);
  dns_question_t question = init_question(query);

  // Creating message
  char *msg = calloc(BUFLEN, sizeof(char));
  size_t header_len = sizeof(header),
      qname_len = strlen(qname) + 1,
      question_len = sizeof(question);
  memcpy(msg, &header, header_len);
  memcpy(msg + header_len, qname, qname_len);
  memcpy(msg + header_len + qname_len, &question, question_len);

  // Logging message
  size_t msg_len = header_len + qname_len + question_len;
  log_msg(msg, msg_len);

  // Setting timeout value
  struct timeval time;
  time.tv_sec = TIMEOUT_SEC;
  time.tv_usec = TIMEOUT_USEC;

  // Setting up server
  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(53);

  // Setting up file descriptor set
  fd_set read_fds;
  FD_ZERO(&read_fds);
  FD_SET(sockUDP, &read_fds);

  // Initiating communication
  int i;
  ssize_t r;
  char buf[BUFLEN];
  char received[BUFLEN];
  enum error_status status = NOSERVER;
  printf("Trying \"%s\"\n", domain);

  for (i = 0; i < conf_size; i++) {
    if (inet_aton(data[i], &server.sin_addr) < 0)
      continue;

    socklen_t sockaddr_len = sizeof(struct sockaddr);
    if (sendto(sockUDP,
               msg,
               msg_len,
               0,
               (struct sockaddr *) &server,
               sockaddr_len) < 0) {
      status = SENDERROR;
      continue;
    }

    if (select(sockUDP + 1, &read_fds, NULL, NULL, &time) == 0) {
      status = NORESPONSE;
      continue;  // timeout
    }

    struct sockaddr_in host;
    r = recvfrom(sockUDP,
                 buf,
                 BUFLEN,
                 0,
                 (struct sockaddr *) &host,
                 &sockaddr_len);
    if (r < 0) {
      status = RECVERROR;
      continue;
    }

    // If the response has NOERROR status, or we're out of valid servers
    dns_header_t ans_header = parse_answer(buf, data[i]);
    if (ans_header.rcode == 0) {
      status = NOERROR;
      sprintf(received, "Received %zu bytes from %s\n", r, data[i]);
      break;
    } else if (i == conf_size - 1) {
      // If no more servers are available, print the last header
      print_header(ans_header);
    }
  }

  switch (status) {
    case NORESPONSE: error("No response from server(s)\n");
    case SENDERROR: error("Send failed.\n");
    case RECVERROR: error("Receive failed.\n");
    case NOSERVER: error("No valid servers.\n");
    case NOERROR: break;
  }

  printf("%s", received);

  close(sockUDP);
  for (i = 0; i <= conf_size; i++)
    free(data[i]);
  free(data);
  free(qname);
  free(msg);
}
