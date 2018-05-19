//
// Copyright Ioana Alexandru 2018.
//

#include "dnsclient.h"

// Print a message (printf-like arguments) to both stdout and fd
void print_and_log(int fd, char *msg,...) {
  char buf[BUFLEN];
  va_list args;
  va_start(args, msg);
  vsprintf(buf, msg, args);
  write(fd, buf, strlen(buf));
  printf("%s", buf);
  va_end(args);
}


// Save message of length len in MSG_LOG as hex segments
void log_msg(char *msg, size_t len) {
  int fd = open(MSG_LOG, O_CREAT | O_APPEND | O_WRONLY, 0755);

  if (fd < 0)
    error("Could not open message log file.\n");

  char hex[10];

  for (int i = 0; i < len; i++) {
    sprintf(hex, "%02X ", msg[i]);
    write(fd, hex, 3);
  }

  write(fd, "\n", 1);
  close(fd);
}

// Print header using the host -v command format
void print_header(dns_header_t header) {
  printf(";; ->>HEADER<<- opcode: ");
  switch (header.opcode) {
    case 0: printf("QUERY");
      break;
    case 1: printf("IQUERY");
      break;
    case 2: printf("STATUS");
      break;
    default: printf("INVALID");
  }
  printf(", status: ");
  switch (header.rcode) {
    case 0: printf("NOERROR");
      break;
    case 1: printf("FORMATERROR");
      break;
    case 2: printf("SERVERFAILURE");
      break;
    case 3: printf("NAMEERROR");
      break;
    case 4: printf("NOTIMPLEMENTED");
      break;
    case 5: printf("REFUSED");
      break;
    default: printf("INVALID");
  }
  printf(", id: %d\n;; flags:", header.id);
  if (header.qr)
    printf(" qr");
  if (header.aa)
    printf(" aa");
  if (header.tc)
    printf(" tc");
  if (header.rd)
    printf(" rd");
  if (header.ra)
    printf(" ra");
  printf("; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n",
         header.qdcount, header.ancount, header.nscount, header.arcount);
}

// Interpret, print and log a number of count rdata sections starting at the
// address ans + offset
void parse_rrdata(int count, char *ans, int *offset, int fd) {
  char name[BUFLEN], qclass[MAX_QUERY_LEN], qtype[MAX_QUERY_LEN], *rdata = NULL;
  while (count) {
    *offset += decompress_string(ans, name, *offset);
    dns_rr_t rr = get_rr(ans + *offset);

    *offset += sizeof(dns_rr_t) - 2;

    get_qclass_string(qclass, rr.class);
    get_qtype_string(qtype, rr.type);
    rdata = get_rdata(ans, rr, *offset);
    print_and_log(fd, ";%s %s %s %s\n", name, qclass, qtype, rdata);

    *offset += rr.rdlength;

    count--;
  }
  if (rdata != NULL)
    free(rdata);
}

// Print and log the sections in the received answer at address ans
dns_header_t parse_answer(char *ans, char *server) {
  char qname[BUFLEN], buf[BUFLEN], qtype[MAX_QUERY_LEN], qclass[MAX_QUERY_LEN];
  int offset = 0, len;
  dns_header_t header = get_header(ans);
  offset += sizeof(dns_header_t);

  if (header.rcode != 0)
    return header;

  print_header(header);

  if (header.qdcount) {
    printf(";; QUESTION SECTION:\n");

    while (header.qdcount) {
      len = decompress_string(ans, qname, offset);
      offset += len;
      dns_question_t question = get_question(ans + offset);
      offset += sizeof(question);

      get_qtype_string(qtype, question.qtype);
      get_qclass_string(qclass, question.qclass);
      printf(";%s %s %s\n\n", qname, qclass, qtype);

      header.qdcount--;
    }
  }

  int fd = open(DNS_LOG, O_APPEND | O_CREAT | O_WRONLY, 0755);

  if (fd < 0)
    error("Could not open message log file.\n");

  sprintf(buf, "; %s - %s %s\n\n", server, qname, qtype);
  write(fd, buf, strlen(buf));

  if (header.ancount) {
    print_and_log(fd, ";; ANSWER SECTION:\n");
    parse_rrdata(header.ancount, ans, &offset, fd);
    print_and_log(fd, "\n");
  }

  if (header.nscount) {
    print_and_log(fd, ";; AUTHORITY SECTION:\n");
    parse_rrdata(header.nscount, ans, &offset, fd);
    print_and_log(fd, "\n");
  }

  if (header.arcount) {
    print_and_log(fd, ";; ADDITIONAL SECTION:\n");
    parse_rrdata(header.arcount, ans, &offset, fd);
    print_and_log(fd, "\n");
  }

  write(fd, "\n", strlen("\n"));

  close(fd);
  return header;
}