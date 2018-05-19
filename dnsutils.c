//
// Copyright Ioana Alexandru 2018.
//

#include "dnsclient.h"

// Read a line from the sockd file descriptor, writing the
// data up to maxlen bytes at the vptr address
ssize_t readline(int sockd, void *vptr, size_t maxlen) {
  ssize_t n, rc;
  char c, *buffer;

  buffer = vptr;

  for (n = 1; n < maxlen; n++) {
    if ((rc = read(sockd, &c, 1)) == 1) {
      if (c == '\n')
        break;
      *buffer++ = c;
    } else if (rc == 0) {
      if (n == 1)
        return 0;
      else
        break;
    }
  }

  *buffer = 0;
  return n;
}

// Extract configuration data from the CONF_FILE, returning
// a vector of server addresses of size conf_size
char **get_conf_data(int *conf_size) {
  char buf[BUFLEN];
  int fd = open(CONF_FILE, O_RDONLY);

  char **data = calloc(MAX_IPS, sizeof(char *));

  if (fd < 0) {
    fprintf(stderr, "Failed to open conf file!\n");
    exit(0);
  }

  int i = 0;
  while (readline(fd, buf, BUFLEN)) {
    if (buf[0] != '#') {
      data[i] = calloc(BUFLEN, sizeof(char));
      strcpy(data[i], buf);
      i++;
    }
  }

  *conf_size = i - 1;

  close(fd);
  return data;
}

// Check if the value ∈ [0, 255]
bool is_byte(int n) {
  return n >= 0 && n <= 255;
}

// Find the domain type of a string, and reformat IPs for reverse lookup
enum domain_type get_domain_type(char *type) {
  int a, b, c, d;
  if (sscanf(type, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
    if (is_byte(a) && is_byte(b) && is_byte(c) && is_byte(d)) {
      sprintf(type, "%d.%d.%d.%d.in-addr.arpa", d, c, b, a);
      return IP;
    } else {
      return INVALID;
    }
  }
  return NAME;
}

// Get the query type value from a string
enum query_type get_query_type(char *type) {
  int i = 0;
  while (type[i]) {
    type[i] = (char) toupper(type[i]);  // ignore case
    i++;
  }

  if (strcmp(type, "A") == 0)  // Host Address
    return A;
  else if (strcmp(type, "MX") == 0) // Mail Exchange
    return MX;
  else if (strcmp(type, "NS") == 0) // Authoritative Name Server
    return NS;
  else if (strcmp(type, "CNAME") == 0) // Canonical name for alias
    return CNAME;
  else if (strcmp(type, "SOA") == 0) // Start of Zone of Authority
    return SOA;
  else if (strcmp(type, "TXT") == 0) // Text strings
    return TXT;
  else if (strcmp(type, "PTR") == 0) // Domain Name Pointer
    return PTR;
  else
    return NONE;
}

// Get query type string from value (the reverse of get_query_type)
void get_qtype_string(char *type, unsigned short qtype) {
  switch (qtype) {
    case A: strcpy(type, "A");
      break;
    case MX: strcpy(type, "MX");
      break;
    case NS: strcpy(type, "NS");
      break;
    case CNAME: strcpy(type, "CNAME");
      break;
    case SOA: strcpy(type, "SOA");
      break;
    case TXT: strcpy(type, "TXT");
      break;
    case PTR: strcpy(type, "PTR");
      break;
    default: strcpy(type, "UNDEFINED");
  }
}

// Get query class string from value (only one possible value, but implemented
// for the sake of extendability)
void get_qclass_string(char *class, unsigned short qclass) {
  switch (qclass) {
    case 1: strcpy(class, "IN");
      break;
    default: strcpy(class, "UNDEFINED");
  }
}

// Initialise a dns_header_t
dns_header_t init_header() {
  dns_header_t header;
  memset(&header, 0, sizeof(header));
  header.id = htons((uint16_t) getpid());  // using process id as transaction id
  header.rd = 1;
  header.qdcount = htons(1);
  return header;
}

// Initialise a dns_question_t
dns_question_t init_question(unsigned short qtype) {
  dns_question_t question;
  question.qtype = htons(qtype);
  question.qclass = htons(1);
  return question;
}

// Extract header from address
dns_header_t get_header(char *buf) {
  dns_header_t header;
  memcpy(&header, buf, sizeof(dns_header_t));
  header.qdcount = ntohs(header.qdcount);
  header.ancount = ntohs(header.ancount);
  header.nscount = ntohs(header.nscount);
  header.arcount = ntohs(header.arcount);
  return header;
}

// Extract question from address
dns_question_t get_question(char *buf) {
  dns_question_t question;
  memcpy(&question, buf, sizeof(dns_question_t));

  question.qclass = ntohs(question.qclass);
  question.qtype = ntohs(question.qtype);

  return question;
}

// Extract resource records from address
dns_rr_t get_rr(char *buf) {
  dns_rr_t rr;
  memcpy(&rr, buf, sizeof(dns_rr_t));

  rr.type = ntohs(rr.type);
  rr.class = ntohs(rr.class);
  rr.ttl = ntohl(rr.ttl);
  rr.rdlength = ntohs(rr.rdlength);

  return rr;
}

// Extract rdata from address buf + offset using information from rr
char *get_rdata(char *buf, dns_rr_t rr, int offset) {
  char *rdata = calloc(MAX_RDATA_LEN, sizeof(char));
  char str[MAX_NAME_LEN];
  unsigned int nr;

  switch (rr.type) {
    case A:
      sprintf(rdata,
              "%hhu.%hhu.%hhu.%hhu",
              *(buf + offset),
              *(buf + offset + 1),
              *(buf + offset + 2),
              *(buf + offset + 3));
      break;
    case NS:
    case PTR:
    case CNAME: decompress_string(buf, rdata, offset);
      break;
    case MX: decompress_string(buf, str, offset + 2);
      sprintf(rdata, "%hhu %s", *(buf + offset + 1), str);
      break;
    case SOA: offset += decompress_string(buf, rdata, offset);
      size_t len = strlen(rdata);
      rdata[len] = ' ';
      offset += decompress_string(buf, rdata + len + 1, offset);
      for (int i = 0; i < 5; i++) {
        memcpy(&nr, buf + offset, 4);
        sprintf(rdata, "%s %d", rdata, ntohl(nr));
        offset += 4;
      }
      break;
    case TXT: memcpy(rdata, buf + offset, rr.rdlength);
      break;
    default:sprintf(rdata, "UNDEFINED");
  }

  return rdata;
}

// Convert a string to the QNAME format
char *toQNAME(char *name) {
  char *qname = calloc(MAX_NAME_LEN, sizeof(char));
  char copy[MAX_NAME_LEN];
  strcpy(copy, name);
  char *tok = strtok(copy, ".");
  unsigned char tok_len, len = 0;

  while (tok != NULL) {
    tok_len = (char) strlen(tok);
    qname[len++] = tok_len;
    strcpy(qname + len, tok);
    len += tok_len;
    tok = strtok(NULL, ".");
  }

  return qname;
}

// Check if the first two bits of a 16-bit sequence are set
bool is_pointer(unsigned short sequence) {
  // if the first two bits are 1 => sequence >> 14 == 0x11 = 3
  return (sequence >> 14u) == 3;
}

// Decompress a compressed message section at src + offset, knowing that src is
// the beginning of the whole message and writing result to dest
// Return value is the length of the data that was decompressed
int decompress_string(char *src, char *dest, int offset) {
  int i = offset;
  size_t dest_len = 0;
  unsigned short sequence;
  while (src[i]) {
    memcpy(&sequence, src + i, 2);
    sequence = ntohs(sequence);

    if (is_pointer(sequence)) {
      int new_offset = sequence & (unsigned) 0xFFF;  // clearing first two bits
      decompress_string(src, dest + dest_len, new_offset);
      i += 2;
      return i - offset;
    } else {  // sequence is a label
      for (int j = 0; j < src[i]; j++)
        dest[dest_len++] = src[i + j + 1];
      dest[dest_len++] = '.';
      i += src[i] + 1;
      if (!src[i]) {
        dest[dest_len] = 0;
        i++;
        return i - offset;
      }
    }
  }
  return i - offset;
}