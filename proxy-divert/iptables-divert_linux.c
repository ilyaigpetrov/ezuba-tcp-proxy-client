#include <sys/socket.h>
#include <errno.h>
#include <string.h> //memset
#include <stdio.h>
#include <netinet/ip.h> // IPPROTO_TCP
#include <netinet/tcp.h>
#include <arpa/inet.h> // inet_ntoa
#include <linux/netfilter_ipv4.h>
#include <unistd.h> // close(sock)

typedef struct {
  char* error;
  int socket;
} SOCKET;

char* getLastErrorMessage() {
  return strerror(errno);
}

SOCKET createTcpRawSocket() {

  SOCKET result;
  result.error = NULL;

  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  if(s == -1)
  {
    result.error = getLastErrorMessage();
    return result;
  }
  result.socket = s;
  return result;

}

static int getdestaddrIptables(int fd, struct sockaddr_in *destaddr)
{
  socklen_t socklen = sizeof(*destaddr);
  int error;

  error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
  if (error) {
    return errno;
  }
  destaddr->sin_port = ntohs(destaddr->sin_port);
  return 0;
}

SOCKET createTcpListeningSocket(unsigned long ip, int port) {

  SOCKET result;
  result.error = NULL;

  int s = socket(AF_INET, SOCK_STREAM , 0);
  if(s == -1)
  {
    result.error = getLastErrorMessage();
    return result;
  }
  result.socket = s;
  struct sockaddr_in server;
  server.sin_addr.s_addr = ip;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);

  if( bind(s, (struct sockaddr *)&server , sizeof(server)) < 0)
  {
    result.error = getLastErrorMessage();
    return result;
  }
  listen(s, 5);

  result.socket = s;
  return result;

}

SOCKET createTcpConnectingSocket(char* ip) {

  SOCKET result;
  result.error = NULL;

  int s = socket(AF_INET, SOCK_STREAM , 0);
  if(s == -1)
  {
    result.error = getLastErrorMessage();
    return result;
  }
  result.socket = s;

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(ip);
  server.sin_port = 0;

  if( bind(s, (struct sockaddr *)&server , sizeof(server)) < 0)
  {
    result.error = getLastErrorMessage();
    return result;
  }

  int c;
  if (getsockname(s, (struct sockaddr *)&server, (socklen_t*)&c) < 0)
  {
    result.error = getLastErrorMessage();
    return result;
  }

  if (connect(s , (struct sockaddr *)&server , sizeof(server)) < 0)
  {
    result.error = getLastErrorMessage();
    return result;
  }

  result.socket = s;
  return result;
}


typedef struct {
  int clientSocket;
  struct sockaddr_in sockaddr;
  int addrLen;
  char* error;
} CONN;

CONN acceptTcpSocket(int s) {

  CONN result;
  result.error = NULL;
  struct sockaddr_in client;
  int c, clientSocket;

  clientSocket = accept(s, (struct sockaddr *)&client, (socklen_t*)&c);

  client.sin_port = ntohs(client.sin_port);
  //client.sin_addr.s_addr = ntohl(client.sin_addr.s_addr);

  result.clientSocket = clientSocket;
  result.sockaddr = client;
  result.addrLen = c;
  return result;

}

int injectTcpPacket(int socket, void* packetData, int n, struct sockaddr sin) {

  int res = sendto(socket, packetData, n, 0, (struct sockaddr *) &sin, sizeof (sin));
  if (res < 0) {
    return errno;
  }
  return 0;

}

typedef void (*packetHandler) (int, void*, int);

int subscribeToTcpPackets(int s, packetHandler handlePacket) {

  int maxIpPacketSize = 65535;
  char packetData[maxIpPacketSize];
  memset(packetData, 0, maxIpPacketSize);
  while(1) {
    int n = recv(s, packetData, maxIpPacketSize, 0);
    //printf("Received %d bytes\n", n);
    if (n > 0) {
      handlePacket(s, packetData, n);
    }
  }

  return 0;

}

void handlePacket(int s, void* packetData, int n) {

  const struct ip* ippacket = (struct ip*)(packetData);
  unsigned int size_ip = ippacket->ip_hl * 4;
  struct tcphdr *tcp_hdr = (struct tcphdr*)(packetData + size_ip);
  int srcPort = ntohs(tcp_hdr->th_sport);
  int dstPort = ntohs(tcp_hdr->th_dport);

  if (dstPort != 2222) {
    return;
  }

  printf("The source IP address is %s\n", inet_ntoa(ippacket->ip_src));
  printf("The destination IP address is %s\n", inet_ntoa(ippacket->ip_dst));

  printf("Source port: %d\n", srcPort);
  printf("Dest port: %d\n", dstPort);

  struct sockaddr_in* destaddr;
  destaddr->sin_family = AF_INET;
  destaddr->sin_port = srcPort;
  destaddr->sin_addr = ippacket->ip_src;

  socklen_t socklen = sizeof(*destaddr);
  int error;

  error = getsockopt(s, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
  if (error) {
    perror("FAIL FAIL FAIL");
    return;
  }
  puts("SUCCESS");

}

/*
int main(void) {

  SOCKET s = createTcpListeningSocket(2222);
  if (s.error) {
    puts(s.error);
    return 1;
  }
  CONN conn = acceptTcpSocket(s.socket);
  if (conn.error) {
    puts("Accept error");
    puts(conn.error);
    return 1;
  }
  puts("Everything is fine!");
  struct sockaddr_in sin = conn.sockaddr;
  printf("Packet from %s:%d\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

  close(s.socket)
  close(s.clientSocket)

  return 0;

}
*/
