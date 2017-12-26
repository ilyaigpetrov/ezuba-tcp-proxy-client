#include <sys/socket.h>
#include <errno.h>
#include <string.h> //memset
#include <stdio.h>
#include <netinet/ip.h> // IPPROTO_TCP
#include <netinet/tcp.h>
#include <arpa/inet.h> // inet_ntoa
#include <linux/netfilter_ipv4.h>

typedef struct {
  char* error;
  int socket;
} SOCKET;

SOCKET createTcpSocket() {

  SOCKET result;
  result.error = NULL;

  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  if(s == -1)
  {
    result.error = strerror(errno);
    return result;
  }
  result.socket = s;
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

  SOCKET s = createTcpSocket();
  if (s.error) {
    puts(s.error);
    return 1;
  }
  subscribeToTcpPackets(s.socket, handlePacket);
  return 0;

}
*/
