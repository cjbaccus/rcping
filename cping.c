//  curses based ping and traceroute
//  Willem A Scheuder
//  willem@prinmath.com
//
//  Version     Date       Remarks
//    1.0   Jun 25, 2018   Initial release
//    2.0   Jul 21, 2020   Numbered pings and stats
//    2.1   Aug 26, 2020   Windows support; Save to file
//    2.2   Jun 24, 2021   Advance/reverse time
//    2.3   May 22, 2022   Allow options in config file
//    2.4   Jun 24, 2026   Set ICMP packet size
//
//  This code is released under the GNU Public License Version 2.

#define VER "2.4.0"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
//  For Windows use PDCurses
#ifdef __CYGWIN__
#include "pdcurses.h"
#else
#include <ncurses.h>
#endif
//  Buttons for GPIO (BCM names)
#ifdef piGPIO
#include <pigpio.h>
int SW[] = {27,23,22,17};
double swt=0;
#endif
//  CYGWIN missing ICMP definitions
#ifdef __CYGWIN__
#define ICMP_ECHO           8 // Echo Request
#define ICMP_ECHOREPLY      0 // Echo Reply
#define ICMP_UNREACH        3 // Echo Unreachable
#define ICMP_TIME_EXCEEDED 11 // Echo Time Exceeded
#endif
//  OSX renames ICMP_TIME_EXCEEDED
#ifdef __APPLE__
   #define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#endif
//  OSX and CYGWIN missing struct icmphdr
#if defined(__APPLE__) || defined(__CYGWIN__)
   struct icmphdr
   {
      u_int8_t  type;
      u_int8_t  code;
      u_int16_t checksum;
      union
      {
         struct
         {
            u_int16_t id;
            u_int16_t sequence;
         } echo;
         u_int32_t gateway;
      } un;
   };
#endif
//  CYGWIN predefines optarg
#ifndef __CYGWIN__
extern char *optarg;
extern int  optind,opterr;
#endif

//  Option string
#ifdef piGPIO
#define OPTSTR "vbanrxthSm:s:p:f:c:o:N:g"
#else
#define OPTSTR "vbanrxthSm:s:p:f:c:o:N:"
#endif

//  Maximum size of ICMP packet
#define MAXSZ 1024

//  Help text
const char* help =
   "PgUp   Scroll up\n"
   "PgDn   Scroll down\n"
   "  ^    Select previous router\n"
   "  v    Select next router\n"
   " <-    Reverse time a second\n"
   " ->    Advance time a second\n"
   "  -    Reverse time a minute\n"
   "  +    Advance time a minute\n"
   " End   Current time\n"
   "  0    Reset stats\n"
   "ENTER  Traceroute to router\n"
   " ESC   Return to ping screen\n"
   "  i    Invert colors\n"
   "  r    Reverse direction\n"
   "  t    Toggle time statistics\n"
   "  S    Toggle sound for all\n"
   "  s    Toggle sound for selected\n"
   "  a    Toggle address\n"
   "  n    Toggle hop count\n"
   "  c    Toggle character\n"
#ifdef piGPIO
   "  g    Enable pi GPIO access\n"
#endif
   "  h    Help\n"
   "  q    Quit program\n";

//  Ping TTL
#define pTTL 64
//  Trace TTL
#define tTTL 24
//  Max length of ping trace in seconds
#define nsec 3600
//  Special ping values
enum {NoPing=0xFF,LostPing=0xFE,LatePing=0xFD};

typedef struct
{
   int    n;    // Count
   double S;    // Sum
   double S2;   // Sum of squares
   double min;  // Minimum ping
   double max;  // Maximum ping
   double avg;  // Average ping
   double std;  // Standard deviation
   int    lost; // Lost packets
   int    late; // Late packets
} Stat;
typedef struct
{
   int     cur;       // Current index
   uint8_t buf[nsec]; // Buffer of replies
} Ping;
typedef struct
{
   in_addr_t ip;    // IP address
   char*     fqdn;  // Display name
   char*     addr;  // IP address text
} DNS;
typedef struct
{
   in_addr_t ip;   // IP address
   char*     fqdn; // FQDN
   char*     addr; // IP address text
   double    dt;   // milliseconds
   Ping      ping; // Ping replies
   Stat      stat; // Statistics
} Trace;
typedef struct
{
   char*           hdr;    // Header
   char*           name;   // Display name
   char*           host;   // Hostname or IP
   int             silent; // Do not beep
   double          dt;     // milliseconds
   Ping            ping;   // Ping replies
   Stat            stat;   // Statistics
   int             ttl;    // TTL
   struct in_addr  ip;     // IP address
   struct sockaddr sa;     // Socket address
} Target;

int     mode=0;       //  Mode 1=traceroute, 0=ping, -1=help
int     delt=0;       //  Time offset
int     white=1;      //  White background
int     sbp=1;        //  Seconds between ping
int     r2l=1;        //  Right to left
int     ntar;         //  Number of targets
int     nhdr;         //  Number of header lines
int     sel=0;        //  Selected target
Target* pt;           //  Ping target
int     sock;         //  ICMP socket
int     pingid;       //  PID to identify ping packets
int     seq;          //  Ping sequence number
int     minsz=0;      //  Minimum ICMP packet size
int     wid=0;        //  Window width
int     hgt=0;        //  Window height
int     top=0;        //  Top entry in display
int     nping;        //  Number of pings shown
int     nwid;         //  Name width
int     awid;         //  Addres width
pthread_t rd;         //  Read thread
pthread_t wr;         //  Write thread
int     show=1;       //  Update display
Trace*  tt;           //  Traceroute array
int     tseq;         //  Trace sequence number
int     hop=1;        //  Show hops with ping table
int     nhop=0;       //  Number of traceroute hops
int     stat=0;       //  Display ping time stats
int     traceid;      //  PID to identify ping packets
DNS*    dns;          //  DNS
int     ndns;         //  Number of DNS entries
int     maxdns;       //  Maximum DNS entries
int     silent=0;     //  Do not beep
int     showip=0;     //  Show IP address
int     pus=1000;     //  Time between pings (in uS)
char    pch=0;        //  Ping character
int     ich=0;        //  Ping symbol
int     swx=0;        //  Switch
FILE*   fout=0;       //  Output file
int     num=0;        //  Number of pings before stopping
int     total=0;      //  Total pings
int     run=1;        //  Continue running

//
//  Current time (double)
//
void timeprint(void)
{
   time_t t =  time(NULL)-delt;
   struct tm*  l = localtime(&t);
   printw("%4d-%.2d-%.2d %.2d:%.2d:%.2d",l->tm_year+1900,l->tm_mon+1,l->tm_mday,l->tm_hour,l->tm_min,l->tm_sec);
   if (delt) printw(" dt=%d",delt);
   printw("   #%d  Period %ds Ping time",seq,sbp);
   if (ich==3)
   {
      attron(A_BOLD);
      attron(COLOR_PAIR(2));
      printw(" x1");
      attron(COLOR_PAIR(3));
      printw(" x10");
      attron(COLOR_PAIR(4));
      printw(" x100");
      attron(COLOR_PAIR(5));
      printw(" x1000");
      attroff(A_BOLD);
   }
   else
   {
      attron(COLOR_PAIR(2));
      printw(" <10");
      attron(COLOR_PAIR(3));
      printw(" 10-99");
      attron(COLOR_PAIR(4));
      printw(" 100-999");
      attron(COLOR_PAIR(5));
      printw(" >1000");
   }
   if (silent)
   {
      attron(COLOR_PAIR(5));
      printw(" SILENT");
   }
   attron(COLOR_PAIR(1));
   printw("\n");
}

//
//  Current time (double)
//
double now(void)
{
   struct timeval tv;
   gettimeofday(&tv,(struct timezone *)NULL);
   return tv.tv_sec + ((double)tv.tv_usec)/1000000;
}

//
//  Print error and exit
//
void Fatal(const char* format , ...)
{
   va_list args;
   //  wid>0 indicates curses active
   if (wid>0) endwin();
   //  Print error
   va_start(args,format);
   vfprintf(stderr,format,args);
   va_end(args);
   exit(1);
}

//
//  Initialize DNS cache structure
//
void InitDNS()
{
   maxdns = 1024;
   dns = (DNS*)malloc(maxdns*sizeof(DNS));
   if (!dns) Fatal("Cannot allocate DNS memory");
   ndns = 1;
   dns[0].ip = 0;
   dns[0].fqdn = "*";
   dns[0].addr = "*";
}

//
//  Look up DNS address with local cache
//
int nslookup(Trace* tr)
{
   //  Look up IP address
   for (int k=0;k<ndns;k++)
      if (tr->ip == dns[k].ip)
      {
         tr->addr = dns[k].addr;
         tr->fqdn = dns[k].fqdn;
         return strlen(dns[k].fqdn);
      }
   //  Increase array if necessary
   int k = ndns++;
   if (ndns>maxdns)
   {
      maxdns += 1024;
      dns = (DNS*)realloc(dns,maxdns*sizeof(DNS));
      if (!dns) Fatal("Cannot allocate DNS memory");
   }
   //  Set IP
   dns[k].ip = tr->ip;
   char addr[16];
   inet_ntop(AF_INET,&tr->ip,addr,16);
   tr->addr = dns[k].addr = malloc(16);
   strcpy(dns[k].addr,addr);
   //  Look up hostname
   struct hostent* he = gethostbyaddr((char*)&tr->ip,sizeof(in_addr_t),AF_INET);
   if (he)
   {
      tr->fqdn = dns[k].fqdn = malloc(strlen(he->h_name)+1);
      strcpy(dns[k].fqdn,he->h_name);
   }
   else
      tr->fqdn = dns[k].fqdn = dns[k].addr;
   //  Return length
   return strlen(dns[k].fqdn);
}

//
//  Initialize statistics
//
void InitStat(Stat* stat)
{
   stat->n    = 0;
   stat->S    = 0;
   stat->S2   = 0;
   stat->min  = -1;
   stat->max  = -1;
   stat->avg  = -1;
   stat->std  = -1;
   stat->lost = -1;
   stat->late =  0;
}

//
//  Initialize ping buffer
//
void InitPing(Ping* ping)
{
   ping->cur = nsec-1;
   for (int i=0;i<nsec;i++)
      ping->buf[i] = NoPing;
}

//
//  Set pings
//
static inline void SetPing(Ping* ping,int off,uint8_t val)
{
   int k = (ping->cur+off) % nsec;
   ping->buf[k] = val;
}

//
//  Get pings
//
static inline uint8_t GetPing(Ping* ping,int off)
{
   int k = (ping->cur+off+delt) % nsec;
   return ping->buf[k];
}

//
//  Initialize traceroute
//
void InitTrace()
{
   tseq=0;
   for (int k=0;k<tTTL;k++)
   {
      InitStat(&tt[k].stat);
      InitPing(&tt[k].ping);
   }
}

//
//  Options
//
int CheckOpt(char ch,char* charg)
{
   //  Black background
   if (ch == 'b')
      white = 0;
   //  Do not show hops
   else if (ch == 'n')
      hop = 0;
   //  Minimum packet size
   else if (ch == 'm')
   {
      minsz = atoi(charg);
      if (!minsz)
        Fatal("Invalid -m %s\n",charg);
      else if (minsz<sizeof(struct icmphdr)+sizeof(double))
        Fatal("-m too small %s\n",charg);
      else if (minsz>MAXSZ)
        Fatal("-m too large %s\n",charg);
   }
   //  Reverse direction
   else if (ch == 'r')
      r2l = 0;
   //  Microseconds between pings
   else if (ch == 'p')
   {
      pus = atoi(charg);
      if (pus<1) Fatal("Invalid -p %s\n",charg);
   }
   //  Show address
   else if (ch == 'a')
      showip = 1;
   //  Show numbers
   else if (ch == 'x')
      ich = 3;
   //  Show stats
   else if (ch == 't')
      stat = 1;
   //  Seconds beteen ping groups
   else if (ch == 's')
   {
      sbp = atoi(charg);
      if (sbp<1 || sbp>5) Fatal("Invalid -s %s\n",charg);
   }
   //  Ping character
   else if (ch == 'c')
      pch = charg[0];
   //  Output file
   else if (ch == 'o')
   {
      fout = fopen(charg,"w");
      if (!fout) Fatal("Cannot open output file %s\n",charg);
   }
   //  Number of pings
   else if (ch == 'N')
   {
      num = atoi(charg);
      if (num<1) Fatal("Invalid -N %d\n",num);
   }
   //  Silent
   else if (ch == 'S')
   {
      silent = 1;
   }
   else
      return 0;
   return 1;
}

//
//  Read configuration file
//
void ReadConfig(char* file[],const int nfile)
{
   char line[1024];
   int maxn=0;

   //  Initialize
   ntar = 0;
   nhdr = 0;
   seq  = 0;
   nwid = 6;  //  Minimum width
   awid = 6;  //  Addres width
   //  Initialize Traceroute array (max number of entries it tTTL)
   tt = (Trace*)malloc(tTTL*sizeof(Trace));
   //  Open first file in the list that is readable
   FILE* f=0;
   for (int k=0;k<nfile && !f;k++)
      f = fopen(file[k],"r");
   //  Cannot open any of the files
   if (!f)
   {
      fprintf(stderr,"Cannot open file %s",file[0]);
      for (int k=1;k<nfile;k++)
         fprintf(stderr," or %s",file[k]);
      Fatal("\n");
   }
   //  
   //  Read first 3 characters to check BOM
   unsigned char magic[3];
   if (fread(magic,1,3,f)==3 && magic[0]==0xEF && magic[1]==0xBB && magic[2]==0xBF)
      fprintf(stderr,"WARNING: UTF-8 file treated as ASCII\n");
   else
      rewind(f);

   //  Read line
   int  indent=0;
   char* hdr=0;
   while (fgets(line,sizeof(line),f) != NULL )
   {
      char host[256];
      //  Skip comments
      if (line[0] == '#') continue;
      //  Trim trailing whitespace
      int l=strlen(line)-1;
      while (l>0 && isspace((int)line[l-1])) l--;
      line[l] = 0;
      //  Skip blank lines
      if (l==0) continue;
      //  Header line
      if (line[0] == '>')
      {
         //  Reset indent
         if (l==1 && indent>0)
            hdr = 0;
         //  Add header
         else
         {
            nhdr++;
            hdr = malloc(l+1);
            memcpy(hdr,line+1,l);
         }
         indent = l>1?3:0;
         continue;
      }
      //  Option line
      if (line[0] == '-')
      {
         char charg[257] = "";
         sscanf(line+2,"%256s",charg);
         if (!CheckOpt(line[1],charg))
           Fatal("Invalid option in config file\n%s\n",file,line);
         continue;
      }
      //  Next target
      if (ntar+1>maxn)
      {
         maxn += 32;
         pt = (Target*)realloc(pt,maxn*sizeof(Target));
         if (!pt) Fatal("Out of memory allocating ping targets\n");
      }
      //  Set header
      pt[ntar].hdr = hdr;
      if (hdr) hdr = 0;
      //  Get hostname/ip and offset to start of display name
      int i;
      if (sscanf(line,"%255s %n",host,&i)!=1) Fatal("Error reading address: %s\n",line);
      //  Save display name and host name
      if (l>i)
      {
         //  Display name
         l = l-i+indent;
         pt[ntar].name = malloc(l+1);
         for (int j=0;j<indent;j++)
            pt[ntar].name[j] = ' ';
         memcpy(pt[ntar].name+indent,line+i,l-indent+1);
         if (l>nwid) nwid = l;
         //  Hostname
         l = strlen(host);
         pt[ntar].host = malloc(l+1);
         memcpy(pt[ntar].host,host,l+1);
         if (l>awid) awid = l;
      }
      //  Use host name as display name
      else
      {
         l = strlen(host)+indent;
         pt[ntar].name = malloc(l+1);
         for (int j=0;j<indent;j++)
            pt[ntar].name[j] = ' ';
         memcpy(pt[ntar].name+indent,host,l+1-indent);
         if (l>nwid) nwid = l;
         //  Blank host name
         pt[ntar].host = malloc(1);
         pt[ntar].host[0] = 0;
      }
      //  Enable beep
      pt[ntar].silent = 0;
      //  Initialize pings
      pt[ntar].dt = -1;
      InitPing(&pt[ntar].ping);
      InitStat(&pt[ntar].stat);
      //  Get IP address
      struct hostent* he = gethostbyname(host);
      if (!he) Fatal("Cannot resolve host name %s\n",host);
      memcpy(&pt[ntar].ip.s_addr,he->h_addr_list[0],4);
      //  Set up sa as an IP socket
      memset(&pt[ntar].sa,0,sizeof(struct sockaddr));
      struct sockaddr_in *isa = (struct sockaddr_in*)&pt[ntar].sa;
      isa->sin_family = AF_INET;
      isa->sin_addr.s_addr = pt[ntar].ip.s_addr;
      //  Check for duplicate IP addresses
      for (i=0;i<ntar;i++)
         if (pt[ntar].ip.s_addr==pt[i].ip.s_addr)
           Fatal("%s has a duplicate IP\n",pt[ntar].name);
      //  Increment ntar
      ntar++;
   }
   fclose (f);
   if (!ntar) Fatal("No targets in %s\n",file);
   //  Write header
   if (fout)
   {
      for (int i=0;i<ntar;i++)
      {
         if (pt[i].hdr) fprintf(fout,"#                    %s\n",pt[i].hdr);
         fprintf(fout,"#%-3d %-15s %s\n",i+1,pt[i].host,pt[i].name);
      }
      fprintf(fout,"#\n");
      fprintf(fout,"#  Date      Time  ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6d",i+1);
      fprintf(fout,"\n");
   }
}

//
//  Calculate checksum
//
unsigned short checksum(char* data,int len)
{
   int sum = 0;
   unsigned short csum = 0;
   unsigned short* word = (unsigned short*) data;
   while (len>1)
   {
     sum += *word++;
     len -= 2;
   }
   if (len==1)
   {
     *(unsigned char *)(&csum) = *(unsigned char *)word;
     sum += csum;
   }
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   csum = ~sum;                         // truncate to 16 bits
   return csum;
}

//
//  Draw single ping
//
void DrawPing(Ping* ping,int l)
{
   uint8_t ch = GetPing(ping,l);
   //  No ping yet
   if (ch==NoPing)
   {
      attron(COLOR_PAIR(1));
      addch('-');
   }
   //  No reply or late reply
   else if (ch==LostPing || ch==LatePing)
   {
      attron(COLOR_PAIR(5));
      attron(A_BOLD);
      addch(ch==LostPing?'X':'+');
      attroff(A_BOLD);
   }
   // Reply
   else
   {
      //  Upper nibble is exponent (color)
      attron(COLOR_PAIR((ch>>4)+2));
      //  Numeric
      if (ich==3)
      {
         //  Lower nibble is mantissa (0-9)
         attron(A_BOLD);
         addch((ch&0xF)+'0');
         attroff(A_BOLD);
      }
      //  Symbol
      else if (pch)
         addch(pch);
      else if (ich==2)
         addch('*');
      else if (ich==1)
         addch(ACS_BLOCK);
      else
         addch(ACS_DIAMOND);
   }
}

//
//  Draw row of pings
//
void DrawPingRow(Ping* ping,int n)
{
   if (r2l)
      for (int l=n-1;l>=0;l--)
         DrawPing(ping,l);
   else
      for (int l=0;l<n;l++)
         DrawPing(ping,l);
}

//
//  Figure out the bottom row
//
int Bottom(int top)
{
   int i = (ntar+nhdr+1<hgt || hgt>20) ? 2 : 1;
   for (int k=top;k<ntar;k++)
   {
      i += pt[k].hdr ? 2 : 1;
      if (i==hgt)
         return k;
      else if (i>hgt)
         return k-1;
   }
   return ntar-1;
}

//
//  Print history header
//
void PrintHist(int n)
{
   //  Ping history header right to left
   if (r2l)
      for (int l=n-1;l>=0;l--)
      {
         if (l%10==0)
            addch('0');
         else if (l>10 && (l-1)%10==0)
            addch('0'+(l%100)/10);
         else if (l>100 && (l-2)%10==0)
            addch('0'+l/100);
         else
            addch(' ');
      }
   //  Ping history header left to right
   else
      for (int l=0;l<n;l++)
      {
         if (l%10==0)
            addch('0');
         else if (l>8 && (l+1)%10==0)
            addch('0'+((l+1)%100)/10);
         else if (l>97 && (l+2)%10==0)
            addch('0'+(l+2)/100);
         else
            addch(' ');
      }
}

//
//  Display
//
void Display(int new)
{
   int bell = 0;
   //  Stop advance when reviewing until end of buffer is reached
   if (new && delt) delt++;
   if (delt>nsec-nping-3) delt = nsec-nping-3;
   //  Clear
   erase();
#ifdef piGPIO
   //  Do full refresh
   if (seq%10==0) clearok(curscr,1);
#endif
   attron(COLOR_PAIR(1));
   //  Help
   if (mode<0)
   {
      attron(A_BOLD);
      printw("cping version " VER "\n");
      printw(" Key   Function\n");
      attroff(A_BOLD);
      printw("%s",help);
   }
   //  Traceroute
   else if (mode)
   {
      //  Unwind trailing lack of response
      while (nhop>1 && !tt[nhop-1].ip && !tt[nhop-2].ip)
         nhop--;
      //  Display
      if (nhop+3<hgt) timeprint();
      attron(A_BOLD);
      printw("Traceroute to %s\n\n",pt[sel].name);
      //  Look up hostname and figure longest name
      int len=5;
      int lan=4;
      for (int k=0;k<nhop;k++)
      {
         int l = nslookup(tt+k);
         if (l>len) len = l;
         l = strlen(tt[k].addr);
         if (l>lan) lan = l;
      }
      //  Truncate hostnames if too long
      if (len+lan+12>wid) len = wid-12-lan;
      int ntrac = wid-13-len-lan;
      if (stat) ntrac -= 23;
      if (ntrac>nsec) ntrac = nsec;
      //  Print header
      printw("Hop Host");
      for (int k=0;k<len;k++)
         addch(' ');
      printw(" IP");
      for (int k=5;k<lan;k++)
         addch(' ');
      PrintHist(ntrac);
      printw("    ms");
      if (stat) printw("   min   avg   max lost");
      printw("\n");
      attroff(A_BOLD);
      int m = (nhop<hgt-3) ? nhop : hgt-3;
      //  Print replies
      for (int k=0;k<m;k++)
      {
         attron(COLOR_PAIR(1));
         printw("%3d ",k+1);
         char* ch = tt[k].fqdn;
         for (int l=0;l<len+1;l++)
            addch(*ch?*ch++:' ');
         ch = tt[k].addr;
         for (int l=0;l<lan+1;l++)
            addch(*ch?*ch++:' ');
         //  Pings
         DrawPingRow(&tt[k].ping,ntrac);
         //  Draw stats
         attron(COLOR_PAIR(1));
         if (tt[k].dt<0)
            printw(" unrch");
         else
            printw(" %5.1f",tt[k].dt);
         if (stat) printw("%6.1f%6.1f%6.1f%5d",tt[k].stat.min,tt[k].stat.avg,tt[k].stat.max,tt[k].stat.lost);
         printw("\n");
      }
      //  Bell on lost packets
      if (!silent && !pt[sel].silent)
         for (int k=0;k<nhop;k++)
            bell = bell | (tt[k].dt<0);
   }
   //  Ping
   else
   {
      int i=1;
      //  Print header if we have enough rows
      if (ntar+nhdr+1<hgt || hgt>20)
      {
         timeprint();
         i++;
      }
      //
      //  Print header line
      //
      attron(A_BOLD);
      //  Display name
      printw("Target");
      for (int l=6;l<nwid;l++)
         addch(' ');
      //  Host/IP if selected
      if (showip)
      {
         printw(" Address");
         for (int l=7;l<awid;l++)
            addch(' ');
      }
      PrintHist(nping);
      //  Ping times
      printw("   ms");
      //  Number of hops
      if (hop) printw(" hop");
      //  Stats
      if (stat) printw("   min   avg   max lost");
      attroff(A_BOLD);
      //
      //  Draw ping table
      //
      for (int k=top;k<ntar;k++)
      {
         //  Bail out at the bottom of the screen
         if (i>=hgt) break;
         //  Target name
         move(i++,0);
         if (pt[k].hdr)
         {
            attron(A_BOLD);
            printw("%s",pt[k].hdr);
            attroff(A_BOLD);
            move(i++,0);
            //  Bail out at the bottom of the screen
            if (i>hgt) break;
         }
         //  Choose color
         if (k==sel && pt[k].silent)
            attron(COLOR_PAIR(4));
         else if (pt[k].silent)
            attron(COLOR_PAIR(5));
         else if (k==sel)
            attron(COLOR_PAIR(3));
         else
            attron(COLOR_PAIR(1));
         //  Print name
         char* ch = pt[k].name;
         for (int l=0;l<nwid;l++)
            addch(*ch?*ch++:'.');
         //  Print address
         if (showip)
         {
            addch(' ');
            char* ch = pt[k].host;
            for (int l=0;l<awid;l++)
               addch(*ch?*ch++:'.');
         }
         if (k==sel) attron(COLOR_PAIR(1));
         //  Pings
         DrawPingRow(&pt[k].ping,nping);
         //  Ping time
         attron(COLOR_PAIR(1));
         if (pt[k].dt<0)
            printw(" -----");
         else
            printw(" %5.1f",pt[k].dt);
         //  Hop count
         if (hop)
         {
            //  Guess initial TTL as 256, 128 or 64
            int TTL0;
            if (pt[k].ttl>128)
               TTL0 = 256;
            else if (pt[k].ttl>64)
               TTL0 = 128;
            else
               TTL0 = 64;
            //  Print hops
            int l = TTL0+1-pt[k].ttl;
            if (pt[k].dt<0 || l<0)
               printw(" --");
            else
               printw(" %2d",l);
         }
         //  Draw stats
         if (stat) printw("%6.1f%6.1f%6.1f%5d",pt[k].stat.min,pt[k].stat.avg,pt[k].stat.max,pt[k].stat.lost);
      }
      //  Bell on lost packets
      if (!silent)
         for (int k=0;k<ntar;k++)
            bell = bell | (seq>1 && GetPing(&pt[k].ping,0)==LostPing && !pt[k].silent);
   }
   show = 0;
   if (new && bell) beep();
   refresh();
}

//
//  Send ICMP packet
//
void ICMP(int id,int seq,int ttl,struct sockaddr sa)
{
   char buf[MAXSZ];
   //  Set TTL
   if (setsockopt(sock,IPPROTO_IP,IP_TTL,(void*)&ttl,sizeof(ttl))<0) Fatal("Cannot set TTL\n");
   //  Set up ICMP packet header
   struct icmphdr* icp = (struct icmphdr*)buf;
   icp->type       = ICMP_ECHO;
   icp->code       = 0;
   icp->checksum   = 0;
   icp->un.echo.id = id;
   icp->un.echo.sequence = seq;
   //  Set up the payload
   double time = now();
   int len = sizeof(struct icmphdr);
   memcpy(buf+len,&time,sizeof(double));
   len += sizeof(double);
   //  Pad packet if len<minsz
   while (len<minsz)
      buf[len++] = 0;
   //  Compute checksum
   icp->checksum = checksum(buf,len);
   //  Send packet
   int i = sendto(sock,buf,len,0,&sa,sizeof(struct sockaddr));
#ifdef __APPLE__
   //  Some OSX machines inexplicably return -1
   if (i>0 && i!=len) fprintf(stderr,"Failed to send ICMP packet\n");
#else
   if (i<0 || i!=len) fprintf(stderr,"Failed to send ICMP packet\n");
#endif
}

//
//  Shift ping buffer
//
void PingShift(Ping* ping,Stat* stat)
{
   //  Lost<0 means initialize
   if (stat->lost<0)
      stat->lost = 0;
   //  Limit lost to 99999 to prevent field overflow
   else if (GetPing(ping,0)==LostPing && stat->lost<99999)
      stat->lost++;
   //  Shift ping buffer
   ping->cur--;
   if (ping->cur<0) ping->cur += nsec;
   //  Initialize as lost
   SetPing(ping,0,LostPing);
}

//
//  Send ping to all targets
//
void* SendPing()
{
   while (run)
   {
      total++;
      //  Parallel traceroute
      tseq++;
      if (tseq>65535) tseq=nsec;
      nhop = tTTL;
      for (int k=0;k<tTTL;k++)
      {
         //  Initialize trace
         tt[k].dt = 0;
         tt[k].ip = 0;
         PingShift(&tt[k].ping,&tt[k].stat);
         //  Send Ping
         ICMP(traceid,k+1,k+1,pt[sel].sa);
         //  Pause before sending next
         usleep(pus);
      }
      //  Write ping times
      if (fout && seq)
      {
         time_t t =  time(NULL);
         struct tm*  l = localtime(&t);
         fprintf(fout,"%4d-%.2d-%.2d-%.2d:%.2d:%.2d",l->tm_year+1900,l->tm_mon+1,l->tm_mday,l->tm_hour,l->tm_min,l->tm_sec);
         for (int i=0;i<ntar;i++)
            fprintf(fout," %6.1f",pt[i].dt);
         fprintf(fout,"\n");
      }
      //  Ping all targets with TTL pTTL
      seq++;
      if (seq>65535) seq=nsec;
      for (int k=0;k<ntar;k++)
      {
         //  Advance ping array
         PingShift(&pt[k].ping,&pt[k].stat);
         // Send Ping
         ICMP(pingid,seq,pTTL,pt[k].sa);
         //  Pause before sending next
         usleep(pus);
      }
      //  Pause until next second
      usleep(950000-ntar*pus);
      show = 1;
      //  Give display 50ms to update
      usleep((sbp-1)*1000000+50000);
      //  Check if this is a finite ping
      if (num>0 && seq>=num) run = 0;
   }
   return NULL;
}

//
//  Unpack IP/ICMP header
//
int UnpackHeader(unsigned char* data,int l,int* ttl,int* rtp,int* rcd, int* rid,int* rsq)
{
   int len=0;
   //  Get TTL
   if (l<sizeof(struct ip)) return 0;
   struct ip* ip = (struct ip*)data;
   *ttl = ip->ip_ttl;
   //  Skip the IP header
   int hlen = ip->ip_hl << 2;
   data += hlen;
   len  += hlen;
   l    -= hlen;
   //  Unpack ICMP header
   if (l<sizeof(struct icmphdr)) return 0;
   struct icmphdr* icp = (struct icmphdr*)data;
   *rtp = icp->type;
   *rcd = icp->code;
   *rid = icp->un.echo.id;
   *rsq = icp->un.echo.sequence;
   data += sizeof(struct icmphdr);
   len  += sizeof(struct icmphdr);
   return len;
}

//
//  Encode time as byte
//  Upper nibble exponent base 10
//  Lower nibble mantissa 0-9
//     Example 0x25 = 500
//  Special values
//     0xFF - NoPing
//     0xFE - Lost ping
//     0xFD - Late ping
//
uint8_t ByteTime(double dt)
{
   int idt = dt+0.5;
   uint8_t bdt=LostPing;
   if (idt<10)
      bdt = idt;
   else if (idt<100)
      bdt = (idt/10) + 0x10;
   else if (idt<1000)
      bdt = (idt/100) + 0x20;
   else if (idt<10000)
      bdt = (idt/1000) + 0x30;
   return bdt;
}

//
//  Update ping stats
//
void Stats(double dt,Stat* stat)
{
   stat->n++;
   stat->S  += dt;
   stat->S2 += dt*dt;
   if (stat->min<0 || dt<stat->min) stat->min = dt;
   if (stat->max<0 || dt>stat->max) stat->max = dt;
   stat->avg = stat->S / stat->n;
   stat->std = (stat->n > 1) ? sqrt((stat->S2-stat->S*stat->S/stat->n)/(stat->n-1)) : 0;
}

//
//  Receive pings
//
void* Receive()
{
   while (1)
   {
      unsigned char buf[8192];
      unsigned char* data=buf;
      //  Check for reply
      struct sockaddr from;
      socklen_t flen = sizeof(from);
      int l = recvfrom(sock,buf,8192,0,&from,&flen);
      if (l<0) continue;
      //  Check if this packet is from a known host
      struct sockaddr_in* isa = (struct sockaddr_in*)&from;
      int host = -1;
      for (int i=0;i<ntar && host<0;i++)
         if (isa->sin_addr.s_addr==pt[i].ip.s_addr) host = i;
      //  Unpack header
      int ttl,rtp,rcd,rid,rsq;
      int off = UnpackHeader(data,l,&ttl,&rtp,&rcd,&rid,&rsq);
      if (!off) continue;
      data += off;
      l    -= off;
      //  Process echo reply
      if (rtp==ICMP_ECHOREPLY && l>=sizeof(double))
      {
         //  Calculate delay
         double t0 = *(double*)data;
         double dt = 1000*(now()-t0);
         //  Ping reply from known host
         if (rid==pingid && host>=0)
         {
            //  Current
            if (rsq==seq)
            {
               pt[host].ttl = ttl;
               pt[host].dt  = dt;
               SetPing(&pt[host].ping,0,ByteTime(dt));
               Stats(dt,&pt[host].stat);
            }
            //  Late
            else
            {
               pt[host].stat.late++;
               //  Offset in ping array
               int k = seq-rsq;
               //  Catch wrapping from 65535 to nsec
               if (k<0) k += 65536-nsec;
               //  Check offset in range and previously marked as lost
               if (0<k && k<nsec && GetPing(&pt[host].ping,k)==LostPing)
                  SetPing(&pt[host].ping,k,LatePing);
            }
         }
         //  Traceroute reply
         else if (rid==traceid && rsq>0 && rsq<=nhop)
         {
            //  Length of path
            if (rsq<nhop) nhop = rsq;
            tt[rsq-1].dt = dt;
            tt[rsq-1].ip = isa->sin_addr.s_addr;
            SetPing(&tt[rsq-1].ping,0,ByteTime(dt));
            Stats(dt,&tt[rsq-1].stat);
         }
      }
      //  Traceroute time exceeded
      else if (rtp==ICMP_TIME_EXCEEDED)
      {
         //  Data is original packet
         off = UnpackHeader(data,l,&ttl,&rtp,&rcd,&rid,&rsq);
         if (!off) continue;
         data += off;
         l    -= off;
         if (l<sizeof(double)) continue;
         double t0 = *(double*)data;
         double dt = 1000*(now()-t0);
         if (rid==traceid && rsq>0 && rsq<=nhop)
         {
            tt[rsq-1].dt = dt;
            tt[rsq-1].ip = isa->sin_addr.s_addr;
            SetPing(&tt[rsq-1].ping,0,ByteTime(dt));
            Stats(dt,&tt[rsq-1].stat);
         }
      }
      //  Destination unreachable
      else if (rtp==ICMP_UNREACH)
      {
         //  Data is original packet
         off = UnpackHeader(data,l,&ttl,&rtp,&rcd,&rid,&rsq);
         if (!off) continue;
         if (rid==traceid && rsq>0 && rsq<nhop)
         {
            nhop = rsq;
            tt[rsq-1].dt = -1;
            tt[rsq-1].ip = isa->sin_addr.s_addr;
         }
      }
   }
}

//
//  Check that selected item is in range
//  dir=0 is resizing the screen
//
void Scroll(int dir)
{
   //  Everything fits
   if (ntar+nhdr+1<hgt)
      top = 0;
   //  Ping mode scroll or resize
   else if (!mode)
   {
      //  Current bottom
      int bot = Bottom(top);
      // Scroll down
      if (dir>0)
      {
         for (int i=0;i<dir && Bottom(top)<ntar-1;i++)
            bot = Bottom(++top);
      }
      //  Scroll up
      else if (dir<0)
      {
         top = top+dir>0 ? top+dir : 0;
         bot = Bottom(top);
      }
      //  Check that selection is on the screen
      if (sel<top) sel = top;
      if (sel>bot) sel = bot;
   }
   //  Resize in traceroute mode
   else if (!dir)
   {
      //  Current bottom
      int bot = Bottom(top);
      //  Make sure that selection remains on the screen
      if (sel<top) top = sel;
      if (sel>bot) top -= sel-bot;
      if (top<0) top = 0;
   }
}

//
//  Select new target
//
void newsel(int dir)
{
   int new = sel+dir;
   if (new<0)
      new = 0;
   else if (new>=ntar)
      new = ntar-1;
   //  Scroll up if required
   if (dir<0)
   {
      while (new<top)
        Scroll(-1);
   }
   //  Scroll down if required
   else
   {
      while (new>Bottom(top))
        Scroll(+1);
   }
   sel = new;
   //  Reset traceroute hops when selected target changes
   nhop = 0;
   InitTrace();
}

//
//  Set window size
//
void Resize()
{
   int nx = hop ? nwid+9 : nwid+6;
   if (showip) nx += awid + 1;
   getmaxyx(stdscr,hgt,wid);
   Scroll(0);
   nping = wid - nx;
   if (stat) nping -= 23;
   if (nping>nsec) nping = nsec;
}

//
//  Set color
//
void SetColor()
{
   if (white)
   {
      init_pair(1,COLOR_BLACK,COLOR_WHITE);
      init_pair(2,COLOR_CYAN,COLOR_WHITE);
      init_pair(3,COLOR_GREEN,COLOR_WHITE);
      init_pair(4,COLOR_YELLOW,COLOR_WHITE);
      init_pair(5,COLOR_RED,COLOR_WHITE);
   }
   else
   {
      init_pair(1,COLOR_WHITE,COLOR_BLACK);
      init_pair(2,COLOR_CYAN,COLOR_BLACK);
      init_pair(3,COLOR_GREEN,COLOR_BLACK);
      init_pair(4,COLOR_YELLOW,COLOR_BLACK);
      init_pair(5,COLOR_RED,COLOR_BLACK);
   }
   bkgd(COLOR_PAIR(1));
}

//
//  Initialize curses
//
void InitCurses()
{
   // Start curses with raw input
   if (!initscr()) Fatal("Cannot initialize ncurses\n");
   nonl(); cbreak(); noecho(); nodelay(stdscr,TRUE); keypad(stdscr,TRUE); curs_set(0);
   //  Set colors
   if (!has_colors()) Fatal("No color support\n");
   start_color();
   init_color(COLOR_WHITE,1000,1000,1000);
   SetColor();
   // Set window size
   Resize();
}

//
//  Initialize wiringPi
//
#ifdef piGPIO
void gpio(int pin,int level,uint32_t tick)
{
   //  Ignore rapid interrupts (probably contact bounce)
   double t = now();
   if (t-swt<0.3) return;
   //  Check for mapped pin
   for (int k=0;k<4;k++)
     if (pin==SW[k]) swx = k+1;
   //  Remember time
   if (swx) swt = t;
}
void InitPIgpio(void)
{
   //  Initialize piGPIO
   if (gpioInitialise()<0) Fatal("Cannot initialize GPIO\n");
   //  Set pins for input, pull-up and interrupt
   for (int k=0;k<4;k++)
   {
      if (gpioSetMode(SW[k],PI_INPUT)) Fatal("Error setting SW%d to input\n",SW[k]);
      if (gpioSetPullUpDown(SW[k],PI_PUD_UP)) Fatal("Error setting SW%d to pull-up\n",SW[k]);
      if (gpioSetISRFunc(SW[k],FALLING_EDGE,-1,&gpio)) Fatal("Error setting interrupt for SW%d\n",SW[k]);
   }
}
#endif

//
//  Init ICMP socket
//
void InitSock(int init)
{
   //  Close old socket
   if (!init) close(sock);

   //  Get unique IDs for ping and traceroute
   pingid = (getpid() & 0x7FFF) << 1;
   traceid = pingid|0x01;

   //  Set up socket for ICMP
   sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
   if (sock<0) Fatal("Cannot open ICMP socket\n");

   //  Show reset
   move(0,0);
   printw("********RESET*******");
}

int main(int argc,char* argv[])
{
   //
   //  Process command line arguments
   //
   int ch;
   //  Check if a file is specified
   int   nfile = 2;
   char* file[2] = {"cping.cfg","/etc/cping.cfg"};
   while ((ch = getopt(argc,argv,OPTSTR)) != EOF)
       if (ch == 'f')
       {
          nfile = 1;
          file[0] = optarg;
       }
   //  Read config file
   ReadConfig(file,nfile);

   //  Process command line arguments
   optind = 1;
   while ((ch = getopt(argc,argv,OPTSTR)) != EOF)
   {
       //  Common options
       if (CheckOpt(ch,optarg))
       {}
       //  Help
       else if (ch == 'h')
          Fatal("Usage: cping [-vbanrgxthS] [-N count] [-p us] [-f file] [-o file]\n" 
                "  -b  White lettering on black background\n"
                "  -a  Show address in ping table\n"
                "  -n  No hops on ping table\n"
                "  -r  Scroll pings left to right\n"
                "  -p  microseconds between pings [default 1000]\n"
                "  -f  config file [default cping.cfg or /etc/cping.cfg]\n"
                "  -o  output file\n"
                "  -N  Stop after this many pings\n"
                "  -s  seconds between ping\n"
                "  -m  minimum ICMP packet size\n"
                "  -S  silent\n"
                "  -x  show numeric ping character\n"
                "  -t  show ping time stats\n"
                "  -v  show cping version\n"
                "  -h  help\n\n"
		" Ping targets are read from cping.cfg\n"
		" Each line is a target name followed by an ip address\n"
		" ~ in the target name becomes a space\n"
		" # in column 1 starts a comment\n\n"
                " Key  Function\n%s",help);
       //  Cping version
       else if (ch == 'v')
          Fatal("cping version " VER "\n");
#ifdef piGPIO
       //  Initialize piGPIO
       else if (ch == 'g')
          InitPIgpio();
#endif
       //  Something other than the config file
       else if (ch != 'f')
          Fatal("Unknown option %c\n",ch);
   }
   //  Check that we have time to do everything
   if (pus*(ntar+tTTL)>950000) Fatal("Pause length exceeds one second\n");
   //  Initialize curses
   InitCurses();
   //  Initialize ICMP socket
   InitSock(1);
   //  Initialize DNS
   InitDNS();
   //  Start read thread
   if (pthread_create(&rd,NULL,Receive,NULL)) Fatal("Cannot start receive thread\n");
   //  Start write thread
   if (pthread_create(&rd,NULL,SendPing,NULL)) Fatal("Cannot start write thread\n");
   //  Main loop
   while(run)
   {
      int ch = getch();
      //  Quit
      if (ch=='q')
         run = 0;
      //  Window resized
      else if (ch==KEY_RESIZE)
      {
         Resize();
         Display(0);
      }
      //  Reverse time one second
      else if (ch==KEY_LEFT)
      {
         delt++;
         Display(0);
      }
      //  Advance time one second
      else if (ch==KEY_RIGHT && delt>0)
      {
         delt--;
         Display(0);
      }
      //  Reverse time one minute
      else if (ch=='-')
      {
         delt += 60;
         Display(0);
      }
      //  Advance time one minte
      else if (ch=='+')
      {
         delt -= 60;
         if (delt<0) delt = 0;
         Display(0);
      }
      //  Current time
      else if (ch==KEY_END)
      {
         delt = 0;
         Display(0);
      }
      //  Scroll down
      else if (ch==KEY_NPAGE)
      {
         Scroll(+1);
         Display(0);
      }
      //  Scroll up
      else if (ch==KEY_PPAGE)
      {
         Scroll(-1);
         Display(0);
      }
      //  Toggle mode
      else if (swx==1)
      {
         swx = 0;
         mode = !mode;
         Display(0);
      }
      //  Previous target with scroll
      else if (swx==2 || ch==KEY_UP)
      {
         swx = 0;
         newsel(-1);
         Display(0);
      }
      //  Next target with scroll
      else if (swx==3 || ch==KEY_DOWN)
      {
         swx = 0;
         newsel(+1);
         Display(0);
      }
      //  Toggle display of addresses
      else if (swx==4)
      {
         swx = 0;
         showip = !showip;
         Resize();
         Display(0);
      }
      //  Switch to traceroute mode
      else if (ch==KEY_ENTER || ch=='\n' || ch=='\r')
      {
         mode = !mode;
         Display(0);
      }
      //  Switch to ping mode
      else if (ch==27) // ESC
      {
         mode = 0;
         Display(0);
      }
      //  Toggle hops in display
      else if (ch=='n')
      {
         hop = 1-hop;
         Resize();
         Display(0);
      }
      //  Invert colors
      else if (ch=='i')
      {
         white = !white;
         SetColor();
         Display(0);
      }
      //  Reverse ping display direction
      else if (ch=='r')
      {
         r2l = !r2l;
         Display(0);
      }
      //  Toggle display of addresses
      else if (ch=='a')
      {
         showip = !showip;
         Resize();
         Display(0);
      }
      //  Toggle stats
      else if (ch=='t')
      {
         stat = !stat;
         Resize();
         Display(0);
      }
      //  Toggle master silent
      else if (ch=='S')
      {
         silent = !silent;
         Display(0);
      }
      //  Toggle silent
      else if (ch=='s')
      {
         pt[sel].silent = !pt[sel].silent;
         Display(0);
      }
      //  Show help
      else if (ch=='h')
      {
         mode = -1;
         Display(0);
      }
      //  Toggle ping character
      else if (ch=='c')
         ich = (ich+1)%4;
      //  Reset ping socket and re-initialize statistics
      else if (ch=='0')
      {
         InitSock(0);
         for (int k=0;k<tTTL;k++)
            InitStat(&tt[k].stat);
         for (int k=0;k<ntar;k++)
            InitStat(&pt[k].stat);
         Display(0);
      }
      //  Update display
      else if (show)
         Display(1);
      //  Sleep 1ms
      usleep(1000);
   }
   endwin();
#ifdef piGPIO
   gpioTerminate();
#endif
   //  Write starts to end of output file
   if (fout)
   {
      //  Allow Receive to catch stragglers
      sleep(2);
      fprintf(fout,"END Total pings %d\n",total);
      //  Finalize lost count
      for (int k=0;k<ntar;k++)
         if (GetPing(&pt[k].ping,0)==LostPing && pt[k].stat.lost<99999)
            pt[k].stat.lost++;
      //  Print statistics
      fprintf(fout,"Replies            ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6d",pt[i].stat.n);
      fprintf(fout,"\n");
      fprintf(fout,"Lost               ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6d",pt[i].stat.lost);
      fprintf(fout,"\n");
      fprintf(fout,"Late(>1s)          ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6d",pt[i].stat.late);
      fprintf(fout,"\n");
      fprintf(fout,"Minimum            ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6.1f",pt[i].stat.min);
      fprintf(fout,"\n");
      fprintf(fout,"Average            ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6.1f",pt[i].stat.avg);
      fprintf(fout,"\n");
      fprintf(fout,"Maximum            ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6.1f",pt[i].stat.max);
      fprintf(fout,"\n");
      fprintf(fout,"StdDev             ");
      for (int i=0;i<ntar;i++)
         fprintf(fout," %6.1f",pt[i].stat.std);
      fprintf(fout,"\n");
      fclose(fout);
   }
   return 0;
}
