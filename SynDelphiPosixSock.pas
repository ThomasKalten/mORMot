/// low level access to network Sockets for POSIX on Delphi - using System units
// - this unit is a part of the freeware Synopse framework,
// licensed under a MPL/GPL/LGPL tri-license; version 1.18
unit SynDelphiPosixSock;

{
    This file is part of Synopse framework.

    Synopse framework. Copyright (C) 2022 Arnaud Bouchez
      Synopse Informatique - https://synopse.info

  *** BEGIN LICENSE BLOCK *****
  Version: MPL 1.1/GPL 2.0/LGPL 2.1

  The contents of this file are subject to the Mozilla Public License Version
  1.1 (the "License"); you may not use this file except in compliance with
  the License. You may obtain a copy of the License at
  http://www.mozilla.org/MPL

  Software distributed under the License is distributed on an "AS IS" basis,
  WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
  for the specific language governing rights and limitations under the License.

  The Original Code is Synapse library.

  The Initial Developer of the Original Code is Lukas Gebauer (Czech Republic).
  Portions created by Lukas Gebauer are Copyright (C) 2003.
  All Rights Reserved.

  Portions created by Arnaud Bouchez are Copyright (C) 2022 Arnaud Bouchez.
  All Rights Reserved.

  Contributor(s):
  - Alfred Glaenzer

  Alternatively, the contents of this file may be used under the terms of
  either the GNU General Public License Version 2 or later (the "GPL"), or
  the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
  in which case the provisions of the GPL or the LGPL are applicable instead
  of those above. If you wish to allow use of your version of this file only
  under the terms of either the GPL or the LGPL, and not to allow others to
  use your version of this file under the terms of the MPL, indicate your
  decision by deleting the provisions above and replace them with the notice
  and other provisions required by the GPL or the LGPL. If you do not delete
  the provisions above, a recipient may use your version of this file under
  the terms of any one of the MPL, the GPL or the LGPL.

  ***** END LICENSE BLOCK *****

     Low level access to network Sockets
    *************************************

  Shared by Kylix and FPC for all POSIX systems.

}

{$ifdef FPC}
  'This Unit is for Delphi Only';
{$endif}


interface

uses
  SysUtils,
  SyncObjs,
  System.Net.Socket,
  Posix.NetinetIn,
  Posix.NetinetTCP,
  Posix.SysSocket,
  Posix.SysSelect,
  Posix.SysTime,
  Posix.SysTypes,
  Posix.SysUn,
  Posix.StrOpts,
  Posix.Errno,
  Posix.Unistd,
  Posix.ArpaInet,
  Posix.NetDB,
  SynDelphiPosix,
  NonWindows,
  Classes;

const
  InitSocketInterface = true;

procedure DestroySocketInterface;

{$MINENUMSIZE 4}

const
  DLLStackName = '';
  WinsockLevel = $0202;

  cLocalHost = '127.0.0.1';
  cAnyHost = '0.0.0.0';
  c6AnyHost = '::0';
  c6Localhost = '::1';
  cLocalHostStr = 'localhost';

type
  TSocket = longint;

  TFDSet = posix.SysSelect.fd_set; //  System.Net.Socket.TFDSet;
  PFDSet = posix.SysSelect.pfd_set;
  Ptimeval = Posix.SysTime.Ptimeval;
  Ttimeval = Posix.SysTime.timeval;

  PInAddr = ^TInAddr;
  TInAddr = in_addr;

  PSockAddrIn = ^TSockAddrIn;
  TSockAddrIn = sockaddr_in; // TInetSockAddr;

  PInAddr6 = ^TInAddr6;
  TInAddr6 =  in6_addr;

  PSockAddrIn6 = ^TSockAddrIn6;
  TSockAddrIn6 = sockaddr_in6;

  TSockAddr = Posix.SysSocket.sockaddr;
  PSockAddr = ^sockaddr;

const
  FIONREAD        = Posix.StrOpts.FIONREAD;
  // From Android NDK
  {$ifdef ANDROID}
  FIONBIO  = $5421;
  FIOASYNC = $5422;
  {$else}
  // Not general available
  FIONBIO         = Posix.StrOpts.FIONBIO;
  FIOASYNC        = Posix.StrOpts.FIOASYNC;
  {$endif}


  IP_TOS             = Posix.NetinetIn.IP_TOS;             { int; IP type of service and precedence.  }
  IP_TTL             = Posix.NetinetIn.IP_TTL;             { int; IP time to live.  }
  IP_HDRINCL         = Posix.NetinetIn.IP_HDRINCL;         { int; Header is included with data.  }
  IP_OPTIONS         = Posix.NetinetIn.IP_OPTIONS;         { ip_opts; IP per-packet options.  }
  IP_RECVOPTS        = Posix.NetinetIn.IP_RECVOPTS;        { bool }
  IP_RETOPTS         = Posix.NetinetIn.IP_RETOPTS;         { bool }
  IP_MULTICAST_IF    = Posix.NetinetIn.IP_MULTICAST_IF;    { in_addr; set/get IP multicast i/f }
  IP_MULTICAST_TTL   = Posix.NetinetIn.IP_MULTICAST_TTL;   { u_char; set/get IP multicast ttl }
  IP_MULTICAST_LOOP  = Posix.NetinetIn.IP_MULTICAST_LOOP;  { i_char; set/get IP multicast loopback }
  IP_ADD_MEMBERSHIP  = Posix.NetinetIn.IP_ADD_MEMBERSHIP;  { ip_mreq; add an IP group membership }
  IP_DROP_MEMBERSHIP = Posix.NetinetIn.IP_DROP_MEMBERSHIP; { ip_mreq; drop an IP group membership }

  SHUT_RD         = Posix.SysSocket.SHUT_RD;
  SHUT_WR         = Posix.SysSocket.SHUT_WR;
  SHUT_RDWR       = Posix.SysSocket.SHUT_RDWR;

  SOL_SOCKET    = Posix.SysSocket.SOL_SOCKET;

  SO_DEBUG      = Posix.SysSocket.SO_DEBUG;
  SO_REUSEADDR  = Posix.SysSocket.SO_REUSEADDR;
  {$ifdef MACOS}//  BSD}
  SO_REUSEPORT  = Posix.SysSocket.SO_REUSEPORT;
  {$endif}
  SO_TYPE       = Posix.SysSocket.SO_TYPE;
  SO_ERROR      = Posix.SysSocket.SO_ERROR;
  SO_DONTROUTE  = Posix.SysSocket.SO_DONTROUTE;
  SO_BROADCAST  = Posix.SysSocket.SO_BROADCAST;
  SO_SNDBUF     = Posix.SysSocket.SO_SNDBUF;
  SO_RCVBUF     = Posix.SysSocket.SO_RCVBUF;
  SO_KEEPALIVE  = Posix.SysSocket.SO_KEEPALIVE;
  SO_OOBINLINE  = Posix.SysSocket.SO_OOBINLINE;
  SO_LINGER     = Posix.SysSocket.SO_LINGER;
  SO_RCVLOWAT   = Posix.SysSocket.SO_RCVLOWAT;
  SO_SNDLOWAT   = Posix.SysSocket.SO_SNDLOWAT;
  SO_RCVTIMEO   = Posix.SysSocket.SO_RCVTIMEO;
  SO_SNDTIMEO   = Posix.SysSocket.SO_SNDTIMEO;

  // we use Linux default here
  SOMAXCONN     = 128;

  IPV6_UNICAST_HOPS     = Posix.NetinetIn.IPV6_UNICAST_HOPS;
  IPV6_MULTICAST_IF     = Posix.NetinetIn.IPV6_MULTICAST_IF;
  IPV6_MULTICAST_HOPS   = Posix.NetinetIn.IPV6_MULTICAST_HOPS;
  IPV6_MULTICAST_LOOP   = Posix.NetinetIn.IPV6_MULTICAST_LOOP;
  IPV6_JOIN_GROUP       = Posix.NetinetIn.IPV6_JOIN_GROUP;
  IPV6_LEAVE_GROUP      = Posix.NetinetIn.IPV6_LEAVE_GROUP;

  MSG_OOB       = Posix.SysSocket.MSG_OOB;      // Process out-of-band data.
  MSG_PEEK      = Posix.SysSocket.MSG_PEEK;     // Peek at incoming messages.

  MSG_NOSIGNAL  = Posix.SysSocket.MSG_NOSIGNAL; // Do not generate SIGPIPE.

  { TCP options. }
  TCP_NODELAY     = $0001;

  { Address families. }
  AF_UNSPEC       = Posix.SysSocket.AF_UNSPEC;               { unspecified }
  AF_LOCAL        = Posix.SysSocket.AF_UNIX;
  AF_INET         = Posix.SysSocket.AF_INET;               { internetwork: UDP, TCP, etc. }
  AF_UNIX         = Posix.SysSocket.AF_UNIX;
  AF_MAX          = 24; // Usage??

  { Protocol families, same as address families for now. }
  PF_UNSPEC       = AF_UNSPEC;
  PF_INET         = AF_INET;
  PF_MAX          = AF_MAX;

const
  WSAEINTR = Posix.Errno.EINTR;
  WSAEBADF = Posix.Errno.EBADF;
  WSAEACCES = Posix.Errno.EACCES;
  WSAEFAULT = Posix.Errno.EFAULT;
  WSAEINVAL = Posix.Errno.EINVAL;
  WSAEMFILE = Posix.Errno.EMFILE;
  WSAEWOULDBLOCK = Posix.Errno.EWOULDBLOCK; // =WSATRY_AGAIN/ESysEAGAIN on POSIX
  WSAEINPROGRESS = Posix.Errno.EINPROGRESS;
  WSAEALREADY = Posix.Errno.EALREADY;
  WSATRY_AGAIN = Posix.Errno.EAGAIN;
  WSAENOTSOCK = Posix.Errno.ENOTSOCK;
  WSAEDESTADDRREQ = Posix.Errno.EDESTADDRREQ;
  WSAEMSGSIZE = Posix.Errno.EMSGSIZE;
  WSAEPROTOTYPE = Posix.Errno.EPROTOTYPE;
  WSAENOPROTOOPT = Posix.Errno.ENOPROTOOPT;
  WSAEPROTONOSUPPORT = Posix.Errno.EPROTONOSUPPORT;
  WSAESOCKTNOSUPPORT = Posix.Errno.ESOCKTNOSUPPORT;
  WSAEOPNOTSUPP = Posix.Errno.EOPNOTSUPP;
  WSAEPFNOSUPPORT = Posix.Errno.EPFNOSUPPORT;
  WSAEAFNOSUPPORT = Posix.Errno.EAFNOSUPPORT;
  WSAEADDRINUSE = Posix.Errno.EADDRINUSE;
  WSAEADDRNOTAVAIL = Posix.Errno.EADDRNOTAVAIL;
  WSAENETDOWN = Posix.Errno.ENETDOWN;
  WSAENETUNREACH = Posix.Errno.ENETUNREACH;
  WSAENETRESET = Posix.Errno.ENETRESET;
  WSAECONNABORTED = Posix.Errno.ECONNABORTED;
  WSAECONNRESET = Posix.Errno.ECONNRESET;
  WSAENOBUFS = Posix.Errno.ENOBUFS;
  WSAEISCONN = Posix.Errno.EISCONN;
  WSAENOTCONN = Posix.Errno.ENOTCONN;
  WSAESHUTDOWN = Posix.Errno.ESHUTDOWN;
  WSAETOOMANYREFS = Posix.Errno.ETOOMANYREFS;
  WSAETIMEDOUT = Posix.Errno.ETIMEDOUT;
  WSAECONNREFUSED = Posix.Errno.ECONNREFUSED;
  WSAELOOP = Posix.Errno.ELOOP;
  WSAENAMETOOLONG = Posix.Errno.ENAMETOOLONG;
  WSAEHOSTDOWN = Posix.Errno.EHOSTDOWN;
  WSAEHOSTUNREACH = Posix.Errno.EHOSTUNREACH;
  WSAENOTEMPTY = Posix.Errno.ENOTEMPTY;
  WSAEPROCLIM = -1;
  WSAEUSERS = Posix.Errno.EUSERS;
  WSAEDQUOT = Posix.Errno.EDQUOT;
  WSAESTALE = Posix.Errno.ESTALE;
  WSAEREMOTE = Posix.Errno.EREMOTE;
  WSASYSNOTREADY = -2;
  WSAVERNOTSUPPORTED = -3;
  WSANOTINITIALISED = -4;
  WSAEDISCON = -5;
  WSAHOST_NOT_FOUND = 1;
  WSANO_RECOVERY = 3;
  WSANO_DATA = -6;


const
  IPPROTO_IP     =   Posix.NetinetIn.IPPROTO_IP;		{ Dummy					}
  IPPROTO_ICMP   =   Posix.NetinetIn.IPPROTO_ICMP;		{ Internet Control Message Protocol }
  IPPROTO_IGMP   =   Posix.NetinetIn.IPPROTO_IGMP;		{ Internet Group Management Protocol}
  IPPROTO_TCP    =   Posix.NetinetIn.IPPROTO_TCP;		{ TCP           			}
  IPPROTO_UDP    =   Posix.NetinetIn.IPPROTO_UDP;	{ User Datagram Protocol		}
  IPPROTO_IPV6   =   Posix.NetinetIn.IPPROTO_IPV6;
  IPPROTO_ICMPV6 =   Posix.NetinetIn.IPPROTO_ICMPV6;
  IPPROTO_RM     =   113; // ??

  IPPROTO_RAW    =   Posix.NetinetIn.IPPROTO_RAW;
  IPPROTO_MAX    =   Posix.NetinetIn.IPPROTO_MAX;

  AF_INET6       = Posix.SysSocket.AF_INET6;  { Internetwork Version 6 }
  PF_INET6       = AF_INET6;

  SOCK_STREAM     = Posix.SysSocket.SOCK_STREAM;    { stream socket }
  SOCK_DGRAM      = Posix.SysSocket.SOCK_DGRAM;     { datagram socket }
  SOCK_RAW        = Posix.SysSocket.SOCK_RAW;       { raw-protocol interface }
  SOCK_RDM        = Posix.SysSocket.SOCK_RDM;       { reliably-delivered message }
  SOCK_SEQPACKET  = Posix.SysSocket.SOCK_SEQPACKET; { sequenced packet stream }

  FD_SETSIZE      = Posix.SysSelect.FD_SETSIZE;

type
  TIP_mreq =  record
    imr_multiaddr: TInAddr;     // IP multicast address of group
    imr_interface: TInAddr;     // local IP address of interface
  end;

  TIPv6_mreq = record
    ipv6mr_multiaddr: TInAddr6; // IPv6 multicast address.
    ipv6mr_interface: integer;   // Interface index.
  end;

const
  INADDR_ANY       = $00000000;
  INADDR_LOOPBACK  = $7F000001;
  INADDR_BROADCAST = $FFFFFFFF;
  INADDR_NONE      = $FFFFFFFF;
  ADDR_ANY		     = INADDR_ANY;
  INVALID_SOCKET	 = TSocket(NOT(0));
  SOCKET_ERROR		 = -1;


type
  { Structure used for manipulating linger option. }
  PLinger = ^TLinger;
  TLinger = packed record
    l_onoff: integer;
    l_linger: integer;
  end;

const
  WSADESCRIPTION_LEN     =   256;
  WSASYS_STATUS_LEN      =   128;

type
  PWSAData = ^TWSAData;
  TWSAData = packed record
    wVersion: Word;
    wHighVersion: Word;
    szDescription: array[0..WSADESCRIPTION_LEN] of Char;
    szSystemStatus: array[0..WSASYS_STATUS_LEN] of Char;
    iMaxSockets: Word;
    iMaxUdpDg: Word;
    lpVendorInfo: PChar;
  end;

function IN6_IS_ADDR_UNSPECIFIED(const a: PInAddr6): boolean;
function IN6_IS_ADDR_LOOPBACK(const a: PInAddr6): boolean;
function IN6_IS_ADDR_LINKLOCAL(const a: PInAddr6): boolean;
function IN6_IS_ADDR_SITELOCAL(const a: PInAddr6): boolean;
function IN6_IS_ADDR_MULTICAST(const a: PInAddr6): boolean;
function IN6_ADDR_EQUAL(const a: PInAddr6; const b: PInAddr6):boolean;
procedure SET_IN6_IF_ADDR_ANY (const a: PInAddr6);
procedure SET_LOOPBACK_ADDR6 (const a: PInAddr6);

var
  in6addr_any, in6addr_loopback : TInAddr6;

{$ifdef FPC} // some functions inlined redirection to Sockets.pp

procedure FD_CLR(Socket: TSocket; var FDSet: TFDSet); inline;
function FD_ISSET(Socket: TSocket; var FDSet: TFDSet): Boolean; inline;
procedure FD_SET(Socket: TSocket; var FDSet: TFDSet); inline;
procedure FD_ZERO(var FDSet: TFDSet); inline;

function ResolveIPToName(const IP: string; Family,SockProtocol,SockType: integer): string;
function ResolvePort(const Port: string; Family,SockProtocol,SockType: integer): Word;

function fpbind(s:cint; addrx: psockaddr; addrlen: tsocklen): cint; inline;
function fplisten(s:cint; backlog: cint): cint; inline;
function fprecv(s:cint; buf: pointer; len: size_t; Flags: cint): ssize_t; inline;
function fpsend(s:cint; msg:pointer; len:size_t; flags:cint): ssize_t; inline;

{$endif FPC}

const
  // we assume that the Posix OS has IP6 compatibility
  SockEnhancedApi = true;
  SockWship6Api = true;

type
  PVarSin = ^TVarSin;
  TVarSin = packed record
    {$ifdef SOCK_HAS_SINLEN}
    sin_len: cuchar;
    {$endif}
    case integer of
      0: (AddressFamily: sa_family_t);
      1: (
        case sin_family: sa_family_t of
          AF_INET: (sin_port: word;
                    sin_addr: TInAddr;
                    sin_zero: array[0..7] of Char);
          AF_INET6:(sin6_port:     word; // see sockaddr_in6
                    sin6_flowinfo: cardinal;
      	    	    sin6_addr:     TInAddr6;
      		    sin6_scope_id: cardinal);
          AF_UNIX: (sun_path: array[0..{$ifdef SOCK_HAS_SINLEN}103{$else}107{$endif}] of Char);
          );
  end;

function SizeOfVarSin(const sin: TVarSin): integer;

function WSAStartup(wVersionRequired: Word; var WSData: TWSAData): Integer;
function WSACleanup: Integer;
function WSAGetLastError: Integer;
function GetHostName: string;
function Shutdown(s: TSocket; how: Integer): Integer;
function SetSockOpt(s: TSocket; level,optname: Integer; optval: pointer;
  optlen: Integer): Integer;
function GetSockOpt(s: TSocket; level,optname: Integer; optval: pointer;
  var optlen: Integer): Integer;
function SendTo(s: TSocket; Buf: pointer; len,flags: Integer; addrto: TVarSin): Integer;
function RecvFrom(s: TSocket; Buf: pointer; len,flags: Integer; var from: TVarSin): Integer;
function ntohs(netshort: word): word;
function ntohl(netlong: cardinal): cardinal;
function Listen(s: TSocket; backlog: Integer): Integer;
function IoctlSocket(s: TSocket; cmd: DWORD; var arg: integer): Integer;
function htons(hostshort: word): word;
function htonl(hostlong: cardinal): cardinal;
function GetSockName(s: TSocket; var name: TVarSin): Integer;
function GetPeerName(s: TSocket; var name: TVarSin): Integer;
function Connect(s: TSocket; const name: TVarSin): Integer;
function CloseSocket(s: TSocket): Integer;
function Bind(s: TSocket; const addr: TVarSin): Integer;
function Accept(s: TSocket; var addr: TVarSin): TSocket;
function Socket(af,Struc,Protocol: Integer): TSocket;
function Select(nfds: Integer; readfds,writefds,exceptfds: PFDSet;
  timeout: PTimeVal): Longint;

function IsNewApi(Family: integer): Boolean;
function SetVarSin(var Sin: TVarSin; const IP,Port: string;
  Family,SockProtocol,SockType: integer; PreferIP4: Boolean): integer;
function GetSinIP(const Sin: TVarSin): AnsiString;
function GetSinPort(const Sin: TVarSin): Integer;
procedure ResolveNameToIP(const Name: AnsiString; Family, SockProtocol, SockType: integer;
  IPList: TStrings; IPListClear: boolean = true);

const
  // poll() flag when there is data to read
  POLLIN       = $001;
  // poll() flag when there is urgent data to read
  POLLPRI      = $002;
  // poll() flag when writing now will not block
  POLLOUT      = $004;
  // poll() flag error condition (always implicitly polled for)
  POLLERR      = $008;
  // poll() flag hung up (always implicitly polled for)
  POLLHUP      = $010;
  // poll() flag invalid polling request (always implicitly polled for)
  POLLNVAL     = $020;
  // poll() flag when normal data may be read
  POLLRDNORM   = $040;
  // poll() flag when priority data may be read
  POLLRDBAND   = $080;
  // poll() flag when writing now will not block
  POLLWRNORM   = $100;
  // poll() flag when priority data may be written
  POLLWRBAND   = $200;
  // poll() flag extension for Linux
  POLLMSG      = $400;

type
  /// polling request data structure for poll()
  TPollFD = {packed} record
    /// file descriptor to poll
    fd: integer;
    /// types of events poller cares about
    // - mainly POLLIN and/or POLLOUT
    events: Smallint;
    /// types of events that actually occurred
    // - caller could just reset revents := 0 to reuse the structure
    revents: Smallint;
  end;
  PPollFD = ^TPollFD;
  TPollFDDynArray = array of TPollFD;

/// Poll the file descriptors described by the nfds structures starting at fds
// - if TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
// an event to occur; if TIMEOUT is -1, block until an event occurs
// - returns the number of file descriptors with events, zero if timed out,
// or -1 for errors

// function poll(fds: PPollFD; nfds, timeout: integer): integer;

{$ifdef Linux}
const
  // associated file is available for read operations
  EPOLLIN  = $01;
  // urgent data available for read operations
  EPOLLPRI = $02;
  // associated file is available for write operations
  EPOLLOUT = $04;
  // error condition happened on the associated file descriptor
  EPOLLERR = $08;
  // hang up happened on the associated file descriptor
  EPOLLHUP = $10;
  // sets the One-Shot behaviour for the associated file descriptor
  // - i.e. after an event is pulled out, the file descriptor is disabled
  EPOLLONESHOT = $40000000;
  // sets the Edge-Triggered (ET) behaviour  for  the  associated file descriptor
  EPOLLET  = $80000000;

  EPOLL_CTL_ADD = 1;
  EPOLL_CTL_DEL = 2;
  EPOLL_CTL_MOD = 3;

type
  /// application-level data structure for epoll
  TEPollData = record
    case integer of
      0: (ptr: pointer);
      1: (fd: integer);
      2: (u32: cardinal);
      3: (u64: Int64);
      4: (obj: TObject);
  end;
  PEPollData = ^TEPollData;

  /// epoll descriptor data structure
  TEPollEvent = packed record
    events: cardinal;
    data: TEpollData;
  end;
  PEPollEvent = ^TEPollEvent;
  TEPollEventDynArray = array of TEPollEvent;

/// open an epoll file descriptor
function epoll_create(size: integer): integer;
  {$ifdef FPC}inline;{$endif} {$ifdef KYLIX3}cdecl;{$endif}

/// control interface for an epoll descriptor
function epoll_ctl(epfd, op, fd: integer; event: PEPollEvent): integer;
  {$ifdef FPC}inline;{$endif} {$ifdef KYLIX3}cdecl;{$endif}

/// wait for an I/O event on an epoll file descriptor
function epoll_wait(epfd: integer; events: PEPollEvent; maxevents, timeout: integer): integer;
  {$ifdef FPC}inline;{$endif} {$ifdef KYLIX3}cdecl;{$endif}

/// finalize an epoll file descriptor
// - call fpclose/libc.close
function epoll_close(epfd: integer): integer;
{$endif Linux}

var
  SynSockCS: TRTLCriticalSection;

implementation

{$ifdef USELIBC}
{$i SynFPCSockLIBC.inc}
{$endif}

function IN6_IS_ADDR_UNSPECIFIED(const a: PInAddr6): boolean;
begin
  result := ((a^.s6_addr32[0]=0) and (a^.s6_addr32[1]=0) and
             (a^.s6_addr32[2]=0) and (a^.s6_addr32[3]=0));
end;

function IN6_IS_ADDR_LOOPBACK(const a: PInAddr6): boolean;
begin
  result := ((a^.s6_addr32[0]=0) and (a^.s6_addr32[1]=0) and
             (a^.s6_addr32[2]=0) and
             (a^.s6_addr[12]=0) and (a^.s6_addr[13]=0) and
             (a^.s6_addr[14]=0) and (a^.s6_addr[15]=1));
end;

function IN6_IS_ADDR_LINKLOCAL(const a: PInAddr6): boolean;
begin
  result := ((a^.s6_addr[0]=$FE) and (a^.s6_addr[1]=$80));
end;

function IN6_IS_ADDR_SITELOCAL(const a: PInAddr6): boolean;
begin
  result := ((a^.s6_addr[0]=$FE) and (a^.s6_addr[1]=$C0));
end;

function IN6_IS_ADDR_MULTICAST(const a: PInAddr6): boolean;
begin
  result := (a^.s6_addr[0]=$FF);
end;

function IN6_ADDR_EQUAL(const a: PInAddr6; const b: PInAddr6): boolean;
begin
  result := CompareMem(a,b,sizeof(TInAddr6));
end;

procedure SET_IN6_IF_ADDR_ANY (const a: PInAddr6);
begin
  FillChar(a^,sizeof(TInAddr6),0);
end;

procedure SET_LOOPBACK_ADDR6 (const a: PInAddr6);
begin
  FillChar(a^,sizeof(TInAddr6),0);
  a^.s6_addr[15] := 1;
end;


function WSAStartup(wVersionRequired: Word; var WSData: TWSAData): Integer;
begin
  with WSData do begin
    wVersion := wVersionRequired;
    wHighVersion := $202;
    szDescription := 'Synopse Sockets';
    szSystemStatus := 'Posix DELPHI';
    iMaxSockets := 32768;
    iMaxUdpDg := 8192;
  end;
  result := 0;
end;

function WSACleanup: Integer;
begin
  result := 0;
end;

function WSAGetLastError: Integer;
begin
  result := Errno;
end;

{$ifdef FPC}

function FD_ISSET(Socket: TSocket; var fdset: TFDSet): Boolean;
begin
  result := fpFD_ISSET(socket,fdset) <> 0;
end;

procedure FD_SET(Socket: TSocket; var fdset: TFDSet);
begin
  fpFD_SET(Socket,fdset);
end;

procedure FD_CLR(Socket: TSocket; var fdset: TFDSet);
begin
  fpFD_CLR(Socket,fdset);
end;

procedure FD_ZERO(var fdset: TFDSet);
begin
  fpFD_ZERO(fdset);
end;

{$ifndef USELIBC}
function fpbind(s:cint; addrx: psockaddr; addrlen: tsocklen): cint;
begin
  result := sockets.fpbind(s, addrx, addrlen);
end;

function fplisten(s:cint; backlog : cint): cint;
begin
  result := sockets.fplisten(s, backlog);
end;

function fprecv(s:cint; buf: pointer; len: size_t; Flags: cint): ssize_t;
begin
  result := sockets.fprecv(s, buf, len, Flags);
end;

function fpsend(s:cint; msg:pointer; len:size_t; flags:cint): ssize_t;
begin
  result := sockets.fpsend(s, msg, len, flags);
end;
{$endif USELIBC}

{$endif FPC}

function SizeOfVarSin(const sin: TVarSin): integer;
begin
  case sin.sin_family of
    AF_INET:  result := SizeOf(TSockAddrIn);
    AF_INET6: result := SizeOf(TSockAddrIn6);
    AF_UNIX:  result := SizeOf(sockaddr_un);
  else        result := 0;
  end;
end;

{=============================================================================}

function Bind(s: TSocket; const addr: TVarSin): Integer;
begin
  if Posix.SysSocket.Bind(s, PSockAddr(@addr)^, SizeOfVarSin(addr)) = 0 then
    result := 0 else
    result := SOCKET_ERROR;
end;

function Connect(s: TSocket; const name: TVarSin): Integer;
begin
  if Posix.SysSocket.Connect(s, PSockAddr(@name)^, SizeOfVarSin(name))=0 then
    result := 0 else
    result := SOCKET_ERROR;
end;

function GetSockName(s: TSocket; var name: TVarSin): Integer;
var len: integer;
begin
  len := SizeOf(name);
  FillChar(name, len, 0);
  result := Posix.SysSocket.getsockname(s, PSockAddr(@name)^, PSockLen_t(@len)^);
end;

function GetPeerName(s: TSocket; var name: TVarSin): Integer;
var len: integer;
begin
  len := SizeOf(name);
  FillChar(name,len,0);
  result := Posix.SysSocket.getpeername(s, PSockAddr(@name)^, PSockLen_t(@len)^);
end;

function GetHostName: string;
var tmp: array[byte] of AnsiChar;
begin
  Posix.Unistd.gethostname(tmp, sizeof(tmp) - 1);
  result:= String(tmp);
end;

function SendTo(s: TSocket; Buf: pointer; len,flags: Integer; addrto: TVarSin): Integer;
begin
  result := Posix.SysSocket.sendto(s,Buf^,len,flags,PSockAddr(@addrto)^,SizeOfVarSin(addrto));
end;

function RecvFrom(s: TSocket; Buf: pointer; len,flags: Integer; var from: TVarSin): Integer;
var x: integer;
begin
  x := SizeOf(from);
  result := Posix.SysSocket.recvfrom(s,Buf^,len,flags,PSockAddr(@from)^, PSockLen_t(@x)^);
end;

function Accept(s: TSocket; var addr: TVarSin): TSocket;
var x: integer;
begin
  x := SizeOf(addr);
  result := Posix.SysSocket.accept(s, PSockAddr(@addr)^, PSockLen_t(@x)^);
end;

function Shutdown(s: TSocket; how: Integer): Integer;
begin
  result := Posix.SysSocket.shutdown(s, how);
end;

function SetSockOpt(s: TSocket; level,optname: Integer; optval: pointer;
  optlen: Integer): Integer;
begin
  result := Posix.SysSocket.setsockopt(s, level, optname, optval, optlen);
end;

function GetSockOpt(s: TSocket; level,optname: Integer; optval: pointer;
  var optlen: Integer): Integer;
begin
  result := Posix.SysSocket.getsockopt(s,level,optname,pointer(optval),socklen_t(optlen));
end;

function ntohs(netshort: word): word;
begin
  result := Posix.ArpaInet.ntohs(NetShort);
end;

function ntohl(netlong: cardinal): cardinal;
begin
  result := Posix.ArpaInet.ntohl(NetLong);
end;

function Listen(s: TSocket; backlog: Integer): Integer;
begin
  if Posix.SysSocket.listen(s, backlog)=0 then
    result := 0 else
    result := SOCKET_ERROR;
end;

function IoctlSocket(s: TSocket; cmd: DWORD; var arg: integer): Integer;
begin
  result := Posix.StrOpts.ioctl(s,cmd,@arg);
end;

function htons(hostshort: word): word;
begin
  result := Posix.ArpaInet.htons(hostshort);
end;

function htonl(hostlong: cardinal): cardinal;
begin
  result := Posix.ArpaInet.htonl(hostlong);
end;

function CloseSocket(s: TSocket): Integer;
begin
  result := Posix.Unistd.__close(s);
end;

function Socket(af,Struc,Protocol: Integer): TSocket;
begin
  result := Posix.SysSocket.socket(af, struc, protocol);
end;

function Select(nfds: Integer; readfds,writefds,exceptfds: PFDSet;
  timeout: PTimeVal): Longint;
begin
  result := Posix.SysSelect.select(nfds,readfds,writefds,exceptfds,timeout);
end;

function IsNewApi(Family: integer): Boolean;
begin
  result := SockEnhancedApi;
  if not result then
    result := (Family=AF_INET6) and SockWship6Api;
end;

function GetSinPort(const Sin: TVarSin): Integer;
begin
  if (Sin.sin_family=AF_INET6) then
    result := ntohs(Sin.sin6_port) else
    result := ntohs(Sin.sin_port);
end;

//function poll(fds: PPollFD; nfds, timeout: integer): integer;
//begin
//  {$ifdef KYLIX3}
//  result := libc.poll(pointer(fds),nfds,timeout);
//  {$else}
//  result := fppoll(pointer(fds),nfds,timeout);
//  {$endif}
//end;

function SetVarSin(var Sin: TVarSin; const IP,Port: string;
  Family,SockProtocol,SockType: integer; PreferIP4: Boolean): integer;

  function GetAddr(const IP, port: AnsiString; var Hints: addrinfo; var Sin: TVarSin): integer;
  var Addr: Paddrinfo;
  begin
    Addr := nil;
    try
      FillChar(Sin, Sizeof(Sin), 0);
      if Hints.ai_socktype=SOCK_RAW then begin
        Hints.ai_socktype := 0;
        Hints.ai_protocol := 0;
        result := Posix.NetDB.getaddrinfo(PAnsiChar(IP), nil, Hints, Addr);
      end else
        if (IP=cAnyHost) or (IP=c6AnyHost) then begin
          Hints.ai_flags := AI_PASSIVE;
          result := Posix.NetDB.getaddrinfo(nil, PAnsiChar(Port), Hints, Addr);
        end else
          if (IP = cLocalhost) or (IP = c6Localhost) then
            result := Posix.NetDB.getaddrinfo(nil, PAnsiChar(Port), Hints, Addr) else
            result := Posix.NetDB.getaddrinfo(PAnsiChar(IP), PAnsiChar(Port), Hints, Addr);
      if (Result=0) and (Addr<>nil) then
        Move(Addr^.ai_addr^, Sin, Addr^.ai_addrlen);
    finally
      if Assigned(Addr) then
        Posix.NetDB.freeaddrinfo(Addr^);
    end;
  end;

var Hints1, Hints2: addrinfo;
    Sin1, Sin2: TVarSin;
    TwoPass: boolean;
begin
  FillChar(Hints1, Sizeof(Hints1), 0);
  FillChar(Hints2, Sizeof(Hints2), 0);
  TwoPass := False;
  if Family=AF_UNSPEC then begin
    if PreferIP4 then begin
      Hints1.ai_family := AF_INET;
      Hints2.ai_family := AF_INET6;
      TwoPass := True;
    end else begin
      Hints1.ai_family := AF_INET6;
      Hints2.ai_family := AF_INET;
      TwoPass := True;
    end;
  end else
    Hints1.ai_family := Family;
  Hints1.ai_socktype := SockType;
  Hints1.ai_protocol := SockProtocol;
  Hints2.ai_socktype := SockType;
  Hints2.ai_protocol := SockProtocol;
  result := GetAddr(IP, Port, Hints1, Sin1);
  if result=0 then
    sin := sin1 else
    if TwoPass then begin
      result := GetAddr(IP, Port, Hints2, Sin2);
      if result=0 then
        sin := sin2;
    end;
end;

{$IFDEF FPC} // FPC Version differs to above Kylix based
function SetVarSin(var Sin: TVarSin; const IP,Port: string;
  Family,SockProtocol,SockType: integer; PreferIP4: Boolean): integer;
var TwoPass: boolean;
    f1,f2: integer;

  function GetAddr(f:integer): integer;
  var a4: array[1..1] of TInAddr;
      a6: array[1..1] of TInAddr6;
      he: THostEntry;
  begin
    result := WSAEPROTONOSUPPORT;
    case f of
      AF_INET: begin
        if IP=cAnyHost then begin
          Sin.sin_family := AF_INET;
          result := 0;
        end else begin
          if lowercase(IP)=cLocalHostStr then
            a4[1].s_addr := htonl(INADDR_LOOPBACK) else begin
            a4[1].s_addr := 0;
            result := WSAHOST_NOT_FOUND;
            a4[1] := StrTonetAddr(IP);
            if a4[1].s_addr=INADDR_ANY then
              if GetHostByName(ip,he) then
                a4[1] := HostToNet(he.Addr) else
                Resolvename(ip,a4);
          end;
          if a4[1].s_addr <> INADDR_ANY then begin
            Sin.sin_family := AF_INET;
            sin.sin_addr := a4[1];
            result := 0;
          end;
        end;
      end;
      AF_INET6: begin
        if IP=c6AnyHost then begin
          Sin.sin_family := AF_INET6;
          result := 0;
        end else begin
          if lowercase(IP)=cLocalHostStr then
            SET_LOOPBACK_ADDR6(@a6[1]) else begin
            result := WSAHOST_NOT_FOUND;
            SET_IN6_IF_ADDR_ANY(@a6[1]);
            a6[1] := StrTonetAddr6(IP);
            if IN6_IS_ADDR_UNSPECIFIED(@a6[1]) then
              Resolvename6(ip,a6);
          end;
          if not IN6_IS_ADDR_UNSPECIFIED(@a6[1]) then begin
            Sin.sin_family := AF_INET6;
            sin.sin6_addr := a6[1];
            result := 0;
          end;
        end;
      end;
    end;
  end;

begin
  result := 0;
  if (Family=AF_UNIX) then begin
    Sin.AddressFamily := AF_UNIX;
    Move(IP[1],Sin.sun_path,length(IP));
    Sin.sun_path[length(IP)]:=#0;
    exit;
  end;

  FillChar(Sin,SizeOf(Sin),0);
  Sin.sin_port := Resolveport(port,family,SockProtocol,SockType);
  TwoPass := false;
  if Family=AF_UNSPEC then begin
    if PreferIP4 then begin
      f1 := AF_INET;
      f2 := AF_INET6;
      TwoPass := true;
    end else begin
      f2 := AF_INET6;
      f1 := AF_INET;
      TwoPass := true;
    end;
  end else
    f1 := Family;
  result := GetAddr(f1);
  if result <> 0 then
    if TwoPass then
      result := GetAddr(f2);
end;

{$ENDIF}

function GetSinIP(const Sin: TVarSin): AnsiString;
var host: array[0..NI_MAXHOST] of AnsiChar;
    serv: array[0..NI_MAXSERV] of AnsiChar;
    r: integer;
begin
  r := Posix.NetDB.getnameinfo(PSockAddr(@sin)^, SizeOfVarSin(sin), host, NI_MAXHOST,
                               serv, NI_MAXSERV, NI_NUMERICHOST+NI_NUMERICSERV);
  if r=0 then
    result := host else
    result := '';
end;

procedure ResolveNameToIP(const Name: AnsiString; Family, SockProtocol, SockType: integer;
  IPList: TStrings; IPListClear: boolean);
var
  Hints: addrinfo;
  Addr: PAddrinfo;
  AddrNext: PAddrinfo;
  r, prev: integer;
  host, serv: string;
  hostlen, servlen: integer;
begin
  if IPListClear then
    IPList.Clear;
  Addr := nil;
  try // we force to find TCP/IP
    FillChar(Hints, Sizeof(Hints), 0);
    Hints.ai_family := Family;
    Hints.ai_protocol := SockProtocol;
    Hints.ai_socktype := SockType;
    r := Posix.NetDB.getaddrinfo(PansiChar(Name), nil, Hints, Addr);
    if r=0 then begin
      AddrNext := Addr;
      while not(AddrNext=nil) do begin
        if not(((Family=AF_INET6) and (AddrNext^.ai_family=AF_INET))
          or ((Family=AF_INET) and (AddrNext^.ai_family=AF_INET6))) then begin
          hostlen := NI_MAXHOST;
          servlen := NI_MAXSERV;
          setlength(host,hostlen);
          setlength(serv,servlen);
          r := Posix.NetDB.getnameinfo(AddrNext^.ai_addr^, AddrNext^.ai_addrlen,
                                       PAnsiChar(host), hostlen, PAnsiChar(serv), servlen,
                                       NI_NUMERICHOST + NI_NUMERICSERV);
          if r=0 then begin
            host := PAnsiChar(host);
            IPList.Add(host);
          end;
        end;
        AddrNext := AddrNext^.ai_next;
      end;
    end;
  finally
    if Assigned(Addr) then
       Posix.NetDB.freeaddrinfo(Addr^);
  end;
  if IPList.Count=0 then
    IPList.Add(cAnyHost);
end;


//procedure ResolveNameToIP(const Name: AnsiString; Family, SockProtocol, SockType: integer;
//  IPList: TStrings; IPListClear: boolean);
//var x,n: integer;
//    a4: array[1..255] of in_addr;
//    a6: array[1..255] of Tin6_addr;
//    he: THostEntry;
//begin
//  if IPListClear then
//    IPList.Clear;
//  if (family=AF_INET) or (family=AF_UNSPEC) then begin
//    if lowercase(name)=cLocalHostStr then
//      IpList.Add(cLocalHost)
//    else if name=cAnyHost then
//      IpList.Add(cAnyHost)
//    else begin
//      a4[1] := StrTonetAddr(name);
//      if a4[1].s_addr=INADDR_ANY then
//        if GetHostByName(name,he) then begin
//          a4[1] := HostToNet(he.Addr);
//          x := 1;
//        end else
//          x := Resolvename(name,a4) else
//          x := 1;
//      for n := 1  to x do
//        IpList.Add(netaddrToStr(a4[n]));
//    end;
//  end;
//  if (family=AF_INET6) or (family=AF_UNSPEC) then begin
//    if lowercase(name)=cLocalHostStr then
//      IpList.Add(c6LocalHost)
//    else if name=c6AnyHost then
//      IpList.Add(c6AnyHost)
//    else begin
//      a6[1] := StrTonetAddr6(name);
//      if IN6_IS_ADDR_UNSPECIFIED(@a6[1]) then
//        x := Resolvename6(name,a6) else
//        x := 1;
//      for n := 1  to x do
//        IpList.Add(netaddrToStr6(a6[n]));
//    end;
//  end;
//  if IPList.Count=0 then
//    IPList.Add(cAnyHost);
//end;

{$IFDEF FPC}
function ResolvePort(const Port: string; Family,SockProtocol,SockType: integer): Word;
var ProtoEnt: TProtocolEntry;
    ServEnt: TServiceEntry;
begin
  result := htons(StrToIntDef(Port,0));
  if result=0 then begin
    ProtoEnt.Name := '';
    GetProtocolByNumber(SockProtocol,ProtoEnt);
    ServEnt.port := 0;
    GetServiceByName(Port,ProtoEnt.Name,ServEnt);
    result := ServEnt.port;
  end;
end;

function ResolveIPToName(const IP: string; Family,SockProtocol,SockType: integer): string;
var n: integer;
    a4: array[1..1] of TInAddr;
    a6: array[1..1] of TInAddr6;
    a: array[1..1] of string;
begin
  result := IP;
  a4[1] := StrToNetAddr(IP);
  if a4[1].s_addr <> INADDR_ANY then begin
    n := ResolveAddress(nettohost(a4[1]),a);
    if n>0 then
      result := a[1];
  end else begin
    a6[1] := StrToNetAddr6(IP);
    n := ResolveAddress6(a6[1],a);
    if n>0 then
      result := a[1];
  end;
end;
{$endif}


{$ifdef Linux} // epoll is Linux-specific

{$ifdef FPC} // use Linux.pas wrappers
function epoll_create(size: integer): integer;
begin
  result := Linux.epoll_create(size);
end;

function epoll_ctl(epfd, op, fd: integer; event: PEPollEvent): integer;
begin
  result := Linux.epoll_ctl(epfd, op, fd, pointer(event));
end;

function epoll_wait(epfd: integer; events: PEPollEvent; maxevents, timeout: integer): integer;
begin
  result := Linux.epoll_wait(epfd, pointer(events), maxevents, timeout);
end;

function epoll_close(epfd: integer): integer;
begin
  result := fpClose(epfd);
end;
{$endif}

{$ifdef KYLIX3} // use libc.so wrappers
function epoll_create; external libcmodulename name 'epoll_create';
function epoll_ctl; external libcmodulename name 'epoll_ctl';
function epoll_wait; external libcmodulename name 'epoll_wait';

function epoll_close(epfd: integer): integer;
begin
  result := __close(epfd);
end;
{$endif}

{$endif Linux}

procedure DestroySocketInterface;
begin
  // nothing to do, since we use either the FPC units, either LibC.pas
end;

initialization
  SET_IN6_IF_ADDR_ANY(@in6addr_any);
  SET_LOOPBACK_ADDR6(@in6addr_loopback);
  InitializeCriticalSection(SynSockCS);

finalization
  DeleteCriticalSection(SynSockCS);
end.
