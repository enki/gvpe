/*
    vpn_tcp.C -- handle the tcp part of the protocol.
    Copyright (C) 2003-2005 Marc Lehmann <gvpe@schmorp.de>
 
    This file is part of GVPE.

    GVPE is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with gvpe; if not, write to the Free Software
    Foundation, Inc. 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "config.h"

#if ENABLE_TCP

// tcp processing is extremely ugly, since the vpe protocol is simply
// designed for unreliable datagram networks. tcp is implemented by
// multiplexing packets over tcp. errors are completely ignored, as we
// rely on the higher level protocol to time out and reconnect.

#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <map>

#include "netcompat.h"

#include "vpn.h"

#if ENABLE_HTTP_PROXY
# include "conf.h"
#endif

struct tcp_connection;

struct lt_sockinfo
{
  bool operator()(const sockinfo *a, const sockinfo *b) const
  {
    return *a < *b;
  }
};

struct tcp_si_map : public map<const sockinfo *, tcp_connection *, lt_sockinfo> {
  void cleaner_cb (time_watcher &w); time_watcher cleaner;

  tcp_si_map ()
  : cleaner(this, &tcp_si_map::cleaner_cb)
  { }

} tcp_si;

struct tcp_connection : io_watcher {
  tstamp last_activity;
  const sockinfo si;
  vpn &v;
  bool active; // this connection has been actively established
  enum { ERROR, IDLE, CONNECTING, CONNECTING_PROXY, ESTABLISHED } state;

  vpn_packet *r_pkt;
  u32 r_len, r_ofs;

  vpn_packet *w_pkt;
  u32 w_len, w_ofs;

#if ENABLE_HTTP_PROXY
  char *proxy_req;
  int proxy_req_len;
#endif

  void tcpv4_ev (io_watcher &w, short revents);

  bool send_packet (vpn_packet *pkt, int tos);
  bool write_packet ();

  void error (); // abort conenction && cleanup

  operator tcp_si_map::value_type()
  {
    return tcp_si_map::value_type (&si, this);
  }

  tcp_connection (int fd_, const sockinfo &si_, vpn &v_);
  ~tcp_connection ();
};

void tcp_si_map::cleaner_cb (time_watcher &w)
{
  w.start (NOW + 600);

  tstamp to = NOW - ::conf.keepalive - 30 - 60;

  for (iterator i = begin (); i != end(); )
    if (i->second->last_activity >= to)
      ++i;
    else
      {
        erase (i);
        i = begin ();
      }
}

void
vpn::tcpv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      int fd = accept (w.fd, (sockaddr *)&sa, &sa_len);

      if (fd >= 0)
        {
          fcntl (fd, F_SETFL, O_NONBLOCK);
          fcntl (fd, F_SETFD, FD_CLOEXEC);

          sockinfo si(sa, PROT_TCPv4);

          slog (L_DEBUG, _("%s: accepted tcp connection"), (const char *)si);//D

          tcp_connection *i = new tcp_connection (fd, si, *this);
          tcp_si.insert (*i);
        }
    }
}

bool
vpn::send_tcpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  tcp_si_map::iterator info = tcp_si.find (&si);

  tcp_connection *i;

  if (info == tcp_si.end ())
    {
      i = new tcp_connection (-1, si, *this);
      tcp_si.insert (*i);
    }
  else
    i = info->second;

  return i->send_packet (pkt, tos);
}

bool
tcp_connection::write_packet ()
{
  ssize_t len;

  if (w_ofs < 2)
    {
      u16 plen = htons (w_pkt->len);

      iovec vec[2];
      //TODO: char* is the right type? hardly...
      vec[0].iov_base = (char *)((u8 *)&plen) + w_ofs;
      vec[0].iov_len = 2 - w_ofs;
      vec[1].iov_base = (char *)&((*w_pkt)[0]);
      vec[1].iov_len = w_len - 2;

      len = writev (fd, vec, 2);
    }
  else
    len = write (fd, &((*w_pkt)[w_ofs - 2]), w_len);

  if (len > 0)
    {
      w_ofs += len;
      w_len -= len;

      return w_len == 0;
    }
  else if (len < 0 && (errno == EAGAIN || errno == EINTR))
    return false;
  else
    {
      error ();
      return false;
    }
}

void
tcp_connection::tcpv4_ev (io_watcher &w, short revents)
{
  last_activity = NOW;

  if (revents & EVENT_WRITE)
    {
      if (state == CONNECTING)
        {
          state = ESTABLISHED;
          set (EVENT_READ);
#if ENABLE_HTTP_PROXY
          if (::conf.proxy_host && ::conf.proxy_port)
            {
              state = CONNECTING_PROXY;

              if (write (fd, proxy_req, proxy_req_len) == 0)
                {
                  error ();
                  return;
                }

              free (proxy_req); proxy_req = 0;
            }
#endif
        }
      else if (state == ESTABLISHED)
        {
          if (w_pkt)
            {
              if (write_packet ())
                {
                  delete w_pkt; w_pkt = 0;

                  set (EVENT_READ);
                }
            }
          else
            set (EVENT_READ);
        }
      else
        set (EVENT_READ);
    }

  if (revents & EVENT_READ)
    {
      if (state == ESTABLISHED)
        for (;;)
          {
            if (!r_pkt)
              {
                r_pkt = new vpn_packet;
                r_ofs = 0;
                r_len = 2; // header
              }

            ssize_t len = read (fd, &((*r_pkt)[r_ofs < 2 ? r_ofs : r_ofs - 2]), r_len);

            if (len > 0)
              {
                r_len -= len;
                r_ofs += len;

                if (r_len == 0)
                  {
                    if (r_ofs == 2)
                      {
                        r_len = ntohs (*(u16 *)&((*r_pkt)[0]));
                        r_pkt->len = r_len;

                        if (r_len > 0 && r_len < MAXSIZE)
                          continue;
                      }
                    else
                      {
                        v.recv_vpn_packet (r_pkt, si);
                        delete r_pkt;
                        r_pkt = 0;

                        continue;
                      }
                  }
                else
                  break;
              }
            else if (len < 0 && (errno == EINTR || errno == EAGAIN))
              break;

            // len == 0 <-> EOF
            error ();
            break;
          }
#if ENABLE_HTTP_PROXY
      else if (state == CONNECTING_PROXY)
        {
          fcntl (fd, F_SETFL, 0);
          char r[1024];
          int i;
          bool emptyline = false;

          // we do a blocking read of the response, to hell with it
          for (i = 0; i < 1023; i++)
            {
              int l = read (fd, &r[i], 1);

              if (l <= 0)
                {
                  error ();
                  return;
                }

              if (r[i] == '\012')
                {
                  if (emptyline)
                    break;
                  else
                    emptyline = true;
                }
              else if (r[i] != '\015')
                emptyline = false;
            }

          fcntl (fd, F_SETFL, O_NONBLOCK);

          if (i < 12)
            {
              slog (L_ERR, _("(%s): unable to do proxy-forwarding, short response"),
                    (const char *)si);
              error ();
            }
          else if (r[0] != 'H' || r[1] != 'T' || r[2] != 'T' || r[3] != 'P' || r[4] != '/'
                   || r[5] != '1' // http-major
                   || r[9] != '2') // response
            {
              slog (L_ERR, _("(%s): malformed or unexpected proxy response (%.12s)"),
                    (const char *)si, r);
              error ();
            }
          else
            state = ESTABLISHED;
        }
#endif
    }
}

bool
tcp_connection::send_packet (vpn_packet *pkt, int tos)
{
  last_activity = NOW;

  if (state == IDLE)
    {
      // woaw, the first lost packet ;)
      fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);

      if (fd >= 0)
        {
          const sockinfo *csi = &si;

#if ENABLE_HTTP_PROXY
          sockinfo psi;

          if (::conf.proxy_host && ::conf.proxy_port)
            {
              psi.set (::conf.proxy_host, ::conf.proxy_port, PROT_TCPv4);

              if (psi.valid ())
                {
                  csi = &psi;

                  proxy_req_len = asprintf (&proxy_req,
                                            "CONNECT %s:%d HTTP/1.0\015\012"
                                            "%s%s%s" // optional proxy-auth
                                            "\015\012",
                                            si.ntoa (),
                                            ntohs (si.port),
                                            ::conf.proxy_auth ? "Proxy-Authorization: Basic " : "",
                                            ::conf.proxy_auth ? ::conf.proxy_auth             : "",
                                            ::conf.proxy_auth ? "\015\012"                    : "");

                }
              else
                slog (L_ERR, _("unable to resolve http proxy hostname '%s', trying direct"),
                      ::conf.proxy_host);
            }
#endif
          
          fcntl (fd, F_SETFL, O_NONBLOCK);

          if (connect (fd, csi->sav4 (), csi->salenv4 ()) >= 0
              || errno == EINPROGRESS)
            {
              fcntl (fd, F_SETFL, O_NONBLOCK);
              fcntl (fd, F_SETFD, FD_CLOEXEC);

              state = CONNECTING;
              start (fd, EVENT_WRITE);
            }
          else
            close (fd);
        }
    }
  else if (state == ESTABLISHED)
    {
      // drop packet if the tcp write buffer is full. this *is* the
      // right thing to do, not using tcp *is* the right thing to do.
      if (!w_pkt)
        {
          // how this maps to the underlying tcp packets we don't know
          // and we don't care. at least we tried ;)
#if defined(SOL_IP) && defined(IP_TOS)
          setsockopt (fd, SOL_IP, IP_TOS, &tos, sizeof tos);
#endif

          w_pkt = pkt;
          w_ofs = 0;
          w_len = pkt->len + 2; // length + size header

          if (write_packet ())
            w_pkt = 0;
          else
            {
              w_pkt = new vpn_packet;
              w_pkt->set (*pkt);

              set (EVENT_READ | EVENT_WRITE);
            }
        }
    }

  return state != ERROR;
}

void tcp_connection::error ()
{
  if (fd >= 0)
    {
      close (fd);
      fd = -1;
    }

  delete r_pkt; r_pkt = 0;
  delete w_pkt; w_pkt = 0;
#if ENABLE_HTTP_PROXY
  free (proxy_req); proxy_req = 0;
#endif

  stop ();
  state = active ? IDLE : ERROR;
}

tcp_connection::tcp_connection (int fd_, const sockinfo &si_, vpn &v_)
: v(v_), si(si_), io_watcher(this, &tcp_connection::tcpv4_ev)
{
  if (!tcp_si.cleaner.active)
    tcp_si.cleaner.start (0);

  last_activity = NOW;
  r_pkt = 0;
  w_pkt = 0;
  fd = fd_;
#if ENABLE_HTTP_PROXY
  proxy_req = 0;
#endif

  if (fd < 0)
    {
      active = true;
      state = IDLE;
    }
  else
    {
      active = false;
      state = ESTABLISHED;
      start (fd, EVENT_READ);
    }
}

tcp_connection::~tcp_connection ()
{
  error ();
}

#endif

