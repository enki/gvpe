/*
    vpn_tcp.C -- handle the tcp part of the protocol.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc. 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include <sys/poll.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>

#include "vpn.h"

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
    {
      cleaner.start (0);
    }
} tcp_si;

struct tcp_connection : io_watcher {
  tstamp last_activity;
  const sockinfo si;
  vpn &v;
  bool active; // this connection has been actively established
  enum { ERROR, IDLE, CONNECTING, ESTABLISHED } state;

  vpn_packet *r_pkt;
  u32 r_len, r_ofs;

  vpn_packet *w_pkt;
  u32 w_len, w_ofs;

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
  w.at = NOW + 600;
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
  if (revents & (POLLIN | POLLERR))
    {
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      int fd = accept (w.fd, (sockaddr *)&sa, &sa_len);

      if (fd >= 0)
        {
          sockinfo si(sa, PROT_TCPv4);

          slog (L_DEBUG, _("%s: accepted tcp connection"), (const char *)si);//D

          fcntl (fd, F_SETFL, O_NONBLOCK);

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

void tcp_connection::error ()
{
  if (fd >= 0)
    {
      close (fd);
      fd = -1;
    }

  delete r_pkt; r_pkt = 0;
  delete w_pkt; w_pkt = 0;

  stop ();
  state = active ? IDLE : ERROR;
}

bool
tcp_connection::write_packet ()
{
  ssize_t len;

  if (w_ofs < 2)
    {
      u16 plen = htons (w_pkt->len);

      iovec vec[2];
      vec[0].iov_base = ((u8 *)&plen) + w_ofs;
      vec[0].iov_len = 2 - w_ofs;
      vec[1].iov_base = &((*w_pkt)[0]);
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

  if (revents & (POLLERR | POLLHUP))
    {
      error ();
      return;
    }

  if (revents & POLLOUT)
    {
      if (state == CONNECTING)
        {
          state = ESTABLISHED;
          set (POLLIN);
        }
      else if (state == ESTABLISHED)
        {
          if (w_pkt)
            {
              if (write_packet ())
                {
                  delete w_pkt; w_pkt = 0;

                  set (POLLIN);
                }
            }
          else
            set (POLLIN);
        }
      else
        set (POLLIN);
    }

  if (revents & POLLIN)
    {
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

          error ();
          break;
        }
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
          fcntl (fd, F_SETFL, O_NONBLOCK);
          
          if (connect (fd, si.sav4 (), si.salenv4 ()) >= 0
              || errno == EINPROGRESS)
            {
              state = CONNECTING;
              start (fd, POLLOUT);
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
          setsockopt (fd, SOL_IP, IP_TOS, &tos, sizeof tos);

          w_pkt = pkt;
          w_ofs = 0;
          w_len = pkt->len + 2; // length + size header

          if (write_packet ())
            w_pkt = 0;
          else
            {
              w_pkt = new vpn_packet;
              w_pkt->set (*pkt);

              set (POLLIN | POLLOUT);
            }
        }
    }

  return state != ERROR;
}

tcp_connection::tcp_connection (int fd_, const sockinfo &si_, vpn &v_)
: v(v_), si(si_), io_watcher(this, &tcp_connection::tcpv4_ev)
{
  last_activity = NOW;
  r_pkt = 0;
  w_pkt = 0;
  fd = fd_;

  if (fd < 0)
    {
      active = true;
      state = IDLE;
    }
  else
    {
      active = false;
      state = ESTABLISHED;
      start (fd, POLLIN);
    }
}

tcp_connection::~tcp_connection ()
{
  error ();
}

#endif

