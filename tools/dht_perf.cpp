/*

Copyright (c) 2014, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/


#include "libtorrent/session.hpp"
#include "libtorrent/hex.hpp" // for from_hex
#include "libtorrent/alert_types.hpp"
#include "libtorrent/bencode.hpp" // for bencode()
#include "libtorrent/kademlia/item.hpp" // for sign_mutable_item
#include "libtorrent/ed25519.hpp"

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <stdlib.h>

using namespace libtorrent;
namespace lt = libtorrent;

#ifdef TORRENT_DISABLE_DHT

int main(int argc, char* argv[])
{
	fprintf(stderr, "not built with DHT support\n");
	return 1;
}

#else

time_point g_start;
sha1_hash g_target;
int g_get_interval = 60;
int g_port = 0;

alert* wait_for_alert(lt::session& s, int alert_type)
{
	alert* ret = NULL;
	bool found = false;

	while (!found)
	{
		s.wait_for_alert(seconds(5));
		if (g_start + minutes(g_get_interval) < clock_type::now())
		{
			g_start = clock_type::now();
			s.dht_get_item(g_target);
		};

		std::vector<alert*> alerts;
		s.pop_alerts(&alerts);
		for (std::vector<alert*>::iterator i = alerts.begin()
			, end(alerts.end()); i != end; ++i)
		{
			if ((*i)->type() != alert_type)
			{
				continue;
			}
			ret = *i;
			found = true;
		}
	}
	return ret;
}

void bootstrap(lt::session& s)
{
	wait_for_alert(s, dht_bootstrap_alert::alert_type);
	wait_for_alert(s, dht_bootstrap_alert::alert_type);
	wait_for_alert(s, dht_bootstrap_alert::alert_type);
}

struct settings
{
	bool read_only;
	bool strap;
	bool ping;
	int interval;

	settings()
	: read_only(false)
	, strap(true)
	, ping(false)
	, interval(5) {};
};

void usage()
{
	printf("Usage:\n");
	printf("dht [readonly] [nostrap] [ping] [refresh <xxx>] [get_target <key>] [get_interval <xxx>] [port <xxx>]\n");
}

bool parse(settings& sett, int argc, char* argv[])
{
	if (argc == 1) return true;
        --argc;
        ++argv;
         while(argc)
         {
		if (0 == strcmp(argv[0], "readonly")) {
			sett.read_only = true;
		} else if (0 == strcmp(argv[0], "nostrap")) {
			sett.strap = false;
		} else if (0 == strcmp(argv[0], "ping")) {
			sett.ping = true;
		} else if (0 == strcmp(argv[0], "refresh")) {
			if (argc <= 1) {
				usage();
				return false;
			}
			--argc;
			++argv;
			sett.interval = atoi(argv[0]);
			if (sett.interval == 0) sett.interval = 5;
		} else if (0 == strcmp(argv[0], "get_target")) {
			if (argc <= 1) {
				usage();
				return false;
			}
			--argc;
			++argv;
			bool ret = from_hex(argv[0], 40, (char*)&g_target[0]);
			if (!ret) {
				printf("invalid target.\n");
				return false;
			}
		} else if (0 == strcmp(argv[0], "get_interval")) {
			if (argc <= 1) {
				usage();
				return false;
			}
			--argc;
			++argv;
			g_get_interval = atoi(argv[0]);
			if (g_get_interval == 0) g_get_interval = 60;
		} else if (0 == strcmp(argv[0], "port")) {
			if (argc <= 1) {
				usage();
				return false;
			}
			--argc;
			++argv;
			g_port = atoi(argv[0]);
		} else {
			usage();
			return false;
		}

                --argc;
                ++argv;
        };

	return true;
}

int main(int argc, char* argv[])
{
	char HelloWorld[] = "da2c25c84131ef9979fd3a2c7a358b7b13091fff";
	from_hex(HelloWorld, 40, (char*)&g_target[0]);

	settings us;
	if (!parse(us, argc, argv)) return 0;

	std::string listen = "0.0.0.0:" + boost::lexical_cast<std::string>(g_port);

	std::cout << "Readonly: " << us.read_only << ", Ping: " << us.ping
		<< ", Strap: " << us.strap << ", Refresh: " << us.interval 
		<< ", Port: " << g_port << std::endl;
	g_start = clock_type::now();

	settings_pack sett;
	sett.set_int(settings_pack::aio_threads, 0);
	sett.set_int(settings_pack::alert_mask, 0xffffffff);
	sett.set_str(settings_pack::listen_interfaces, listen);
	sett.set_bool(settings_pack::enable_dht, false);
	sett.set_bool(settings_pack::enable_upnp, false);
	sett.set_bool(settings_pack::enable_natpmp, false);

	session s(sett);

	s.add_dht_router(std::pair<std::string, int>("router.utorrent.com", 6881));
	dht_settings dht_sett = s.get_dht_settings();
	dht_sett.read_only = us.read_only;
	dht_sett.strap = us.strap;
	dht_sett.ping = us.ping;
	dht_sett.interval = us.interval;
	s.set_dht_settings(dht_sett);

	sett.set_bool(settings_pack::enable_dht, true);
	s.apply_settings(sett);

	std::cout << "Port: " << s.listen_port() << std::endl;

	bootstrap(s);
}

#endif

