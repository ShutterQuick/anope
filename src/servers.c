/* Routines to maintain a list of connected servers
 *
 * (C) 2003-2010 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 *
 * $Id$
 *
 */

#include "services.h"
#include "modules.h"

Server *servlist = NULL;
Server *me_server = NULL;	   /* This are we		*/
Server *serv_uplink = NULL;	 /* This is our uplink */
Flags<CapabType> Capab;
char *uplink;
char *TS6UPLINK;
char *TS6SID;

/* For first_server / next_server */
static Server *server_cur;

CapabInfo Capab_Info[] = {
	{"NOQUIT", CAPAB_NOQUIT},
	{"TSMODE", CAPAB_TSMODE},
	{"UNCONNECT", CAPAB_UNCONNECT},
	{"NICKIP", CAPAB_NICKIP},
	{"SSJOIN", CAPAB_NSJOIN},
	{"ZIP", CAPAB_ZIP},
	{"BURST", CAPAB_BURST},
	{"TS5", CAPAB_TS5},
	{"TS3", CAPAB_TS3},
	{"DKEY", CAPAB_DKEY},
	{"PT4", CAPAB_PT4},
	{"SCS", CAPAB_SCS},
	{"QS", CAPAB_QS},
	{"UID", CAPAB_UID},
	{"KNOCK", CAPAB_KNOCK},
	{"CLIENT", CAPAB_CLIENT},
	{"IPV6", CAPAB_IPV6},
	{"SSJ5", CAPAB_SSJ5},
	{"SN2", CAPAB_SN2},
	{"TOK1", CAPAB_TOKEN},
	{"TOKEN", CAPAB_TOKEN},
	{"VHOST", CAPAB_VHOST},
	{"SSJ3", CAPAB_SSJ3},
	{"SJB64", CAPAB_SJB64},
	{"CHANMODES", CAPAB_CHANMODE},
	{"NICKCHARS", CAPAB_NICKCHARS},
	{"", CAPAB_END}
};

/*************************************************************************/

/**
 * Return the first server in the server struct
 * @param flag Server Flag, see services.h
 * @return Server Struct
 */
Server *first_server(ServerFlag flag)
{
	server_cur = servlist;

	while (server_cur && !server_cur->HasFlag(flag))
		server_cur = next_server(flag);
	return server_cur;
}

/*************************************************************************/

/**
 * Return the next server in the server struct
 * @param flags Server Flags, see services.h
 * @return Server Struct
 */
Server *next_server(ServerFlag flag)
{
	if (!server_cur)
		return NULL;

	do {
		if (server_cur->links) {
			server_cur = server_cur->links;
		} else if (server_cur->next) {
			server_cur = server_cur->next;
		} else {
			do {
				server_cur = server_cur->uplink;
				if (server_cur && server_cur->next) {
					server_cur = server_cur->next;
					break;
				}
			} while (server_cur);
		}
	} while (server_cur && !server_cur->HasFlag(flag));

	return server_cur;
}

/*************************************************************************/

/**
 * This function makes a new Server structure and links it in the right
 * places in the linked list if a Server struct to it's uplink if provided.
 * It can also be NULL to indicate it's the uplink and should be first in
 * the server list.
 * @param server_uplink Server struct
 * @param name Server Name
 * @param desc Server Description
 * @param flags Server Flags, see services.h
 * @param suid Server Universal ID
 * @return Server Struct
 */
Server *new_server(Server * server_uplink, const char *name, const char *desc,
				   ServerFlag flag, const std::string &suid)
{
	Server *serv;

	Alog(LOG_DEBUG) << "Creating " << name << "(" << suid << ") uplinked to " << (server_uplink ? server_uplink->name : "No uplink");
	serv = new Server;
	if (!name)
		name = "";
	serv->name = sstrdup(name);
	serv->desc = sstrdup(desc);
	if (flag != SERVER_START)
		serv->SetFlag(flag);
	serv->uplink = server_uplink;
	if (!suid.empty())
		serv->suid = sstrdup(suid.c_str());
	else
		serv->suid = NULL;

	serv->sync = SSYNC_IN_PROGRESS;
	serv->links = NULL;
	serv->prev = NULL;

	if (!server_uplink) {
		serv->hops = 0;
		serv->next = servlist;
		if (servlist)
			servlist->prev = serv;
		servlist = serv;
	} else {
		serv->hops = server_uplink->hops + 1;
		serv->next = server_uplink->links;
		if (server_uplink->links)
			server_uplink->links->prev = serv;
		server_uplink->links = serv;
	}

	/* Check if this is our uplink server */
	if ((server_uplink == me_server) && flag != SERVER_JUPED)
	{
		// XXX: Apparantly we set ourselves as serv_uplink before we (really) set the uplink when we recieve SERVER. This is wrong and ugly.
		if (serv_uplink != NULL)
		{
			/* Bring in our pseudo-clients */
			introduce_user("");

			/* And hybrid needs Global joined in the logchan */
			if (LogChan && ircd->join2msg) {
				/* XXX might desync */
				ircdproto->SendJoin(findbot(Config.s_GlobalNoticer), Config.LogChannel, time(NULL));
			}
		}
		serv_uplink = serv;
		serv->SetFlag(SERVER_ISUPLINK);
	}

	return serv;
}

/*************************************************************************/

/**
 * Remove and free a Server structure. This function is the most complete
 * remove treatment a server can get, as it first quits all clients which
 * still pretend to be on this server, then it walks through all connected
 * servers and disconnects them too. If all mess is cleared, the server
 * itself will be too.
 * @param Server struct
 * @param reason the server quit
 * @return void
 */
static void delete_server(Server * serv, const char *quitreason)
{
	Server *s, *snext;
	User *u, *unext;
	NickAlias *na;

	if (!serv) {
		Alog(LOG_DEBUG) << "delete_server() called with NULL arg!";
		return;
	}

	Alog(LOG_DEBUG) << "delete_server() called, deleting " << serv->name << "(" << serv->suid << ") uplinked to " 
			<< (serv->uplink ? serv->uplink->name : "NOTHING") << "(" 
			<< (serv->uplink ? serv->uplink->suid : "NOSUIDUPLINK") << ")";

	if (Capab.HasFlag(CAPAB_NOQUIT) || Capab.HasFlag(CAPAB_QS))
	{
		u = firstuser();
		while (u)
		{
			unext = nextuser();
			if (u->server == serv)
			{
				if ((na = findnick(u->nick)) && !na->HasFlag(NS_FORBIDDEN)
					&& (!na->nc->HasFlag(NI_SUSPENDED))
					&& (u->IsRecognized() || u->IsIdentified())) {
					na->last_seen = time(NULL);
					if (na->last_quit)
						delete [] na->last_quit;
					na->last_quit = (quitreason ? sstrdup(quitreason) : NULL);
				}
					if (Config.LimitSessions && !is_ulined(u->server->name)) {
					del_session(u->host);
				}
				delete u;
			}
			u = unext;
		}
		Alog(LOG_DEBUG) << "delete_server() cleared all users";
	}

	s = serv->links;
	while (s) {
		snext = s->next;
		delete_server(s, quitreason);
		s = snext;
	}

	Alog(LOG_DEBUG) << "delete_server() cleared all servers";

	delete [] serv->name;
	delete [] serv->desc;
	if (serv->prev)
		serv->prev->next = serv->next;
	if (serv->next)
		serv->next->prev = serv->prev;
	if (serv->uplink->links == serv)
		serv->uplink->links = serv->next;

	Alog(LOG_DEBUG) << "delete_server() completed";
}

/*************************************************************************/

/**
 * Find a server by name, returns NULL if not found
 * @param s Server struct
 * @param name Server Name
 * @return Server struct
 */
Server *findserver(Server * s, const char *name)
{
	Server *sl;

	if (!name || !*name) {
		return NULL;
	}

	Alog(LOG_DEBUG) << "findserver(" << name << ")";

	while (s && (stricmp(s->name, name) != 0))
	{
		Alog(LOG_DEBUG_3) << "Compared " << s->name << ", not a match";
		if (s->links)
		{
			sl = findserver(s->links, name);
			if (sl)
			{
				s = sl;
			}
			else
			{
				s = s->next;
			}
		}
		else
		{
			s = s->next;
		}
	}

	Alog(LOG_DEBUG) << "findserver(" << name << ") -> " << static_cast<void *>(s);
	return s;
}

/*************************************************************************/

/**
 * Find a server by UID, returns NULL if not found
 * @param s Server struct
 * @param name Server Name
 * @return Server struct
 */
Server *findserver_uid(Server * s, const char *name)
{
	Server *sl;

	if (!name || !*name) {
		return NULL;
	}

	Alog(LOG_DEBUG) << "findserver_uid(" << name << ")";

	while (s && s->suid && (stricmp(s->suid, name) != 0))
	{
		Alog(LOG_DEBUG_3) << "Compared " << s->suid << ", not a match";
		if (s->links)
		{
			sl = findserver_uid(s->links, name);
			if (sl)
			{
				s = sl;
			}
			else
			{
				s = s->next;
			}
		}
		else
		{
			s = s->next;
		}
	}

	Alog(LOG_DEBUG) << "findserver_uid(" << name << ") -> " << static_cast<void *>(s);
	return s;
}

/*************************************************************************/

/**
 * Find if the server is synced with the network
 * @param s Server struct
 * @param name Server Name
 * @return Not Synced returns -1, Synced returns 1, Error returns 0
 */
int anope_check_sync(const char *name)
{
	Server *s;
	s = findserver(servlist, name);

	if (!s)
		return 0;

	if (is_sync(s))
		return 1;
	else
		return -1;
}

/*************************************************************************/

/**
 * Handle adding the server to the Server struct
 * @param source Name of the uplink if any
 * @param servername Name of the server being linked
 * @param hops Number of hops to reach this server
 * @param descript Description of the server
 * @param numeric Server Numberic/SUID
 * @return void
 */
void do_server(const char *source, const char *servername, const char *hops,
			   const char *descript, const std::string &numeric)
{
	Server *s, *newserver;

	Alog(LOG_DEBUG) << "Server introduced (" << servername << ")" << (*source ? " from " : "") << (*source ? source : "");


	if (source[0] == '\0')
		s = me_server;
	else
		s = findserver(servlist, source);

	if (s == NULL)
		s = findserver_uid(servlist, source);

	if (s == NULL)
		throw CoreException("Recieved a server from a nonexistant uplink?");

	/* Create a server structure. */
	newserver = new_server(s, servername, descript, SERVER_START, numeric);

	/* Announce services being online. */
	if (Config.GlobalOnCycle && Config.GlobalOnCycleUP)
		notice_server(Config.s_GlobalNoticer, newserver, "%s", Config.GlobalOnCycleUP);

	/* Let modules know about the connection */
	FOREACH_MOD(I_OnNewServer, OnNewServer(newserver));
}

/*************************************************************************/

/**
 * Handle removing the server from the Server struct
 * @param source Name of the server leaving
 * @param ac Number of arguments in av
 * @param av Agruments as part of the SQUIT
 * @return void
 */
void do_squit(const char *source, int ac, const char **av)
{
	char buf[BUFSIZE];
	Server *s;

	if (ircd->ts6) {
		s = findserver_uid(servlist, av[0]);
		if (!s) {
			s = findserver(servlist, av[0]);
		}
	} else {
		s = findserver(servlist, av[0]);
	}
	if (!s)
	{
		Alog() << "SQUIT for nonexistent server (" << av[0] << ")!!";
		return;
	}
	FOREACH_MOD(I_OnServerQuit, OnServerQuit(s));

	/* If this is a juped server, send a nice global to inform the online
	 * opers that we received it.
	 */
	if (s->HasFlag(SERVER_JUPED))
	{
		snprintf(buf, BUFSIZE, "Received SQUIT for juped server %s",
				 s->name);
		ircdproto->SendGlobops(findbot(Config.s_OperServ), buf);
	}

	snprintf(buf, sizeof(buf), "%s %s", s->name,
			 (s->uplink ? s->uplink->name : ""));

	if (s->uplink == me_server && Capab.HasFlag(CAPAB_UNCONNECT))
	{
		Alog(LOG_DEBUG) << "Sending UNCONNECT SQUIT for " << s->name;
		/* need to fix */
		ircdproto->SendSquit(s->name, buf);
	}

	delete_server(s, buf);
}

/*************************************************************************/

/** Handle parsing the CAPAB/PROTOCTL messages
 * @param ac Number of args
 * @param av Args
 */
void CapabParse(int ac, const char **av)
{
	for (int i = 0; i < ac; ++i)
	{
		for (unsigned j = 0; !Capab_Info[j].Token.empty(); ++j)
		{
			if (av[i] == Capab_Info[j].Token)
			{
				Capab.SetFlag(Capab_Info[j].Flag);

				if (Capab_Info[j].Token == "NICKIP" && !ircd->nickip)
					ircd->nickip = 1;
				break;
			}
		}
	}
}

/*************************************************************************/

/**
 * Search the uline servers array to find out if the server that just set the
 * mode is in our uline list
 * @param server Server Setting the mode
 * @return int 0 if not found, 1 if found
 */
int is_ulined(const char *server)
{
	int j;

	for (j = 0; j < Config.NumUlines; j++) {
		if (stricmp(Config.Ulines[j], server) == 0) {
			return 1;
		}
	}

	return 0;
}

/*************************************************************************/

/**
 * See if the current server is synced, or has an unknown sync state
 * (in which case we pretend it is always synced)
 * @param server Server of which we want to know the state
 * @return int 0 if not synced, 1 if synced
 */
int is_sync(Server * server)
{
	if (server->sync == SSYNC_DONE)
		return 1;
	return 0;
}

/*************************************************************************/

/* Finish the syncing process for this server and (optionally) for all
 * it's leaves as well
 * @param serv Server to finish syncing
 * @param sync_links Should all leaves be synced as well? (1: yes, 0: no)
 * @return void
 */
void finish_sync(Server * serv, int sync_links)
{
	Server *s;

	if (!serv || is_sync(serv))
		return;

	/* Mark each server as in sync */
	s = serv;
	do {
		if (!is_sync(s)) 
		{
			Alog(LOG_DEBUG) << "Finishing sync for server " << s->name;
			s->sync = SSYNC_DONE;
		}

		if (!sync_links)
			break;

		if (s->links) {
			s = s->links;
		} else if (s->next) {
			s = s->next;
		} else {
			do {
				s = s->uplink;
				if (s == serv)
					s = NULL;
				if (s == me_server)
					s = NULL;
			} while (s && !(s->next));
			if (s)
				s = s->next;
		}
	} while (s);

	if (serv == serv_uplink)
	{
		FOREACH_MOD(I_OnFinishSync, OnFinishSync(serv));
		ircdproto->SendEOB();
	}

	/* Do some general stuff which should only be done once */
	// XXX: this doesn't actually match the description. finish_sync(), depending on the ircd, can be called multiple times
	// Perhaps this should be done if serv == serv_uplink?
	restore_unsynced_topics();
	Alog() << "Server " << serv->name << " is done syncing";

	FOREACH_MOD(I_OnServerSync, OnServerSync(s));
	if (serv == serv_uplink)
	{
		FOREACH_MOD(I_OnUplinkSync, OnUplinkSync());
	}
}

/*******************************************************************/

/* TS6 UID generator common code.
 *
 * Derived from atheme-services, uid.c (hg 2954:116d46894b4c).
 *		 -nenolod
 */
static int ts6_uid_initted = 0;
static char ts6_new_uid[10];	/* allow for \0 */
static unsigned int ts6_uid_index = 9;  /* last slot in uid buf */

void ts6_uid_init()
{
	snprintf(ts6_new_uid, 10, "%sAAAAAA", TS6SID);
	ts6_uid_initted = 1;
}

void ts6_uid_increment(unsigned int slot)
{
	if (slot != strlen(TS6SID)) {
		if (ts6_new_uid[slot] == 'Z')
			ts6_new_uid[slot] = '0';
		else if (ts6_new_uid[slot] == '9') {
			ts6_new_uid[slot] = 'A';
			ts6_uid_increment(slot - 1);
		} else
			ts6_new_uid[slot]++;
	} else {
		if (ts6_new_uid[slot] == 'Z')
			for (slot = 3; slot < 9; slot++)
				ts6_new_uid[slot] = 'A';
		else
			ts6_new_uid[slot]++;
	}
}

const char *ts6_uid_retrieve()
{
	if (ircd->ts6 == 0)
	{
		Alog(LOG_DEBUG) << "ts6_uid_retrieve(): TS6 not supported on this ircd";
		return "";
	}

	if (ts6_uid_initted != 1)
	{
		throw CoreException("TS6 IRCd and ts6_uid_init() hasn't been called!");
	}

	ts6_uid_increment(ts6_uid_index - 1);
	return ts6_new_uid;
}

/*******************************************************************/

/*
 * TS6 generator code, provided by DukePyrolator
 */

static int ts6_sid_initted = 0;
static char ts6_new_sid[4];

static void ts6_sid_increment(unsigned pos)
{
	/*
	 * An SID must be exactly 3 characters long, starts with a digit,
	 * and the other two characters are A-Z or digits
	 * The rules for generating an SID go like this...
	 * --> ABCDEFGHIJKLMNOPQRSTUVWXYZ --> 0123456789 --> WRAP
	 */
	if (!pos)
	{
		/* At pos 0, if we hit '9', we've run out of available SIDs,
		 * reset the SID to the smallest possible value and try again. */
		if (ts6_new_sid[pos] == '9')
		{
			ts6_new_sid[0] = '0';
			ts6_new_sid[1] = 'A';
			ts6_new_sid[2] = 'A';
		}
		else
			// But if we haven't, just keep incrementing merrily.
			++ts6_new_sid[0];
	}
	else
	{
		if (ts6_new_sid[pos] == 'Z')
			ts6_new_sid[pos] = '0';
		else if (ts6_new_sid[pos] == '9')
		{
			ts6_new_sid[pos] = 'A';
			ts6_sid_increment(pos - 1);
		}
		else
			++ts6_new_sid[pos];
	}
}

const char *ts6_sid_retrieve()
{
	if (!ircd->ts6)
	{
		Alog(LOG_DEBUG) << "ts6_sid_retrieve(): TS6 not supported on this ircd";
		return "";
	}

	if (!ts6_sid_initted)
	{
		// Initialize ts6_new_sid with the services server SID
		snprintf(ts6_new_sid, 4, "%s", TS6SID);
		ts6_sid_initted = 1;
	}
	while (1)
	{
		// Check if the new SID is used by a known server
		if (!findserver_uid(servlist, ts6_new_sid))
			// return the new SID
			return ts6_new_sid;

		// Add one to the last SID
		ts6_sid_increment(2);
	}
	/* not reached */
	return "";
}

/* EOF */