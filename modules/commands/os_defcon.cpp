/* OperServ core functions
 *
 * (C) 2003-2014 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 */

#include "module.h"
#include "modules/os_session.h"
#include "modules/cs_mode.h"

enum DefconLevel
{
	DEFCON_NO_NEW_CHANNELS,
	DEFCON_NO_NEW_NICKS,
	DEFCON_NO_MLOCK_CHANGE,
	DEFCON_FORCE_CHAN_MODES,
	DEFCON_REDUCE_SESSION,
	DEFCON_NO_NEW_CLIENTS,
	DEFCON_OPER_ONLY,
	DEFCON_SILENT_OPER_ONLY,
	DEFCON_AKILL_NEW_CLIENTS,
	DEFCON_NO_NEW_MEMOS
};

bool DefConModesSet = false;

struct DefconConfig
{
	std::vector<std::bitset<32> > DefCon;
	std::set<Anope::string> DefConModesOn, DefConModesOff;
	std::map<Anope::string, Anope::string> DefConModesOnParams;

	int defaultlevel, sessionlimit;
	Anope::string chanmodes, message, offmessage, akillreason;
	std::vector<Anope::string> defcons;
	time_t akillexpire, timeout;
	bool globalondefcon;

	unsigned max_session_kill;
	time_t session_autokill_expiry;
	Anope::string sle_reason, sle_detailsloc;

	DefconConfig()
	{
		this->DefCon.resize(6);
		this->defcons.resize(5);
	}

	bool Check(DefconLevel level)
	{
		return this->Check(this->defaultlevel, level);
	}

	bool Check(int dlevel, DefconLevel level)
	{
		return this->DefCon[dlevel].test(level);
	}

	void Add(int dlevel, DefconLevel level)
	{
		this->DefCon[dlevel][level] = true;
	}

	void Del(int dlevel, DefconLevel level)
	{
		this->DefCon[dlevel][level] = false;
	}

	bool SetDefConParam(const Anope::string &name, const Anope::string &buf)
	{
	       return DefConModesOnParams.insert(std::make_pair(name, buf)).second;
	}

	void UnsetDefConParam(const Anope::string &name)
	{
		DefConModesOnParams.erase(name);
	}
	
	bool GetDefConParam(const Anope::string &name, Anope::string &buf)
	{
	       std::map<Anope::string, Anope::string>::iterator it = DefConModesOnParams.find(name);
	
	       buf.clear();
	
	       if (it != DefConModesOnParams.end())
	       {
	               buf = it->second;
	               return true;
	       }
	
	       return false;
	}
};

static DefconConfig DConfig;

static void runDefCon();
static Anope::string defconReverseModes(const Anope::string &modes);

static ServiceReference<GlobalService> GlobalService("GlobalService", "Global");

static Timer *timeout;

class DefConTimeout : public Timer
{
	int level;

 public:
	DefConTimeout(Module *mod, int newlevel) : Timer(mod, DConfig.timeout), level(newlevel)
	{
		timeout = this;
	}

	~DefConTimeout()
	{
		timeout = NULL;
	}

	void Tick(time_t) anope_override
	{
		if (DConfig.defaultlevel != level)
		{
			DConfig.defaultlevel = level;
			FOREACH_MOD(OnDefconLevel, (level));
			Log(Config->GetClient("OperServ"), "operserv/defcon") << "Defcon level timeout, returning to level " << level;

			if (DConfig.globalondefcon)
			{
				if (!DConfig.offmessage.empty())
					GlobalService->SendGlobal(NULL, "", DConfig.offmessage);
				else
					GlobalService->SendGlobal(NULL, "", Anope::printf(Language::Translate(_("The Defcon level is now at: \002%d\002")), DConfig.defaultlevel));

				if (!DConfig.message.empty())
					GlobalService->SendGlobal(NULL, "", DConfig.message);
			}

			runDefCon();
		}
	}
};

class CommandOSDefcon : public Command
{
	void SendLevels(CommandSource &source)
	{
		if (DConfig.Check(DEFCON_NO_NEW_CHANNELS))
			source.Reply(_("* No new channel registrations"));
		if (DConfig.Check(DEFCON_NO_NEW_NICKS))
			source.Reply(_("* No new nick registrations"));
		if (DConfig.Check(DEFCON_NO_MLOCK_CHANGE))
			source.Reply(_("* No mode lock changes"));
		if (DConfig.Check(DEFCON_FORCE_CHAN_MODES) && !DConfig.chanmodes.empty())
			source.Reply(_("* Force channel modes (%s) to be set on all channels"), DConfig.chanmodes.c_str());
		if (DConfig.Check(DEFCON_REDUCE_SESSION))
			source.Reply(_("* Use the reduced session limit of %d"), DConfig.sessionlimit);
		if (DConfig.Check(DEFCON_NO_NEW_CLIENTS))
			source.Reply(_("* Kill any new clients connecting"));
		if (DConfig.Check(DEFCON_OPER_ONLY))
			source.Reply(_("* Ignore non-opers with a message"));
		if (DConfig.Check(DEFCON_SILENT_OPER_ONLY))
			source.Reply(_("* Silently ignore non-opers"));
		if (DConfig.Check(DEFCON_AKILL_NEW_CLIENTS))
			source.Reply(_("* AKILL any new clients connecting"));
		if (DConfig.Check(DEFCON_NO_NEW_MEMOS))
			source.Reply(_("* No new memos sent"));
	}

 public:
	CommandOSDefcon(Module *creator) : Command(creator, "operserv/defcon", 1, 1)
	{
		this->SetDesc(_("Manipulate the DefCon system"));
		this->SetSyntax(_("[\0021\002|\0022\002|\0023\002|\0024\002|\0025\002]"));
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) anope_override
	{
		const Anope::string &lvl = params[0];

		if (lvl.empty())
		{
			source.Reply(_("Services are now at DEFCON \002%d\002."), DConfig.defaultlevel);
			this->SendLevels(source);
			return;
		}

		int newLevel = 0;
		try
		{
			newLevel = convertTo<int>(lvl);
		}
		catch (const ConvertException &) { }

		if (newLevel < 1 || newLevel > 5)
		{
			this->OnSyntaxError(source, "");
			return;
		}

		DConfig.defaultlevel = newLevel;

		FOREACH_MOD(OnDefconLevel, (newLevel));

		delete timeout;

		if (DConfig.timeout)
			timeout = new DefConTimeout(this->module, 5);

		source.Reply(_("Services are now at DEFCON \002%d\002."), DConfig.defaultlevel);
		this->SendLevels(source);
		Log(LOG_ADMIN, source, this) << "to change defcon level to " << newLevel;

		/* Global notice the user what is happening. Also any Message that
		   the Admin would like to add. Set in config file. */
		if (DConfig.globalondefcon)
		{
			if (DConfig.defaultlevel == 5 && !DConfig.offmessage.empty())
				GlobalService->SendGlobal(NULL, "", DConfig.offmessage);
			else if (DConfig.defaultlevel != 5)
			{
				GlobalService->SendGlobal(NULL, "", Anope::printf(_("The Defcon level is now at: \002%d\002"), DConfig.defaultlevel));
				if (!DConfig.message.empty())
					GlobalService->SendGlobal(NULL, "", DConfig.message);
			}
		}

		/* Run any defcon functions, e.g. FORCE CHAN MODE */
		runDefCon();
		return;
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) anope_override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("The defcon system can be used to implement a pre-defined\n"
				"set of restrictions to services useful during an attempted\n"
				"attack on the network."));
		return true;
	}
};

class OSDefcon : public Module
{
	ServiceReference<SessionService> session_service;
	ServiceReference<XLineManager> akills;
	CommandOSDefcon commandosdefcon;
	PrimitiveExtensibleItem<std::multimap<bool, std::pair<Anope::string, Anope::string> > > defconmodes;

	void ParseModeString()
	{
		int add = -1; /* 1 if adding, 0 if deleting, -1 if neither */
		unsigned char mode;
		ChannelMode *cm;
		ChannelModeParam *cmp;
		Anope::string modes, param;

		spacesepstream ss(DConfig.chanmodes);

		DConfig.DefConModesOn.clear();
		DConfig.DefConModesOff.clear();
		ss.GetToken(modes);

		/* Loop while there are modes to set */
		for (unsigned i = 0, end = modes.length(); i < end; ++i)
		{
			mode = modes[i];

			switch (mode)
			{
				case '+':
					add = 1;
					continue;
				case '-':
					add = 0;
					continue;
				default:
					if (add < 0)
						continue;
			}

			if ((cm = ModeManager::FindChannelModeByChar(mode)))
			{
				if (add)
				{
					DConfig.DefConModesOn.insert(cm->name);
					DConfig.DefConModesOff.erase(cm->name);

					if (cm->type == MODE_PARAM)
					{
						cmp = anope_dynamic_static_cast<ChannelModeParam *>(cm);

						if (!ss.GetToken(param))
						{
							Log(this) << "DefConChanModes mode character '" << mode << "' has no parameter while one is expected";
							continue;
						}

						if (!cmp->IsValid(param))
							continue;

						DConfig.SetDefConParam(cmp->name, param);
					}
				}
				else if (DConfig.DefConModesOn.count(cm->name))
				{
					DConfig.DefConModesOn.erase(cm->name);

					if (cm->type == MODE_PARAM)
						DConfig.UnsetDefConParam(cm->name);
				}
			}
		}

		/* We can't mlock +L if +l is not mlocked as well. */
		if ((cm = ModeManager::FindChannelModeByName("REDIRECT")) && DConfig.DefConModesOn.count(cm->name) && !DConfig.DefConModesOn.count("LIMIT"))
		{
			DConfig.DefConModesOn.erase("REDIRECT");
	
			Log(this) << "DefConChanModes must lock mode +l as well to lock mode +L";
		}
	}

 public:
	OSDefcon(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR), session_service("SessionService", "session"), akills("XLineManager", "xlinemanager/sgline"), commandosdefcon(this), defconmodes(this, "defconmodes")
	{
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		Configuration::Block *block = conf->GetModule(this);
		DefconConfig dconfig;

		dconfig.defaultlevel = block->Get<int>("defaultlevel");
		dconfig.defcons[4] = block->Get<const Anope::string>("level4");
		dconfig.defcons[3] = block->Get<const Anope::string>("level3");
		dconfig.defcons[2] = block->Get<const Anope::string>("level2");
		dconfig.defcons[1] = block->Get<const Anope::string>("level1");
		dconfig.sessionlimit = block->Get<int>("sessionlimit");
		dconfig.akillreason = block->Get<const Anope::string>("akillreason");
		dconfig.akillexpire = block->Get<time_t>("akillexpire");
		dconfig.chanmodes = block->Get<const Anope::string>("chanmodes");
		dconfig.timeout = block->Get<time_t>("timeout");
		dconfig.globalondefcon = block->Get<bool>("globalondefcon");
		dconfig.message = block->Get<const Anope::string>("message");
		dconfig.offmessage = block->Get<const Anope::string>("offmessage");

		Module *session = ModuleManager::FindModule("os_session");
		block = conf->GetModule(session);

		dconfig.max_session_kill = block->Get<int>("maxsessionkill");
		dconfig.session_autokill_expiry = block->Get<time_t>("sessionautokillexpiry");
		dconfig.sle_reason = block->Get<const Anope::string>("sessionlimitexceeded");
		dconfig.sle_detailsloc = block->Get<const Anope::string>("sessionlimitdetailsloc");

		if (dconfig.defaultlevel < 1 || dconfig.defaultlevel > 5)
			throw ConfigException("The value for <defcon:defaultlevel> must be between 1 and 5");
		else if (dconfig.akillexpire <= 0)
			throw ConfigException("The value for <defcon:akillexpire> must be greater than zero!");

		for (unsigned level = 1; level < 5; ++level)
		{
			spacesepstream operations(dconfig.defcons[level]);
			Anope::string operation;
			while (operations.GetToken(operation))
			{
				if (operation.equals_ci("nonewchannels"))
					dconfig.Add(level, DEFCON_NO_NEW_CHANNELS);
				else if (operation.equals_ci("nonewnicks"))
					dconfig.Add(level, DEFCON_NO_NEW_NICKS);
				else if (operation.equals_ci("nomlockchanges"))
					dconfig.Add(level, DEFCON_NO_MLOCK_CHANGE);
				else if (operation.equals_ci("forcechanmodes"))
					dconfig.Add(level, DEFCON_FORCE_CHAN_MODES);
				else if (operation.equals_ci("reducedsessions"))
					dconfig.Add(level, DEFCON_REDUCE_SESSION);
				else if (operation.equals_ci("nonewclients"))
					dconfig.Add(level, DEFCON_NO_NEW_CLIENTS);
				else if (operation.equals_ci("operonly"))
					dconfig.Add(level, DEFCON_OPER_ONLY);
				else if (operation.equals_ci("silentoperonly"))
					dconfig.Add(level, DEFCON_SILENT_OPER_ONLY);
				else if (operation.equals_ci("akillnewclients"))
					dconfig.Add(level, DEFCON_AKILL_NEW_CLIENTS);
				else if (operation.equals_ci("nonewmemos"))
					dconfig.Add(level, DEFCON_NO_NEW_MEMOS);
			}

			if (dconfig.Check(level, DEFCON_REDUCE_SESSION) && dconfig.sessionlimit <= 0)
				throw ConfigException("The value for <defcon:sessionlimit> must be greater than zero!");
			else if (dconfig.Check(level, DEFCON_AKILL_NEW_CLIENTS) && dconfig.akillreason.empty())
				throw ConfigException("The value for <defcon:akillreason> must not be empty!");
			else if (dconfig.Check(level, DEFCON_FORCE_CHAN_MODES) && dconfig.chanmodes.empty())
				throw ConfigException("The value for <defcon:chanmodes> must not be empty!");
		}

		DConfig = dconfig;
		this->ParseModeString();
	}

	EventReturn OnChannelModeSet(Channel *c, MessageSource &source, ChannelMode *mode, const Anope::string &param) anope_override
	{
		if (DConfig.Check(DEFCON_FORCE_CHAN_MODES) && DConfig.DefConModesOff.count(mode->name) && source.GetUser() && !source.GetBot())
		{
			c->RemoveMode(Config->GetClient("OperServ"), mode, param);

			return EVENT_STOP;
		}

		return EVENT_CONTINUE;
	}

	EventReturn OnChannelModeUnset(Channel *c, MessageSource &source, ChannelMode *mode, const Anope::string &) anope_override
	{
		if (DConfig.Check(DEFCON_FORCE_CHAN_MODES) && DConfig.DefConModesOn.count(mode->name) && source.GetUser() && !source.GetBot())
		{
			Anope::string param;

			if (DConfig.GetDefConParam(mode->name, param))
				c->SetMode(Config->GetClient("OperServ"), mode, param);
			else
				c->SetMode(Config->GetClient("OperServ"), mode);

			return EVENT_STOP;

		}

		return EVENT_CONTINUE;
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) anope_override
	{
		if (command->name == "nickserv/register" || command->name == "nickserv/group")
		{
			if (DConfig.Check(DEFCON_NO_NEW_NICKS))
			{
				source.Reply(_("Services are in DefCon mode, please try again later."));
				return EVENT_STOP;
			}
		}
		else if (command->name == "chanserv/mode" && params.size() > 1 && params[1].equals_ci("LOCK"))
		{
			if (DConfig.Check(DEFCON_NO_MLOCK_CHANGE))
			{
				source.Reply(_("Services are in DefCon mode, please try again later."));
				return EVENT_STOP;
			}
		}
		else if (command->name == "chanserv/register")
		{
			if (DConfig.Check(DEFCON_NO_NEW_CHANNELS))
			{
				source.Reply(_("Services are in DefCon mode, please try again later."));
				return EVENT_STOP;
			}
		}
		else if (command->name == "memoserv/send")
		{
			if (DConfig.Check(DEFCON_NO_NEW_MEMOS))
			{
				source.Reply(_("Services are in DefCon mode, please try again later."));
				return EVENT_STOP;
			}
		}

		return EVENT_CONTINUE;
	}

	void OnUserConnect(User *u, bool &exempt) anope_override
	{
		if (exempt || u->Quitting() || !u->server->IsSynced() || u->server->IsULined())
			return;

		BotInfo *OperServ = Config->GetClient("OperServ");
		if (DConfig.Check(DEFCON_AKILL_NEW_CLIENTS) && akills)
		{
			Log(OperServ, "operserv/defcon") << "DEFCON: adding akill for *@" << u->host;
			XLine x("*@" + u->host, OperServ ? OperServ->nick : "defcon", Anope::CurTime + DConfig.akillexpire, DConfig.akillreason, XLineManager::GenerateUID());
			akills->Send(NULL, &x);
		}
		if (DConfig.Check(DEFCON_NO_NEW_CLIENTS) || DConfig.Check(DEFCON_AKILL_NEW_CLIENTS))
		{
			u->Kill(OperServ ? OperServ->nick : "", DConfig.akillreason);
			return;
		}

		if (DConfig.Check(DEFCON_NO_NEW_CLIENTS) || DConfig.Check(DEFCON_AKILL_NEW_CLIENTS))
		{
			u->Kill(OperServ ? OperServ->nick : "", DConfig.akillreason);
			return;
		}

		if (DConfig.sessionlimit <= 0 || !session_service)
			return;

		Session *session = session_service->FindSession(u->ip);
		Exception *exception = session_service->FindException(u);

		if (DConfig.Check(DEFCON_REDUCE_SESSION) && !exception)
		{
			if (session && session->count > static_cast<unsigned>(DConfig.sessionlimit))
			{
				if (!DConfig.sle_reason.empty())
				{
					Anope::string message = DConfig.sle_reason.replace_all_cs("%IP%", u->ip);
					u->SendMessage(OperServ, message);
				}
				if (!DConfig.sle_detailsloc.empty())
					u->SendMessage(OperServ, DConfig.sle_detailsloc);

				++session->hits;
				if (akills && DConfig.max_session_kill && session->hits >= DConfig.max_session_kill)
				{
					XLine x("*@" + u->host, OperServ ? OperServ->nick : "", Anope::CurTime + DConfig.session_autokill_expiry, "Defcon session limit exceeded", XLineManager::GenerateUID());
					akills->Send(NULL, &x);
					Log(OperServ, "akill/defcon") << "[DEFCON] Added a temporary AKILL for \002*@" << u->host << "\002 due to excessive connections";
				}
				else
				{
					u->Kill(OperServ ? OperServ->nick : "", "Defcon session limit exceeded");
				}
			}
		}
	}

	void OnChannelModeAdd(ChannelMode *cm) anope_override
	{
		if (DConfig.chanmodes.find(cm->mchar) != Anope::string::npos)
			this->ParseModeString();
	}

	void OnChannelSync(Channel *c) anope_override
	{
		if (DConfig.Check(DEFCON_FORCE_CHAN_MODES))
			c->SetModes(Config->GetClient("OperServ"), false, "%s", DConfig.chanmodes.c_str());
	}
};

const ModeLock* getMlock(Channel *chan, ChannelMode *mode)
{
	ModeLocks *ml = chan->ci->GetExt<ModeLocks>("modelocks");
	const ModeLock* lock = ml ? ml->GetMLock(mode->name) : NULL;
	return lock;
}

bool mlockConflict(Channel *chan, bool adding, ChannelMode *mode, const Anope::string& param)
{
	if (DConfig.Check(DEFCON_NO_MLOCK_CHANGE) || !chan->ci)
		return false;

	const ModeLock *lock = getMlock(chan, mode);
	return (lock && (lock->set != adding || lock->param != param));
}

// Parse modeline, remove modes that are mlocked for the channel,
// and return the new modeline
// Saves the data needed to restore original modes to the channel
// returns "" if it encounters an unrecognized mode
Anope::string saveDefConModes(const Anope::string &modeline, Channel *chan)
{
	typedef std::multimap<Anope::string, Anope::string> ModeList;
	typedef std::multimap<bool, std::pair<Anope::string, Anope::string> > StatusMap;

	const size_t delim = modeline.find(' ');
	const Anope::string modes = modeline.substr(0, delim);
	std::vector<Anope::string> params;

	if (delim != Anope::string::npos)
	{
		spacesepstream ss(modeline.substr(delim + 1));
		for (Anope::string param; ss.GetToken(param);)
			params.push_back(param);
	}

	Anope::string ret_modes;
	Anope::string ret_params;

	StatusMap ms;

	const size_t params_size = params.size();
	bool adding = false;
	size_t param_n = 0;
	for (Anope::string::const_iterator mchar = modes.begin(); mchar != modes.end(); ++mchar)
	{
		if (*mchar == '+' || *mchar == '-')
		{
			adding = *mchar == '+';
			ret_modes += adding ? "+" : "-";
			continue;
		}

		ChannelMode* mode = ModeManager::FindChannelModeByChar(*mchar);
		if (!mode)
			continue;

		if (getMlock(chan, mode))
		{
			if (mode->type != MODE_REGULAR)
				++param_n;
			continue;
		}

		if (param_n == params_size && mode->type != MODE_REGULAR)
			return "";

		if (mode->type == MODE_REGULAR || mode->type == MODE_PARAM)
		{
			const std::pair<ModeList::iterator, ModeList::iterator> range = chan->GetModeList(mode->name);
			for (ModeList::iterator mit = range.first; mit != range.second; ++mit)
			{
				ms.insert(std::make_pair(true, std::make_pair(mode->mchar, mit->second)));
				if (mode->type == MODE_PARAM)
					++param_n;
			}

			if (range.first == range.second)
				ms.insert(std::make_pair(false, std::make_pair(mode->mchar, mode->type == MODE_PARAM ? params[++param_n] : "")));
		}
		else if (mode->type == MODE_LIST)
		{
			const Anope::string& param = params[param_n++];
			if (!chan->HasMode(mode->name, param))
				ms.insert(std::make_pair(false, std::make_pair(mode->mchar, param)));
		}
		else if (mode->type == MODE_STATUS)
		{
			const Anope::string& param = params[param_n++];
			User *u = User::Find(param, true);
			if (u && ((adding && !chan->HasUserStatus(u, mode->name)) || (!adding && chan->HasUserStatus(u, mode->name))))
				ms.insert(std::make_pair(!adding, std::make_pair(mode->mchar, param)));
		}

		ret_modes += mode->mchar;
		if (mode->type != MODE_REGULAR)
			ret_params += " " + params[param_n - 1];
	}

	chan->Extend<StatusMap>("defconmodes", ms);

	return ret_modes + ret_params;
}

// Restore the pre-defcon modes on a channel
// Returns the modestring, or "" if it encounters an unrecognized mode
Anope::string loadDefConModes(Channel *chan)
{
	typedef std::multimap<bool, std::pair<Anope::string, Anope::string> > StatusMap;

	StatusMap *ms = chan->GetExt<StatusMap>("defconmodes");
	if (!ms)
		return "";

	Anope::string modes;
	Anope::string params;
	std::pair<StatusMap::iterator, StatusMap::iterator > range;

	for (int i = false; i < 2; ++i)
	{
		modes += i == 0 ? "-" : "+";
		range =  ms->equal_range(i);

		for (StatusMap::iterator it = range.first; it != range.second; ++it)
		{
			ChannelMode *mode = ModeManager::FindChannelModeByChar(it->second.first[0]);
			if (!mode)
			{
				chan->Shrink<StatusMap>("defconmodes");
				return "";
			}

			if (mlockConflict(chan, it->first, mode, it->second.second))
				continue;

			modes += it->second.first;
			params += it->second.second.empty() ? "" : " " + it->second.second;
		}
	}

	chan->Shrink<StatusMap>("defconmodes");
	return modes + params;
}

static void runDefCon()
{
	BotInfo *OperServ = Config->GetClient("OperServ");

	if (DConfig.chanmodes.empty())
		return;

	if (DConfig.chanmodes[0] != '+' && DConfig.chanmodes[0] != '-')
		return;

	// Return if we're already active and going up a level,
	// or not active and going down a level
	bool fcmcheck = DConfig.Check(DEFCON_FORCE_CHAN_MODES);
	if ((!DefConModesSet && !fcmcheck) || (DefConModesSet && fcmcheck))
		return;

	// If we're removing, invert
	const Anope::string &setmodes = fcmcheck
		? DConfig.chanmodes
		: defconReverseModes(DConfig.chanmodes);

	Log(OperServ, "operserv/defcon") << "DEFCON: setting " << setmodes << " on all channels";
	for (channel_map::const_iterator it = ChannelList.begin(), it_end = ChannelList.end(); it != it_end; ++it)
	{
		// If we're enabling DefCon, save the current mode state
		if (fcmcheck)
			it->second->SetModes(OperServ, false, "%s", saveDefConModes(setmodes, it->second).c_str());
		else
			it->second->SetModes(OperServ, false, "%s", loadDefConModes(it->second).c_str());
	}

	DefConModesSet = fcmcheck;
}

static Anope::string defconReverseModes(const Anope::string &modes)
{
	if (modes.empty())
		return "";
	Anope::string newmodes;
	for (unsigned i = 0, end = modes.length(); i < end; ++i)
	{
		if (modes[i] == '+')
			newmodes += '-';
		else if (modes[i] == '-')
			newmodes += '+';
		else
			newmodes += modes[i];
	}
	return newmodes;
}

MODULE_INIT(OSDefcon)
