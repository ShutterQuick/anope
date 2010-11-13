/* OperServ core functions
 *
 * (C) 2003-2010 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 */

/*************************************************************************/

#include "module.h"

class CommandOSNOOP : public Command
{
 public:
	CommandOSNOOP() : Command("NOOP", 2, 2, "operserv/noop")
	{
	}

	CommandReturn Execute(User *u, const std::vector<Anope::string> &params)
	{
		Anope::string cmd = params[0];
		Anope::string server = params[1];

		if (cmd.equals_ci("SET"))
		{
			Anope::string reason;

			/* Remove the O:lines */
			ircdproto->SendSVSNOOP(server, 1);

			reason = "NOOP command used by " + u->nick;
			if (Config->WallOSNoOp)
				ircdproto->SendGlobops(OperServ, "\2%s\2 used NOOP on \2%s\2", u->nick.c_str(), server.c_str());
			u->SendMessage(OperServ, OPER_NOOP_SET, server.c_str());

			/* Kill all the IRCops of the server */
			for (patricia_tree<User>::const_iterator it = UserListByNick.begin(), it_end = UserListByNick.end(); it != it_end; ++it)
			{
				User *u2 = *it;
				++it;

				if (u2 && is_oper(u2) && Anope::Match(u2->server->GetName(), server, true))
					kill_user(Config->s_OperServ, u2->nick, reason);
			}
		}
		else if (cmd.equals_ci("REVOKE"))
		{
			ircdproto->SendSVSNOOP(server, 0);
			u->SendMessage(OperServ, OPER_NOOP_REVOKE, server.c_str());
		}
		else
			this->OnSyntaxError(u, "");
		return MOD_CONT;
	}

	bool OnHelp(User *u, const Anope::string &subcommand)
	{
		u->SendMessage(OperServ, OPER_HELP_NOOP);
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &subcommand)
	{
		SyntaxError(OperServ, u, "NOOP", OPER_NOOP_SYNTAX);
	}

	void OnServHelp(User *u)
	{
		u->SendMessage(OperServ, OPER_HELP_CMD_NOOP);
	}
};

class OSNOOP : public Module
{
	CommandOSNOOP commandosnoop;

 public:
	OSNOOP(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetType(CORE);

		this->AddCommand(OperServ, &commandosnoop);
	}
};

MODULE_INIT(OSNOOP)