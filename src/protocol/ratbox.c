/* Ratbox IRCD functions
 *
 * (C) 2003-2008 Anope Team
 * Contact us at info@anope.org
 *
 * Please read COPYING and README for furhter details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 *
 *
 */

#include "services.h"
#include "pseudo.h"
#include "ratbox.h"

IRCDVar myIrcd[] = {
    {"Ratbox 2.0+",             /* ircd name */
     "+oi",                     /* nickserv mode */
     "+oi",                     /* chanserv mode */
     "+oi",                     /* memoserv mode */
     "+oi",                     /* hostserv mode */
     "+oai",                    /* operserv mode */
     "+oi",                     /* botserv mode  */
     "+oi",                     /* helpserv mode */
     "+oi",                     /* Dev/Null mode */
     "+oi",                     /* Global mode   */
     "+oi",                     /* nickserv alias mode */
     "+oi",                     /* chanserv alias mode */
     "+oi",                     /* memoserv alias mode */
     "+oi",                     /* hostserv alias mode */
     "+oai",                    /* operserv alias mode */
     "+oi",                     /* botserv alias mode  */
     "+oi",                     /* helpserv alias mode */
     "+oi",                     /* Dev/Null alias mode */
     "+oi",                     /* Global alias mode   */
     "+oi",                     /* Used by BotServ Bots */
     2,                         /* Chan Max Symbols     */
     "-acilmnpst",              /* Modes to Remove */
     "+o",                      /* Channel Umode used by Botserv bots */
     0,                         /* SVSNICK */
     0,                         /* Vhost  */
     0,                         /* Has Owner */
     NULL,                      /* Mode to set for an owner */
     NULL,                      /* Mode to unset for an owner */
     NULL,                      /* Mode to set for chan admin */
     NULL,                      /* Mode to unset for chan admin */
     NULL,                      /* Mode On Reg          */
     NULL,                      /* Mode on ID for Roots */
     NULL,                      /* Mode on ID for Admins */
     NULL,                      /* Mode on ID for Opers */
     NULL,                      /* Mode on UnReg        */
     NULL,                      /* Mode on Nick Change  */
     1,                         /* Supports SGlines     */
     1,                         /* Supports SQlines     */
     0,                         /* Supports SZlines     */
     0,                         /* Supports Halfop +h   */
     3,                         /* Number of server args */
     1,                         /* Join 2 Set           */
     1,                         /* Join 2 Message       */
     1,                         /* Has exceptions +e    */
     0,                         /* TS Topic Forward     */
     0,                         /* TS Topci Backward    */
     0,                         /* Protected Umode      */
     0,                         /* Has Admin            */
     1,                         /* Chan SQlines         */
     0,                         /* Quit on Kill         */
     0,                         /* SVSMODE unban        */
     0,                         /* Has Protect          */
     0,                         /* Reverse              */
     0,                         /* Chan Reg             */
     0,                         /* Channel Mode         */
     0,                         /* vidents              */
     0,                         /* svshold              */
     0,                         /* time stamp on mode   */
     0,                         /* NICKIP               */
     0,                         /* UMODE                */
     0,                         /* O:LINE               */
     0,                         /* VHOST ON NICK        */
     0,                         /* Change RealName      */
     CMODE_p,                   /* No Knock             */
     0,                         /* Admin Only           */
     DEFAULT_MLOCK,             /* Default MLOCK        */
     0,                         /* Vhost Mode           */
     0,                         /* +f                   */
     0,                         /* +L                   */
     0,                         /* +f Mode                          */
     0,                         /* +L Mode                              */
     0,                         /* On nick change check if they could be identified */
     0,                         /* No Knock requires +i */
     NULL,                      /* CAPAB Chan Modes             */
     0,                         /* We support TOKENS */
     1,                         /* TOKENS are CASE inSensitive */
     0,                         /* TIME STAMPS are BASE64 */
     1,                         /* +I support */
     0,                         /* SJOIN ban char */
     0,                         /* SJOIN except char */
     0,                         /* SJOIN invite char */
     0,                         /* Can remove User Channel Modes with SVSMODE */
     0,                         /* Sglines are not enforced until user reconnects */
     NULL,                      /* vhost char */
     1,                         /* ts6 */
     0,                         /* support helper umode */
     0,                         /* p10 */
     NULL,                      /* character set */
     0,                         /* reports sync state */
     0,                         /* CIDR channelbans */
     "$$",                      /* TLD Prefix for Global */
     }
    ,
    {NULL}
};

IRCDCAPAB myIrcdcap[] = {
    {
     0,                         /* NOQUIT       */
     0,                         /* TSMODE       */
     0,                         /* UNCONNECT    */
     0,                         /* NICKIP       */
     0,                         /* SJOIN        */
     CAPAB_ZIP,                 /* ZIP          */
     0,                         /* BURST        */
     CAPAB_TS5,                 /* TS5          */
     0,                         /* TS3          */
     0,                         /* DKEY         */
     0,                         /* PT4          */
     0,                         /* SCS          */
     CAPAB_QS,                  /* QS           */
     CAPAB_UID,                 /* UID          */
     CAPAB_KNOCK,               /* KNOCK        */
     0,                         /* CLIENT       */
     0,                         /* IPV6         */
     0,                         /* SSJ5         */
     0,                         /* SN2          */
     0,                         /* TOKEN        */
     0,                         /* VHOST        */
     0,                         /* SSJ3         */
     0,                         /* NICK2        */
     0,                         /* UMODE2       */
     0,                         /* VL           */
     0,                         /* TLKEXT       */
     0,                         /* DODKEY       */
     0,                         /* DOZIP        */
     0, 0, 0}
};

void ratbox_set_umode(User * user, int ac, const char **av)
{
    int add = 1;                /* 1 if adding modes, 0 if deleting */
    const char *modes = av[0];

    ac--;

    if (debug)
        alog("debug: Changing mode for %s to %s", user->nick, modes);

    while (*modes) {

        /* This looks better, much better than "add ? (do_add) : (do_remove)".
         * At least this is readable without paying much attention :) -GD
         */
        if (add)
            user->mode |= umodes[(int) *modes];
        else
            user->mode &= ~umodes[(int) *modes];

        switch (*modes++) {
        case '+':
            add = 1;
            break;
        case '-':
            add = 0;
            break;
        case 'o':
            if (add) {
                opcnt++;

                if (WallOper)
                    anope_cmd_global(s_OperServ,
                                     "\2%s\2 is now an IRC operator.",
                                     user->nick);
                display_news(user, NEWS_OPER);

            } else {
                opcnt--;
            }
            break;
        }
    }
}

unsigned long umodes[128] = {
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused, Unused, Horzontal Tab */
    0, 0, 0,                    /* Line Feed, Unused, Unused */
    0, 0, 0,                    /* Carriage Return, Unused, Unused */
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused */
    0, 0, 0,                    /* Unused, Unused, Space */
    0, 0, 0,                    /* ! " #  */
    0, 0, 0,                    /* $ % &  */
    0, 0, 0,                    /* ! ( )  */
    0, 0, 0,                    /* * + ,  */
    0, 0, 0,                    /* - . /  */
    0, 0,                       /* 0 1 */
    0, 0,                       /* 2 3 */
    0, 0,                       /* 4 5 */
    0, 0,                       /* 6 7 */
    0, 0,                       /* 8 9 */
    0, 0,                       /* : ; */
    0, 0, 0,                    /* < = > */
    0, 0,                       /* ? @ */
    0, 0, 0,                    /* A B C */
    0, 0, 0,                    /* D E F */
    0, 0, 0,                    /* G H I */
    0, 0, 0,                    /* J K L */
    0, 0, 0,                    /* M N O */
    0, 0, 0,                    /* P Q R */
    0, 0, 0,                    /* S T U */
    0, 0, 0,                    /* V W X */
    0,                          /* Y */
    0,                          /* Z */
    0, 0, 0,                    /* [ \ ] */
    0, 0, 0,                    /* ^ _ ` */
    UMODE_a, UMODE_b, 0,        /* a b c */
    UMODE_d, 0, 0,              /* d e f */
    UMODE_g, 0, UMODE_i,        /* g h i */
    0, 0, UMODE_l,              /* j k l */
    0, UMODE_n, UMODE_o,  /* m n o */
    0, 0, 0,                    /* p q r */
    0, 0, UMODE_u,              /* s t u */
    0, UMODE_w, UMODE_x,        /* v w x */
    0,                          /* y */
    0,                          /* z */
    0, 0, 0,                    /* { | } */
    0, 0                        /* ~ � */
};


char myCsmodes[128] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    0,
    0,
    0, 0, 0,
    0,
    0, 0, 0, 0,
    0,

    'v', 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

CMMode myCmmodes[128] = {
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL},     /* BCD */
    {NULL}, {NULL}, {NULL},     /* EFG */
    {NULL},                     /* H */
    {add_invite, del_invite},
    {NULL},                     /* J */
    {NULL}, {NULL}, {NULL},     /* KLM */
    {NULL}, {NULL}, {NULL},     /* NOP */
    {NULL}, {NULL}, {NULL},     /* QRS */
    {NULL}, {NULL}, {NULL},     /* TUV */
    {NULL}, {NULL}, {NULL},     /* WXY */
    {NULL},                     /* Z */
    {NULL}, {NULL},             /* (char 91 - 92) */
    {NULL}, {NULL}, {NULL},     /* (char 93 - 95) */
    {NULL},                     /* ` (char 96) */
    {NULL},                     /* a (char 97) */
    {add_ban, del_ban},
    {NULL},
    {NULL},
    {add_exception, del_exception},
    {NULL},
    {NULL},
    {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL},
    {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}, {NULL}
};


CBMode myCbmodes[128] = {
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0},
    {0},                        /* A */
    {0},                        /* B */
    {0},                        /* C */
    {0},                        /* D */
    {0},                        /* E */
    {0},                        /* F */
    {0},                        /* G */
    {0},                        /* H */
    {0},                        /* I */
    {0},                        /* J */
    {0},                        /* K */
    {0},                        /* L */
    {0},                        /* M */
    {0},                        /* N */
    {0},                        /* O */
    {0},                        /* P */
    {0},                        /* Q */
    {0},                        /* R */
    {0},                        /* S */
    {0},                        /* T */
    {0},                        /* U */
    {0},                        /* V */
    {0},                        /* W */
    {0},                        /* X */
    {0},                        /* Y */
    {0},                        /* Z */
    {0}, {0}, {0}, {0}, {0}, {0},
    {0},
    {0},                        /* b */
    {0},                        /* c */
    {0},                        /* d */
    {0},                        /* e */
    {0},                        /* f */
    {0},                        /* g */
    {0},                        /* h */
    {CMODE_i, 0, NULL, NULL},
    {0},                        /* j */
    {CMODE_k, 0, chan_set_key, cs_set_key},
    {CMODE_l, CBM_MINUS_NO_ARG, set_limit, cs_set_limit},
    {CMODE_m, 0, NULL, NULL},
    {CMODE_n, 0, NULL, NULL},
    {0},                        /* o */
    {CMODE_p, 0, NULL, NULL},
    {0},                        /* q */
    {0},
    {CMODE_s, 0, NULL, NULL},
    {CMODE_t, 0, NULL, NULL},
    {0},
    {0},                        /* v */
    {0},                        /* w */
    {0},                        /* x */
    {0},                        /* y */
    {0},                        /* z */
    {0}, {0}, {0}, {0}
};

CBModeInfo myCbmodeinfos[] = {
    {'i', CMODE_i, 0, NULL, NULL},
    {'k', CMODE_k, 0, get_key, cs_get_key},
    {'l', CMODE_l, CBM_MINUS_NO_ARG, get_limit, cs_get_limit},
    {'m', CMODE_m, 0, NULL, NULL},
    {'n', CMODE_n, 0, NULL, NULL},
    {'p', CMODE_p, 0, NULL, NULL},
    {'s', CMODE_s, 0, NULL, NULL},
    {'t', CMODE_t, 0, NULL, NULL},
    {0}
};


CUMode myCumodes[128] = {
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},

    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},

    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
    {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},

    {0},

    {0},                        /* a */
    {0},                        /* b */
    {0},                        /* c */
    {0},                        /* d */
    {0},                        /* e */
    {0},                        /* f */
    {0},                        /* g */
    {0},
    {0},                        /* i */
    {0},                        /* j */
    {0},                        /* k */
    {0},                        /* l */
    {0},                        /* m */
    {0},                        /* n */
    {CUS_OP, CUF_PROTECT_BOTSERV, check_valid_op},
    {0},                        /* p */
    {0},                        /* q */
    {0},                        /* r */
    {0},                        /* s */
    {0},                        /* t */
    {0},                        /* u */
    {CUS_VOICE, 0, NULL},
    {0},                        /* w */
    {0},                        /* x */
    {0},                        /* y */
    {0},                        /* z */
    {0}, {0}, {0}, {0}, {0}
};



void RatboxProto::cmd_message(const char *source, const char *dest, const char *buf)
{
	if (!buf) return;
	if (NSDefFlags & NI_MSG) cmd_privmsg(source, dest, buf);
	else cmd_notice(source, dest, buf);
}

void RatboxProto::cmd_notice(const char *source, const char *dest, const char *msg)
{
	Uid *ud = find_uid(source);
	User *u = finduser(dest);
	send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "NOTICE %s :%s", UseTS6 ? (u ? u->uid : dest) : dest, msg);
}

void RatboxProto::cmd_privmsg(const char *source, const char *dest, const char *buf)
{
	if (!buf) return;
	Uid *ud = find_uid(source), *ud2 = find_uid(dest);
	send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "PRIVMSG %s :%s", UseTS6 ? (ud2 ? ud2->uid : dest) : dest, buf);
}

void ratbox_cmd_global(const char *source, const char *buf)
{
    Uid *u;

    if (!buf) {
        return;
    }

    if (source) {
        u = find_uid(source);
        if (u) {
            send_cmd((UseTS6 ? u->uid : source), "OPERWALL :%s", buf);
        } else {
            send_cmd((UseTS6 ? TS6SID : ServerName), "OPERWALL :%s", buf);
        }
    } else {
        send_cmd((UseTS6 ? TS6SID : ServerName), "OPERWALL :%s", buf);
    }
}

int anope_event_sjoin(const char *source, int ac, const char **av)
{
    do_sjoin(source, ac, av);
    return MOD_CONT;
}

/*
   Non TS6

   av[0] = nick
   av[1] = hop
   av[2] = ts
   av[3] = modes
   av[4] = user
   av[5] = host
   av[6] = server
   av[7] = info

   TS6
   av[0] = nick
   av[1] = hop
   av[2] = ts
   av[3] = modes
   av[4] = user
   av[5] = host
   av[6] = IP
   av[7] = UID
   av[8] = info

*/
int anope_event_nick(const char *source, int ac, const char **av)
{
    Server *s;
    User *user;

    if (UseTS6 && ac == 9) {
        s = findserver_uid(servlist, source);
        /* Source is always the server */
        user = do_nick("", av[0], av[4], av[5], s->name, av[8],
                       strtoul(av[2], NULL, 10), 0, 0, "*", av[7]);
        if (user) {
            anope_set_umode(user, 1, &av[3]);
        }
    } else {
        if (ac != 2) {
            user = do_nick(source, av[0], av[4], av[5], av[6], av[7],
                           strtoul(av[2], NULL, 10), 0, 0, "*", NULL);
            if (user)
                anope_set_umode(user, 1, &av[3]);
        } else {
            do_nick(source, av[0], NULL, NULL, NULL, NULL,
                    strtoul(av[1], NULL, 10), 0, 0, NULL, NULL);
        }
    }
    return MOD_CONT;
}

int anope_event_topic(const char *source, int ac, const char **av)
{
    User *u;

    if (ac == 4) {
        do_topic(source, ac, av);
    } else {
        Channel *c = findchan(av[0]);
        time_t topic_time = time(NULL);

        if (!c) {
            if (debug) {
                alog("debug: TOPIC %s for nonexistent channel %s",
                     merge_args(ac - 1, av + 1), av[0]);
            }
            return MOD_CONT;
        }

        if (check_topiclock(c, topic_time))
            return MOD_CONT;

        if (c->topic) {
            free(c->topic);
            c->topic = NULL;
        }
        if (ac > 1 && *av[1])
            c->topic = sstrdup(av[1]);

        if (UseTS6) {
            u = find_byuid(source);
            if (u) {
                strscpy(c->topic_setter, u->nick, sizeof(c->topic_setter));
            } else {
                strscpy(c->topic_setter, source, sizeof(c->topic_setter));
            }
        } else {
            strscpy(c->topic_setter, source, sizeof(c->topic_setter));
        }
        c->topic_time = topic_time;

        record_topic(av[0]);

		if (ac > 1 && *av[1])
		    send_event(EVENT_TOPIC_UPDATED, 2, av[0], av[1]);
		else
		    send_event(EVENT_TOPIC_UPDATED, 2, av[0], "");
    }
    return MOD_CONT;
}

int anope_event_tburst(const char *source, int ac, const char **av)
{
    char *setter;
    Channel *c;
    time_t topic_time;

    if (ac != 4) {
        return MOD_CONT;
    }

    setter = myStrGetToken(av[2], '!', 0);

    c = findchan(av[0]);
    topic_time = strtol(av[1], NULL, 10);

    if (!c) {
        if (debug) {
            alog("debug: TOPIC %s for nonexistent channel %s",
                 merge_args(ac - 1, av + 1), av[0]);
        }
        if (setter)
            free(setter);
        return MOD_CONT;
    }

    if (check_topiclock(c, topic_time)) {
        if (setter)
            free(setter);
        return MOD_CONT;
    }

    if (c->topic) {
        free(c->topic);
        c->topic = NULL;
    }
    if (ac > 1 && *av[3])
        c->topic = sstrdup(av[3]);

    strscpy(c->topic_setter, setter, sizeof(c->topic_setter));
    c->topic_time = topic_time;

    record_topic(av[0]);
    if (setter)
        free(setter);
    return MOD_CONT;
}

int anope_event_436(const char *source, int ac, const char **av)
{
    if (ac < 1)
        return MOD_CONT;

    m_nickcoll(av[0]);
    return MOD_CONT;
}


/* *INDENT-OFF* */
void moduleAddIRCDMsgs(void)
{
    Message *m;

    updateProtectDetails("PROTECT","PROTECTME","protect","deprotect","AUTOPROTECT","+","-");

    if (UseTS6) {
        TS6SID = sstrdup(Numeric);
        UseTSMODE = 1;  /* TMODE */
    }

    m = createMessage("401",       anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("402",       anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("436",       anope_event_436); addCoreMessage(IRCD,m);
    m = createMessage("AWAY",      anope_event_away); addCoreMessage(IRCD,m);
    m = createMessage("INVITE",    anope_event_invite); addCoreMessage(IRCD,m);
    m = createMessage("JOIN",      anope_event_join); addCoreMessage(IRCD,m);
    m = createMessage("KICK",      anope_event_kick); addCoreMessage(IRCD,m);
    m = createMessage("KILL",      anope_event_kill); addCoreMessage(IRCD,m);
    m = createMessage("MODE",      anope_event_mode); addCoreMessage(IRCD,m);
    m = createMessage("TMODE",     anope_event_tmode); addCoreMessage(IRCD,m);
    m = createMessage("MOTD",      anope_event_motd); addCoreMessage(IRCD,m);
    m = createMessage("NICK",      anope_event_nick); addCoreMessage(IRCD,m);
    m = createMessage("BMASK",     anope_event_bmask); addCoreMessage(IRCD,m);
    m = createMessage("UID",       anope_event_nick); addCoreMessage(IRCD,m);
    m = createMessage("NOTICE",    anope_event_notice); addCoreMessage(IRCD,m);
    m = createMessage("PART",      anope_event_part); addCoreMessage(IRCD,m);
    m = createMessage("PASS",      anope_event_pass); addCoreMessage(IRCD,m);
    m = createMessage("PING",      anope_event_ping); addCoreMessage(IRCD,m);
    m = createMessage("PRIVMSG",   anope_event_privmsg); addCoreMessage(IRCD,m);
    m = createMessage("QUIT",      anope_event_quit); addCoreMessage(IRCD,m);
    m = createMessage("SERVER",    anope_event_server); addCoreMessage(IRCD,m);
    m = createMessage("SQUIT",     anope_event_squit); addCoreMessage(IRCD,m);
    m = createMessage("TOPIC",     anope_event_topic); addCoreMessage(IRCD,m);
    m = createMessage("TB",        anope_event_tburst); addCoreMessage(IRCD,m);
    m = createMessage("USER",      anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("WALLOPS",   anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("WHOIS",     anope_event_whois); addCoreMessage(IRCD,m);
    m = createMessage("SVSMODE",   anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("SVSNICK",   anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("CAPAB",     anope_event_capab); addCoreMessage(IRCD,m);
    m = createMessage("SJOIN",     anope_event_sjoin); addCoreMessage(IRCD,m);
    m = createMessage("SVINFO",    anope_event_svinfo); addCoreMessage(IRCD,m);
    m = createMessage("ADMIN",     anope_event_admin); addCoreMessage(IRCD,m);
    m = createMessage("ERROR",     anope_event_error); addCoreMessage(IRCD,m);
    m = createMessage("421",       anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("ENCAP",     anope_event_null); addCoreMessage(IRCD,m);
    m = createMessage("SID",       anope_event_sid); addCoreMessage(IRCD,m);
}

/* *INDENT-ON* */


void ratbox_cmd_sqline(const char *mask, const char *reason)
{
    Uid *ud;

    ud = find_uid(s_OperServ);
    send_cmd((UseTS6 ? (ud ? ud->uid : s_OperServ) : s_OperServ),
             "RESV * %s :%s", mask, reason);
}

void ratbox_cmd_unsgline(const char *mask)
{
    Uid *ud;

    ud = find_uid(s_OperServ);
    send_cmd((UseTS6 ? (ud ? ud->uid : s_OperServ) : s_OperServ),
             "UNXLINE * %s", mask);
}

void ratbox_cmd_unszline(const char *mask)
{
    /* Does not support */
}

void ratbox_cmd_szline(const char *mask, const char *reason, const char *whom)
{
    /* Does not support */
}

void ratbox_cmd_svsadmin(const char *server, int set)
{
}

void ratbox_cmd_sgline(const char *mask, const char *reason)
{
    Uid *ud;

    ud = find_uid(s_OperServ);
    send_cmd((UseTS6 ? (ud ? ud->uid : s_OperServ) : s_OperServ),
             "XLINE * %s 0 :%s", mask, reason);
}

void RatboxProto::cmd_remove_akill(const char *user, const char *host)
{
	Uid *ud = find_uid(s_OperServ);
	send_cmd(UseTS6 ? (ud ? ud->uid : s_OperServ) : s_OperServ, "UNKLINE * %s %s", user, host);
}

void RatboxProto::cmd_topic(const char *whosets, const char *chan, const char *whosetit, const char *topic, time_t when)
{
	Uid *ud = find_uid(whosets);
	send_cmd(UseTS6 ? (ud ? ud->uid : whosets) : whosets, "TOPIC %s :%s", chan, topic);
}

void ratbox_cmd_vhost_on(const char *nick, const char *vIdent, const char *vhost)
{
    /* not supported  */
}

void RatboxProto::cmd_unsqline(const char *user)
{
	Uid *ud = find_uid(s_OperServ);
	send_cmd(UseTS6 ? (ud ? ud->uid : s_OperServ) : s_OperServ, "UNRESV * %s", user);
}

void RatboxProto::cmd_join(const char *user, const char *channel, time_t chantime)
{
	Uid *ud = find_uid(user);
	send_cmd(NULL, "SJOIN %ld %s + :%s", static_cast<long>(chantime), channel, UseTS6 ? (ud ? ud->uid : user) : user);
}

/*
oper:		the nick of the oper performing the kline
target.server:	the server(s) this kline is destined for
duration:	the duration if a tkline, 0 if permanent.
user:		the 'user' portion of the kline
host:		the 'host' portion of the kline
reason:		the reason for the kline.
*/

void RatboxProto::cmd_akill(const char *user, const char *host, const char *who, time_t when, time_t expires, const char *reason)
{
	Uid *ud = find_uid(s_OperServ);
	send_cmd(UseTS6 ? (ud ? ud->uid : s_OperServ) : s_OperServ, "KLINE * %ld %s %s :%s", static_cast<long>(expires - time(NULL)), user, host, reason);
}

void RatboxProto::cmd_svskill(const char *source, const char *user, const char *buf)
{
	if (!source || !user || !buf) return;
	Uid *ud = find_uid(source), *ud2 = find_uid(user);
	send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "KILL %s :%s", UseTS6 ? (ud2 ? ud2->uid : user) : user, buf);
}

void RatboxProto::cmd_svsmode(User *u, int ac, const char **av)
{
	send_cmd(UseTS6 ? TS6SID : ServerName, "SVSMODE %s %s", u->nick, av[0]);
}

/*
 * SVINFO
 *      parv[0] = sender prefix
 *      parv[1] = TS_CURRENT for the server
 *      parv[2] = TS_MIN for the server
 *      parv[3] = server is standalone or connected to non-TS only
 *      parv[4] = server's idea of UTC time
 */
void ratbox_cmd_svinfo()
{
    send_cmd(NULL, "SVINFO 6 3 0 :%ld", (long int) time(NULL));
}

void ratbox_cmd_svsinfo()
{

}

/* CAPAB */
/*
  QS     - Can handle quit storm removal
  EX     - Can do channel +e exemptions
  CHW    - Can do channel wall @#
  LL     - Can do lazy links
  IE     - Can do invite exceptions
  EOB    - Can do EOB message
  KLN    - Can do KLINE message
  GLN    - Can do GLINE message
  HUB    - This server is a HUB
  UID    - Can do UIDs
  ZIP    - Can do ZIPlinks
  ENC    - Can do ENCrypted links
  KNOCK  -  supports KNOCK
  TBURST - supports TBURST
  PARA	 - supports invite broadcasting for +p
  ENCAP	 - ?
*/
void ratbox_cmd_capab()
{
    send_cmd(NULL,
             "CAPAB :QS EX CHW IE KLN GLN KNOCK TB UNKLN CLUSTER ENCAP");
}

/* PASS */
void ratbox_cmd_pass(const char *pass)
{
    if (UseTS6) {
        send_cmd(NULL, "PASS %s TS 6 :%s", pass, TS6SID);
    } else {
        send_cmd(NULL, "PASS %s :TS", pass);
    }
}

/* SERVER name hop descript */
void ratbox_cmd_server(const char *servname, int hop, const char *descript)
{
    send_cmd(NULL, "SERVER %s %d :%s", servname, hop, descript);
}

void ratbox_cmd_connect(int servernum)
{
    /* Make myself known to myself in the serverlist */
    if (UseTS6) {
        me_server =
            new_server(NULL, ServerName, ServerDesc, SERVER_ISME, TS6SID);
    } else {
        me_server =
            new_server(NULL, ServerName, ServerDesc, SERVER_ISME, NULL);
    }
    if (servernum == 1)
        ratbox_cmd_pass(RemotePassword);
    else if (servernum == 2)
        ratbox_cmd_pass(RemotePassword2);
    else if (servernum == 3)
        ratbox_cmd_pass(RemotePassword3);

    ratbox_cmd_capab();
    ratbox_cmd_server(ServerName, 1, ServerDesc);
    ratbox_cmd_svinfo();
}

void RatboxProto::cmd_bot_nick(const char *nick, const char *user, const char *host, const char *real, const char *modes)
{
	EnforceQlinedNick(nick, NULL);
	if (UseTS6) {
		char *uidbuf = ts6_uid_retrieve();
		send_cmd(TS6SID, "UID %s 1 %ld %s %s %s 0 %s :%s", nick, static_cast<long>(time(NULL)), modes, user, host, uidbuf, real);
		new_uid(nick, uidbuf);
	}
	else send_cmd(NULL, "NICK %s 1 %ld %s %s %s %s :%s", nick, static_cast<long>(time(NULL)), modes, user, host, ServerName, real);
	ratbox_cmd_sqline(nick, "Reserved for services");
}

void ratbox_cmd_part(const char *nick, const char *chan, const char *buf)
{
    Uid *ud;

    ud = find_uid(nick);

    if (buf) {
        send_cmd((UseTS6 ? ud->uid : nick), "PART %s :%s", chan, buf);
    } else {
        send_cmd((UseTS6 ? ud->uid : nick), "PART %s", chan);
    }
}

int anope_event_ping(const char *source, int ac, const char **av)
{
    if (ac < 1)
        return MOD_CONT;
    ircd_proto.cmd_pong(ac > 1 ? av[1] : ServerName, av[0]);
    return MOD_CONT;
}

int anope_event_away(const char *source, int ac, const char **av)
{
    User *u = NULL;

    if (UseTS6) {
        u = find_byuid(source);
    }

    m_away((UseTS6 ? (u ? u->nick : source) : source),
           (ac ? av[0] : NULL));
    return MOD_CONT;
}

int anope_event_kill(const char *source, int ac, const char **av)
{
    if (ac != 2)
        return MOD_CONT;

    m_kill(av[0], av[1]);
    return MOD_CONT;
}

int anope_event_kick(const char *source, int ac, const char **av)
{
    if (ac != 3)
        return MOD_CONT;
    do_kick(source, ac, av);
    return MOD_CONT;
}

void ratbox_cmd_eob()
{
    /* doesn't support EOB */
}

int anope_event_join(const char *source, int ac, const char **av)
{
    if (ac != 1) {
        do_sjoin(source, ac, av);
        return MOD_CONT;
    } else {
        do_join(source, ac, av);
    }
    return MOD_CONT;
}

int anope_event_motd(const char *source, int ac, const char **av)
{
    if (!source) {
        return MOD_CONT;
    }

    m_motd(source);
    return MOD_CONT;
}

int anope_event_privmsg(const char *source, int ac, const char **av)
{
    User *u;
    Uid *ud;

    if (ac != 2) {
        return MOD_CONT;
    }

    u = find_byuid(source);
    ud = find_nickuid(av[0]);
    m_privmsg((UseTS6 ? (u ? u->nick : source) : source),
              (UseTS6 ? (ud ? ud->nick : av[0]) : av[0]), av[1]);
    return MOD_CONT;
}

int anope_event_part(const char *source, int ac, const char **av)
{
    User *u;

    if (ac < 1 || ac > 2) {
        return MOD_CONT;
    }

    u = find_byuid(source);
    do_part((UseTS6 ? (u ? u->nick : source) : source), ac, av);

    return MOD_CONT;
}

int anope_event_whois(const char *source, int ac, const char **av)
{
    Uid *ud;

    if (source && ac >= 1) {
        ud = find_nickuid(av[0]);
        m_whois(source, (UseTS6 ? (ud ? ud->nick : av[0]) : av[0]));
    }
    return MOD_CONT;
}

/* EVENT: SERVER */
int anope_event_server(const char *source, int ac, const char **av)
{
    if (!stricmp(av[1], "1")) {
        uplink = sstrdup(av[0]);
        if (UseTS6 && TS6UPLINK) {
            do_server(source, av[0], av[1], av[2], TS6UPLINK);
        } else {
            do_server(source, av[0], av[1], av[2], NULL);
        }
    } else {
        do_server(source, av[0], av[1], av[2], NULL);
    }
    return MOD_CONT;
}

int anope_event_sid(const char *source, int ac, const char **av)
{
    Server *s;

    /* :42X SID trystan.nomadirc.net 2 43X :ircd-ratbox test server */

    s = findserver_uid(servlist, source);

    do_server(s->name, av[0], av[1], av[3], av[2]);
    return MOD_CONT;
}

int anope_event_squit(const char *source, int ac, const char **av)
{
    if (ac != 2)
        return MOD_CONT;
    do_squit(source, ac, av);
    return MOD_CONT;
}

int anope_event_quit(const char *source, int ac, const char **av)
{
    User *u;

    if (ac != 1) {
        return MOD_CONT;
    }

    u = find_byuid(source);

    do_quit((UseTS6 ? (u ? u->nick : source) : source), ac, av);
    return MOD_CONT;
}

void ratbox_cmd_372(const char *source, const char *msg)
{
    send_cmd((UseTS6 ? TS6SID : ServerName), "372 %s :- %s", source, msg);
}

void ratbox_cmd_372_error(const char *source)
{
    send_cmd((UseTS6 ? TS6SID : ServerName),
             "422 %s :- MOTD file not found!  Please "
             "contact your IRC administrator.", source);
}

void ratbox_cmd_375(const char *source)
{
    send_cmd((UseTS6 ? TS6SID : ServerName),
             "375 %s :- %s Message of the Day", source, ServerName);
}

void ratbox_cmd_376(const char *source)
{
    send_cmd((UseTS6 ? TS6SID : ServerName),
             "376 %s :End of /MOTD command.", source);
}

/* 391 */
void ratbox_cmd_391(const char *source, const char *timestr)
{
    if (!timestr) {
        return;
    }
    send_cmd(NULL, "391 :%s %s :%s", source, ServerName, timestr);
}

/* 250 */
void ratbox_cmd_250(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd(NULL, "250 %s", buf);
}

/* 307 */
void ratbox_cmd_307(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd((UseTS6 ? TS6SID : ServerName), "307 %s", buf);
}

/* 311 */
void ratbox_cmd_311(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd((UseTS6 ? TS6SID : ServerName), "311 %s", buf);
}

/* 312 */
void ratbox_cmd_312(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd((UseTS6 ? TS6SID : ServerName), "312 %s", buf);
}

/* 317 */
void ratbox_cmd_317(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd((UseTS6 ? TS6SID : ServerName), "317 %s", buf);
}

/* 219 */
void ratbox_cmd_219(const char *source, const char *letter)
{
    if (!source) {
        return;
    }

    if (letter) {
        send_cmd(NULL, "219 %s %c :End of /STATS report.", source,
                 *letter);
    } else {
        send_cmd(NULL, "219 %s l :End of /STATS report.", source);
    }
}

/* 401 */
void ratbox_cmd_401(const char *source, const char *who)
{
    if (!source || !who) {
        return;
    }
    send_cmd((UseTS6 ? TS6SID : ServerName), "401 %s %s :No such service.",
             source, who);
}

/* 318 */
void ratbox_cmd_318(const char *source, const char *who)
{
    if (!source || !who) {
        return;
    }

    send_cmd((UseTS6 ? TS6SID : ServerName),
             "318 %s %s :End of /WHOIS list.", source, who);
}

/* 242 */
void ratbox_cmd_242(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd(NULL, "242 %s", buf);
}

/* 243 */
void ratbox_cmd_243(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd(NULL, "243 %s", buf);
}

/* 211 */
void ratbox_cmd_211(const char *buf)
{
    if (!buf) {
        return;
    }

    send_cmd(NULL, "211 %s", buf);
}

void RatboxProto::cmd_mode(const char *source, const char *dest, const char *buf)
{
	if (!buf) return;
	if (source) {
		Uid *ud = find_uid(source);
		send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "MODE %s %s", dest, buf);
	}
	else send_cmd(source, "MODE %s %s", dest, buf);
}

void ratbox_cmd_tmode(const char *source, const char *dest, const char *fmt, ...)
{
    va_list args;
    char buf[BUFSIZE];
    *buf = '\0';

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(buf, BUFSIZE - 1, fmt, args);
        va_end(args);
    }
    if (!*buf) {
        return;
    }

    send_cmd(NULL, "MODE %s %s", dest, buf);
}

void RatboxProto::cmd_nick(const char *nick, const char *name, const char *mode)
{
	EnforceQlinedNick(nick, NULL);
	if (UseTS6) {
		char *uidbuf = ts6_uid_retrieve();
		send_cmd(TS6SID, "UID %s 1 %ld %s %s %s 0 %s :%s", nick, static_cast<long>(time(NULL)), mode, ServiceUser, ServiceHost, uidbuf, name);
		new_uid(nick, uidbuf);
	}
	else send_cmd(NULL, "NICK %s 1 %ld %s %s %s %s :%s", nick, static_cast<long>(time(NULL)), mode, ServiceUser, ServiceHost, ServerName, name);
	ratbox_cmd_sqline(nick, "Reserved for services");
}

void RatboxProto::cmd_kick(const char *source, const char *chan, const char *user, const char *buf)
{
	Uid *ud = find_uid(source);
	User *u = finduser(user);
	if (buf) send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "KICK %s %s :%s", chan, UseTS6 ? (u ? u->uid : user) : user, buf);
	else send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "KICK %s %s", chan, UseTS6 ? (u ? u->uid : user) : user);
}

void RatboxProto::cmd_notice_ops(const char *source, const char *dest, const char *buf)
{
	if (!buf) return;
	send_cmd(NULL, "NOTICE @%s :%s", dest, buf);
}

void RatboxProto::cmd_bot_chan_mode(const char *nick, const char *chan)
{
	if (UseTS6) {
		Uid *u = find_uid(nick);
		ratbox_cmd_tmode(nick, chan, "%s %s", ircd->botchanumode, u ? u->uid : nick);
	}
	else anope_cmd_mode(nick, chan, "%s %s", ircd->botchanumode, nick);
}

/* QUIT */
void RatboxProto::cmd_quit(const char *source, const char *buf)
{
	Uid *ud = find_uid(source);
	if (buf) send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "QUIT :%s", buf);
	else send_cmd(UseTS6 ? (ud ? ud->uid : source) : source, "QUIT");
}

/* PONG */
void RatboxProto::cmd_pong(const char *servname, const char *who)
{
	if (UseTS6) send_cmd(TS6SID, "PONG %s", who);
	else send_cmd(servname, "PONG %s", who);
}

/* INVITE */
void ratbox_cmd_invite(const char *source, const char *chan, const char *nick)
{
    Uid *ud;
    User *u;

    if (!source || !chan || !nick) {
        return;
    }

    ud = find_uid(source);
    u = finduser(nick);

    send_cmd((UseTS6 ? (ud ? ud->uid : source) : source), "INVITE %s %s",
             (UseTS6 ? (u ? u->uid : nick) : nick), chan);
}

/* SQUIT */
void ratbox_cmd_squit(const char *servname, const char *message)
{
    if (!servname || !message) {
        return;
    }

    send_cmd(NULL, "SQUIT %s :%s", servname, message);
}

int anope_event_mode(const char *source, int ac, const char **av)
{
    User *u, *u2;

    if (ac < 2) {
        return MOD_CONT;
    }

    if (*av[0] == '#' || *av[0] == '&') {
        do_cmode(source, ac, av);
    } else {
        if (UseTS6) {
            u = find_byuid(source);
            u2 = find_byuid(av[0]);
            av[0] = u2->nick;
            do_umode(u->nick, ac, av);
        } else {
            do_umode(source, ac, av);
        }
    }
    return MOD_CONT;
}

int anope_event_tmode(const char *source, int ac, const char **av)
{
    if (*av[1] == '#' || *av[1] == '&') {
        do_cmode(source, ac, av);
    }
    return MOD_CONT;
}

void ratbox_cmd_351(const char *source)
{
    send_cmd((UseTS6 ? TS6SID : ServerName),
             "351 %s Anope-%s %s :%s - %s (%s) -- %s", source, version_number,
             ServerName, ircd->name, version_flags, EncModule, version_build);

}

/* Event: PROTOCTL */
int anope_event_capab(const char *source, int ac, const char **av)
{
    int argvsize = 8;
    int argc;
    const char **argv;
    char *str;

    if (ac < 1)
        return MOD_CONT;

    /* We get the params as one arg, we should split it for capab_parse */
    argv = (const char **)scalloc(argvsize, sizeof(const char *));
    argc = 0;
    while ((str = myStrGetToken(av[0], ' ', argc))) {
        if (argc == argvsize) {
            argvsize += 8;
            argv = (const char **)srealloc(argv, argvsize * sizeof(const char *));
        }
        argv[argc] = str;
        argc++;
    }

    capab_parse(argc, argv);

    /* Free our built ac/av */
    for (argvsize = 0; argvsize < argc; argvsize++) {
        free((char *)argv[argvsize]);
    }
    free((char **)argv);

    return MOD_CONT;
}

/* SVSHOLD - set */
void ratbox_cmd_svshold(const char *nick)
{
    /* Not supported by this IRCD */
}

/* SVSHOLD - release */
void ratbox_cmd_release_svshold(const char *nick)
{
    /* Not Supported by this IRCD */
}

/* SVSNICK */
void ratbox_cmd_svsnick(const char *nick, const char *newnick, time_t when)
{
    /* not supported */
}

void ratbox_cmd_svso(const char *source, const char *nick, const char *flag)
{
    /* Not Supported by this IRCD */
}

void ratbox_cmd_unban(const char *name, const char *nick)
{
    /* Not Supported by this IRCD */
}

/* SVSMODE channel modes */

void ratbox_cmd_svsmode_chan(const char *name, const char *mode, const char *nick)
{
    /* Not Supported by this IRCD */
}

/* SVSMODE +d */
/* sent if svid is something weird */
void ratbox_cmd_svid_umode(const char *nick, time_t ts)
{
    /* not supported */
}

/* SVSMODE +d */
/* nc_change was = 1, and there is no na->status */
void ratbox_cmd_nc_change(User * u)
{
    /* not supported */
}

/* SVSMODE +d */
void ratbox_cmd_svid_umode2(User * u, const char *ts)
{
    /* not supported */
}

void ratbox_cmd_svid_umode3(User * u, const char *ts)
{
    /* not used */
}

/* NICK <newnick>  */
void ratbox_cmd_chg_nick(const char *oldnick, const char *newnick)
{
    if (!oldnick || !newnick) {
        return;
    }

    send_cmd(oldnick, "NICK %s", newnick);
}

/*
 * SVINFO
 *      parv[0] = sender prefix
 *      parv[1] = TS_CURRENT for the server
 *      parv[2] = TS_MIN for the server
 *      parv[3] = server is standalone or connected to non-TS only
 *      parv[4] = server's idea of UTC time
 */
int anope_event_svinfo(const char *source, int ac, const char **av)
{
    /* currently not used but removes the message : unknown message from server */
    return MOD_CONT;
}

int anope_event_pass(const char *source, int ac, const char **av)
{
    if (UseTS6) {
        TS6UPLINK = sstrdup(av[3]);
    }
    return MOD_CONT;
}

void ratbox_cmd_svsjoin(const char *source, const char *nick, const char *chan, const char *param)
{
    /* Not Supported by this IRCD */
}

void ratbox_cmd_svspart(const char *source, const char *nick, const char *chan)
{
    /* Not Supported by this IRCD */
}

void ratbox_cmd_swhois(const char *source, const char *who, const char *mask)
{
    /* not supported */
}

int anope_event_notice(const char *source, int ac, const char **av)
{
    return MOD_CONT;
}

int anope_event_admin(const char *source, int ac, const char **av)
{
    return MOD_CONT;
}

int anope_event_invite(const char *source, int ac, const char **av)
{
    return MOD_CONT;
}

int anope_event_bmask(const char *source, int ac, const char **av)
{
    Channel *c;
    char *bans;
    char *b;
    int count, i;

    /* :42X BMASK 1106409026 #ircops b :*!*@*.aol.com */
    /*             0          1      2   3            */
    c = findchan(av[1]);

    if (c) {
        bans = sstrdup(av[3]);
        count = myNumToken(bans, ' ');
        for (i = 0; i <= count - 1; i++) {
            b = myStrGetToken(bans, ' ', i);
            if (!stricmp(av[2], "b")) {
                add_ban(c, b);
            }
            if (!stricmp(av[2], "e")) {
                add_exception(c, b);
            }
            if (!stricmp(av[2], "I")) {
                add_invite(c, b);
            }
            if (b)
                free(b);
        }
        free(bans);
    }
    return MOD_CONT;
}

int ratbox_flood_mode_check(const char *value)
{
    return 0;
}

int anope_event_error(const char *source, int ac, const char **av)
{
    if (ac >= 1) {
        if (debug) {
            alog("debug: %s", av[0]);
        }
    }
    return MOD_CONT;
}

void ratbox_cmd_jupe(const char *jserver, const char *who, const char *reason)
{
    char rbuf[256];

    snprintf(rbuf, sizeof(rbuf), "Juped by %s%s%s", who,
             reason ? ": " : "", reason ? reason : "");

    if (findserver(servlist, jserver))
        ratbox_cmd_squit(jserver, rbuf);
    ratbox_cmd_server(jserver, 2, rbuf);
    new_server(me_server, jserver, rbuf, SERVER_JUPED, NULL);
}

/*
  1 = valid nick
  0 = nick is in valid
*/
int ratbox_valid_nick(const char *nick)
{
    /* TS6 Save extension -Certus */
    if (isdigit(*nick))
        return 0;
	return 1;
}

/*
  1 = valid chan
  0 = chan is in valid
*/
int ratbox_valid_chan(const char *chan)
{
    /* no hard coded invalid chans */
    return 1;
}


void ratbox_cmd_ctcp(const char *source, const char *dest, const char *buf)
{
    char *s;

    if (!buf) {
        return;
    } else {
        s = normalizeBuffer(buf);
    }

    send_cmd(source, "NOTICE %s :\1%s \1", dest, s);
    free(s);
}


/**
 * Tell anope which function we want to perform each task inside of anope.
 * These prototypes must match what anope expects.
 **/
void moduleAddAnopeCmds()
{
    pmodule_cmd_372(ratbox_cmd_372);
    pmodule_cmd_372_error(ratbox_cmd_372_error);
    pmodule_cmd_375(ratbox_cmd_375);
    pmodule_cmd_376(ratbox_cmd_376);
    pmodule_cmd_351(ratbox_cmd_351);
    pmodule_cmd_invite(ratbox_cmd_invite);
    pmodule_cmd_part(ratbox_cmd_part);
    pmodule_cmd_391(ratbox_cmd_391);
    pmodule_cmd_250(ratbox_cmd_250);
    pmodule_cmd_307(ratbox_cmd_307);
    pmodule_cmd_311(ratbox_cmd_311);
    pmodule_cmd_312(ratbox_cmd_312);
    pmodule_cmd_317(ratbox_cmd_317);
    pmodule_cmd_219(ratbox_cmd_219);
    pmodule_cmd_401(ratbox_cmd_401);
    pmodule_cmd_318(ratbox_cmd_318);
    pmodule_cmd_242(ratbox_cmd_242);
    pmodule_cmd_243(ratbox_cmd_243);
    pmodule_cmd_211(ratbox_cmd_211);
    pmodule_cmd_global(ratbox_cmd_global);
    pmodule_cmd_sqline(ratbox_cmd_sqline);
    pmodule_cmd_squit(ratbox_cmd_squit);
    pmodule_cmd_svso(ratbox_cmd_svso);
    pmodule_cmd_chg_nick(ratbox_cmd_chg_nick);
    pmodule_cmd_svsnick(ratbox_cmd_svsnick);
    pmodule_cmd_vhost_on(ratbox_cmd_vhost_on);
    pmodule_cmd_connect(ratbox_cmd_connect);
    pmodule_cmd_svshold(ratbox_cmd_svshold);
    pmodule_cmd_release_svshold(ratbox_cmd_release_svshold);
    pmodule_cmd_unsgline(ratbox_cmd_unsgline);
    pmodule_cmd_unszline(ratbox_cmd_unszline);
    pmodule_cmd_szline(ratbox_cmd_szline);
    pmodule_cmd_sgline(ratbox_cmd_sgline);
    pmodule_cmd_unban(ratbox_cmd_unban);
    pmodule_cmd_svsmode_chan(ratbox_cmd_svsmode_chan);
    pmodule_cmd_svid_umode(ratbox_cmd_svid_umode);
    pmodule_cmd_nc_change(ratbox_cmd_nc_change);
    pmodule_cmd_svid_umode2(ratbox_cmd_svid_umode2);
    pmodule_cmd_svid_umode3(ratbox_cmd_svid_umode3);
    pmodule_cmd_svsjoin(ratbox_cmd_svsjoin);
    pmodule_cmd_svspart(ratbox_cmd_svspart);
    pmodule_cmd_swhois(ratbox_cmd_swhois);
    pmodule_cmd_eob(ratbox_cmd_eob);
    pmodule_flood_mode_check(ratbox_flood_mode_check);
    pmodule_cmd_jupe(ratbox_cmd_jupe);
    pmodule_valid_nick(ratbox_valid_nick);
    pmodule_valid_chan(ratbox_valid_chan);
    pmodule_cmd_ctcp(ratbox_cmd_ctcp);
    pmodule_set_umode(ratbox_set_umode);
}

/**
 * Now tell anope how to use us.
 **/
int AnopeInit(int argc, char **argv)
{

    moduleAddAuthor("Anope");
    moduleAddVersion("$Id$");
    moduleSetType(PROTOCOL);

    pmodule_ircd_version("Ratbox IRCD 2.0+");
    pmodule_ircd_cap(myIrcdcap);
    pmodule_ircd_var(myIrcd);
    pmodule_ircd_cbmodeinfos(myCbmodeinfos);
    pmodule_ircd_cumodes(myCumodes);
    pmodule_ircd_flood_mode_char_set("");
    pmodule_ircd_flood_mode_char_remove("");
    pmodule_ircd_cbmodes(myCbmodes);
    pmodule_ircd_cmmodes(myCmmodes);
    pmodule_ircd_csmodes(myCsmodes);
    pmodule_ircd_useTSMode(1);

        /** Deal with modes anope _needs_ to know **/
    pmodule_invis_umode(UMODE_i);
    pmodule_oper_umode(UMODE_o);
    pmodule_invite_cmode(CMODE_i);
    pmodule_secret_cmode(CMODE_s);
    pmodule_private_cmode(CMODE_p);
    pmodule_key_mode(CMODE_k);
    pmodule_limit_mode(CMODE_l);

    moduleAddAnopeCmds();
	pmodule_ircd_proto(&ircd_proto);
    moduleAddIRCDMsgs();

    return MOD_CONT;
}
