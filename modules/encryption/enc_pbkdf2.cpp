#include "module.h"
#include "modules/encryption.h"
#include <cmath>

class PBKDF2 : public Module
{

	struct HashSetting
	{
		size_t block_size;
		size_t salt_length;
		float key_length;
		float hash_length;
		size_t iterations;
		Anope::string method;
		ServiceReference<Encryption::Provider> provider;
	};

	HashSetting setting;

	Anope::string Hash(const Anope::string& src, HashSetting& sett)
	{
		Encryption::Context* context = sett.provider->CreateContext();

		context->Update(reinterpret_cast<const unsigned char *>(src.c_str()), src.length());
		context->Finalize();

		Encryption::Hash hash = context->GetFinalizedHash();
		delete context;
		std::vector<unsigned char> ret(hash.first, hash.first + hash.second);
		return Anope::string(ret.begin(), ret.end());
	}

	Anope::string HashHMAC(const Anope::string& key, const Anope::string& msg, HashSetting& sett)
	{
		Anope::string o_key_pad, i_key_pad;
		Anope::string kbuf = key.length() > sett.block_size ? Hash(key, sett) : key;
		kbuf.resize(sett.block_size);

		for (size_t n = 0; n < sett.block_size; n++)
		{
			o_key_pad.push_back(static_cast<char>(kbuf[n] ^ 0x5C));
			i_key_pad.push_back(static_cast<char>(kbuf[n] ^ 0x36));
		}

		return Hash(o_key_pad + Hash(i_key_pad + msg, sett), sett);
	}

	Anope::string Generate(const Anope::string& pass, const Anope::string& salt, HashSetting& sett)
	{
		size_t blocks = std::ceil(sett.key_length / sett.hash_length);

		Anope::string output;
		for (size_t block = 1; block <= blocks; block++)
		{
			std::vector<char> salt_data(4);
			for (size_t i = 0; i < 4; i++)
				salt_data[i] = block >> (24 - i * 8) & 0x0F;

			Anope::string salt_block(salt_data.begin(), salt_data.begin() + 4);
			salt_block = salt + salt_block;

			Anope::string blockdata;
			Anope::string lasthash = blockdata = HashHMAC(pass, salt_block, sett);
			for (size_t iter = 1; iter < sett.iterations; iter++)
			{
				Anope::string tmphash = HashHMAC(pass, lasthash, sett);
				for (size_t i = 0; i < sett.hash_length; i++)
					blockdata[i] ^= tmphash[i];

				lasthash = tmphash;
			}
			output += blockdata;
		}

		output = output.substr(0, sett.key_length);

		return output;
	}

	Anope::string Gensalt(size_t size)
	{
		std::vector<char> tmp(size);
		for (size_t i = 0; i < size; i++)
			tmp[i] = rand() % 255;
		return Anope::string(tmp.begin(), tmp.end());
	}

	struct StoredPass
	{
		Anope::string method;
		size_t iterations;
		Anope::string salt;
		Anope::string hash;

		StoredPass(const Anope::string& line)
		{
			Anope::string tmp;

			sepstream ss(line, ':');
			ss.GetToken(tmp);
			ss.GetToken(method);
			ss.GetToken(tmp);
			ss.GetToken(salt);
			ss.GetToken(hash);

			try
			{
				iterations = convertTo<size_t>(tmp);
			}
			catch (ConvertException&)
			{
				iterations = 0;
			}
		}
	};

 public:
	PBKDF2(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, ENCRYPTION | VENDOR)
	{
		setting.salt_length = 32;
		setting.key_length = 32;
		setting.hash_length = 32;
		setting.block_size = 64;
		setting.iterations = 12288;
		setting.method = "sha256";
		setting.provider = ServiceReference<Encryption::Provider>("Encryption::Provider", setting.method);
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		setting.iterations = conf->GetModule(this)->Get<size_t>("iterations");
	}

	EventReturn OnEncrypt(const Anope::string &src, Anope::string &dest) anope_override
	{
		if (!setting.provider)
			return EVENT_CONTINUE;			

		Anope::string salt = Gensalt(setting.salt_length);
		Anope::string buf = "pbkdf2:" + setting.method + ':' + stringify(setting.iterations) + ':' + Anope::Hex(salt) + ':' + Anope::Hex(Generate(src, salt, setting));

		Log(LOG_DEBUG_2) << "(enc_pbkdf2) hashed password from [" << src << "] to [" << buf << "]";
		dest = buf;
		return EVENT_ALLOW;
	}

	void OnCheckAuthentication(User *, IdentifyRequest *req) anope_override
	{
		const NickAlias *na = NickAlias::Find(req->GetAccount());
		if (na == NULL)
			return;
		NickCore *nc = na->nc;

		size_t pos = nc->pass.find(':');
		if (pos == Anope::string::npos)
			return;
		Anope::string hash_method(nc->pass.begin(), nc->pass.begin() + pos);
		if (!hash_method.equals_cs("pbkdf2"))
			return;

		if (!setting.provider)
		{
			Log(this, "Could not log in " + nc->display + " because " + setting.method + " wan't loaded.");
			return;
		}

		StoredPass sp(nc->pass);
		if (sp.method.empty() || sp.salt.empty() || sp.hash.empty() || !sp.iterations)
			return;

		HashSetting sett = setting;
			sett.iterations = sp.iterations;

		Anope::string rawsalt;
		Anope::Unhex(sp.salt, rawsalt);
		Anope::string hash = Anope::Hex(Generate(req->GetPassword(), rawsalt, sett));
		if (hash == sp.hash)
		{
			if ((ModuleManager::FindFirstOf(ENCRYPTION) != this) || (setting.iterations != sp.iterations))
				Anope::Encrypt(req->GetPassword(), nc->pass);
			req->Success(this);
		}
	}
};

MODULE_INIT(PBKDF2)
