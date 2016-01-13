/* RequiredLibraries: ssl,crypto */
/* RequiredWindowsLibraries: ssleay32,libeay32 */

#include "module.h"
#include "modules/sasl.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

using namespace SASL;

struct scram_context
{
	const EVP_MD *const md;
	const size_t hash_size;

	scram_context(const EVP_MD *const _md)
		: md(_md), hash_size(EVP_MD_size(md))
	{
	}

#define _FAIL_IF(exp) \
	if (exp) \
		throw std::runtime_error("Call to OpenSSL failed!");

	std::vector<uint8_t> calculate_hash(const Anope::string &key, const std::vector<uint8_t> &salt, const size_t iterations)
	{
		std::vector<uint8_t> U[2];
		U[0].resize(this->hash_size);
		U[1].resize(this->hash_size);

		HMAC_CTX ctx;
		_FAIL_IF(1 != HMAC_Init(&ctx, key.data(), key.length(), this->md));
		_FAIL_IF(1 != HMAC_Update(&ctx, reinterpret_cast<const unsigned char *>(salt.data()), salt.size()));
		_FAIL_IF(1 != HMAC_Update(&ctx, reinterpret_cast<const unsigned char *>("\0\0\0\1"), 4));
		_FAIL_IF(1 != HMAC_Final(&ctx, U[0].data(), NULL));
		HMAC_CTX_cleanup(&ctx);

		for (size_t i = 1; i < iterations; ++i)
		{
			_FAIL_IF(NULL == HMAC(this->md, key.data(), key.length(), U[i != 1].data(), this->hash_size, U[1].data(), NULL));
			for (size_t j = 0; j < this->hash_size; ++j)
				U[0][j] ^= U[1][j];
		}

		return U[0];
	}

	std::vector<uint8_t> calculate_client_key(const Anope::string &hash)
	{
		std::vector<uint8_t> ret(this->hash_size);
		_FAIL_IF(NULL == HMAC(this->md, hash.data(), hash.length(), reinterpret_cast<const unsigned char *>("Client Key"), 10, ret.data(), NULL));
		return ret;
	}

	std::vector<uint8_t> calculate_stored_key(const std::vector<uint8_t> &client_key)
	{
		std::vector<uint8_t> ret(this->hash_size);

		EVP_MD_CTX mdctx;
		memset(&mdctx, 0, sizeof(EVP_MD_CTX));
		_FAIL_IF(0 == EVP_DigestInit(&mdctx, this->md));
		_FAIL_IF(0 == EVP_DigestUpdate(&mdctx, client_key.data(), this->hash_size));
		_FAIL_IF(0 == EVP_DigestFinal(&mdctx, ret.data(), NULL));
		EVP_MD_CTX_cleanup(&mdctx);

		return ret;
	}

	std::vector<uint8_t> calculate_client_signature(const std::vector<uint8_t> &stored_key, const Anope::string &auth_message)
	{
		std::vector<uint8_t> ret(this->hash_size);
		_FAIL_IF(NULL == HMAC(this->md, stored_key.data(), stored_key.size(), reinterpret_cast<const unsigned char *>(auth_message.data()), auth_message.length(), ret.data(), NULL));
		return ret;
	}

	std::vector<uint8_t> calculate_client_proof(const std::vector<uint8_t> &client_key, const std::vector<uint8_t> &client_signature)
	{
		std::vector<uint8_t> ret(this->hash_size);
		for (size_t i = 0; i < client_key.size(); ++i)
			ret[i] = client_key.data()[i] ^ client_signature.data()[i];
		return ret;
	}

	std::vector<uint8_t> calculate_server_key(const std::vector<uint8_t> &hash)
	{
		std::vector<uint8_t> ret(this->hash_size);
		_FAIL_IF(NULL == HMAC(this->md, hash.data(), hash.size(), reinterpret_cast<const unsigned char *>("Server Key"), 10, ret.data(), NULL));
		return ret;
	}

	std::vector<uint8_t> calculate_server_signature(const std::vector<uint8_t> server_key, const Anope::string &auth_message)
	{
		std::vector<uint8_t> ret(this->hash_size);
		_FAIL_IF(NULL == HMAC(this->md, server_key.data(), server_key.size(), reinterpret_cast<const unsigned char *>(auth_message.data()), auth_message.length(), ret.data(), NULL));
		return ret;
	}
#undef _FAIL_IF
};

struct scram_helpers
{
	static bool char_is_value_safe(char chr)
	{
		return ((chr >= 0x01 && chr <= 0x2B) || (chr >= 0x2D && chr <= 0x3C) || (chr >= 0x3E && chr <= 0x7F));
	}

	static bool char_is_printable(char chr)
	{
		return ((chr >= 0x21 && chr <= 0x2B) || (chr >= 0x2D && chr <= 0x7E));
	}

	static bool char_is_base64(char chr)
	{
		return ((chr >= 0x30 && chr <= 0x39) ||(chr >= 0x41 && chr <= 0x5A) || (chr >= 0x61 && chr <= 0x7A) || chr == 0x2B || chr == 0x2F || chr == 0x3D);
	}

	static Anope::string saslname_extract(Anope::string saslname)
	{
		for (Anope::string::const_iterator it = saslname.begin(); it != saslname.end(); ++it)
		{
			const size_t pos = it - saslname.begin();
			if (*it == '=' && (saslname.compare(pos, 2, "2C") || saslname.compare(pos, 2, "3D")))
				continue;

			if (!char_is_value_safe(saslname[pos]))
				throw std::invalid_argument("SASLName invalid");
		}

		for (size_t pos = -1; (pos = saslname.find("=2C", pos + 1)) != Anope::string::npos; saslname.replace(pos, 3, ","));
		for (size_t pos = -1; (pos = saslname.find("=3D", pos + 1)) != Anope::string::npos; saslname.replace(pos, 3, "="));

		return saslname;
	}

	static Anope::string printable_extract(Anope::string text)
	{
		for (Anope::string::iterator it = text.begin(); it != text.end(); ++it)
		{
			if (!char_is_printable(*it))
				throw std::invalid_argument("Found non-printable char in printable field");
		}
		return text;
	}

	static Anope::string value_safe_extract(Anope::string text)
	{
		for (Anope::string::iterator it = text.begin(); it != text.end(); ++it)
		{
			if (!char_is_value_safe(*it))
				throw std::invalid_argument("Found non-printable char in printable field");
		}
		return text;
	}

	static Anope::string base64_extract(Anope::string text)
	{
		for (Anope::string::iterator it = text.begin(); it != text.end(); ++it)
		{
			if (!char_is_base64(*it))
				throw std::invalid_argument("Found non-printable char in printable field");
		}
		return text;
	}

	static std::map<char, Anope::string> scram_parse(const Anope::string &format, const Anope::string msg, ...)
	{
		typedef Anope::string(*_extract_func)(Anope::string msg);

		const size_t param_count = std::count(format.begin(), format.end(), '%');

		std::map<char, Anope::string> ret;

		std::vector<std::pair<char, _extract_func> > format_member_vec;
		format_member_vec.reserve(param_count);

		// Extract the parameter options from the format string
		{
			size_t current = 0;
			size_t last = 1;
			do
			{
				current = format.find('%', ++current);

				format_member_vec.push_back(std::pair<char, _extract_func>(format.substr(last, current - last)[0], 0));
				last = current + 1;
			}
			while (current != Anope::string::npos);
		}

		// Assign the the appropriate extract function to the format info
		{
			va_list va_args;
			va_start(va_args, msg);
			for (size_t i = 0; i < param_count; ++i)
				format_member_vec[i].second = va_arg(va_args, _extract_func);
			va_end(va_args);
		}

		Anope::string::const_iterator msg_it = msg.begin();

		for (std::vector<std::pair<char, _extract_func> >::const_iterator info_it = format_member_vec.begin(); info_it != format_member_vec.end(); ++info_it)
		{
			if (msg_it == msg.end() || msg_it + 1 == msg.end() || msg_it + 2 == msg.end())
				throw std::invalid_argument("Message invalid");

			if (*msg_it != info_it->first || *++msg_it != '=')
				throw std::invalid_argument("Letter not found in expected place");

			++msg_it;
			Anope::string::const_iterator end_it = std::find(msg_it, msg.end(), ',');

			ret.insert(std::make_pair(info_it->first, info_it->second(Anope::string(msg_it, end_it))));

			msg_it = end_it;
			if (msg_it != msg.end())
				++msg_it;
		}

		return ret;
	}

	static Anope::string make_nonce(size_t target_length)
	{
		char rand_bytes[256];

		std::vector<uint8_t> ret_buf;
		ret_buf.reserve(target_length);

		for (size_t found_bytes = 0; found_bytes < target_length; )
		{
			if (!RAND_bytes((unsigned char *)rand_bytes, sizeof(rand_bytes)))
				throw std::runtime_error("Psuedo-random number generator failed");

			for (size_t i = 0; i < sizeof(rand_bytes); ++i)
			{
				if (!char_is_printable(rand_bytes[i]))
					continue;

				ret_buf.push_back(rand_bytes[i]);
				if (++found_bytes == target_length)
					break;
			}
		}

		return Anope::string(ret_buf.begin(), ret_buf.end());
	}
};



class SCRAM : public Mechanism
{
	void Err(Session *sess)
	{
		sasl->SendMessage(sess, "D", "F");
		delete sess;
	}

	void Abort(Session *sess)
	{
		sasl->SendMessage(sess, "D", "A");
		delete sess;
	}

public:
	scram_context &scram_ctx;
	SerializableExtensibleItem<Anope::string> scram_salt;
	SerializableExtensibleItem<Anope::string> scram_hash;
	SerializableExtensibleItem<unsigned int> scram_iterations;

	struct SCRAMSession : public SASL::Session
	{
		enum scram_state
		{
			SCRAM_INIT,
			SCRAM_FIRST,
			SCRAM_LAST
		};

		SCRAM *parent;
		scram_context &scram_ctx;

		Anope::string salt;
		Anope::string hash;
		Anope::string gs2;
		Anope::string nonce;
		Anope::string authzid;
		Anope::string username;
		Anope::string client_first;
		Anope::string server_first;
		unsigned int iterations;

		scram_state state;

		Anope::string handle_first(const Anope::string &line)
		{
			size_t pos = 0;

			// Size must be at least gs2 + n=? + r=?
			if (line.length() < 3 + 3 + 3)
				throw std::invalid_argument("Client first message too short");

			if (line.compare(0, 2, "y,"))
				throw std::invalid_argument("Does not support channel bindings");
			pos += 2;

			// Do we have an authzid name?
			if (!line.compare(2, 2, "a="))
			{
				pos += 2;

				size_t saslname_end = line.find(',', pos);
				if (saslname_end == Anope::string::npos)
					throw std::invalid_argument("Wrong format");

				size_t saslname_length = saslname_end - pos;

				this->authzid = scram_helpers::saslname_extract(line.substr(pos, saslname_length));
				pos += saslname_length;
			}

			pos += 1;
			Anope::B64Encode(line.substr(0, pos), this->gs2);

			this->client_first = line.substr(pos);
			std::map<char, Anope::string> fields = scram_helpers::scram_parse("%n%r", this->client_first, scram_helpers::saslname_extract, scram_helpers::printable_extract);

			this->username = fields['n'];

			// Get the user's required SCRAM info
			{
				const NickAlias *na = NickAlias::Find(this->username);
				if (!na)
					return "";

				Anope::string *sc_hash = parent->scram_hash.Get(na->nc);
				if (!sc_hash || !sc_hash->length())
					throw std::logic_error("The user does not have a SCRAM hash");

				Anope::string *sc_salt = parent->scram_salt.Get(na->nc);
				if (!sc_salt || !sc_salt->length())
					throw std::logic_error("The user does not have a SCRAM salt");

				unsigned int *sc_iter = parent->scram_iterations.Get(na->nc);
				if (!sc_iter || !*sc_iter)
					throw std::logic_error("The user does not have a SCRAM iteration count");

				this->hash = *sc_hash;
				this->salt = *sc_salt;
				this->iterations = *sc_iter;
			}

			if (fields['r'].length() < 12)
				throw std::invalid_argument("Client nonce too short");

			this->nonce = fields['r'] + scram_helpers::make_nonce(24);

			// Construct response message
			Anope::string ret = "r=" + this->nonce;
			Anope::string b64_salt;
			Anope::B64Encode(this->salt, b64_salt);
			ret += ",s=" + b64_salt;
			ret += ",i=" + stringify(this->iterations);

			this->server_first = ret;

			return ret;
		}

		Anope::string handle_last(const Anope::string &line)
		{
			std::map<char, Anope::string> fields = scram_helpers::scram_parse("%c%r%p", line, scram_helpers::base64_extract, scram_helpers::printable_extract, scram_helpers::base64_extract);

			if (fields['c'] != this->gs2)
				throw std::invalid_argument("GS2 header mismatch");

			if (fields['r'] != this->nonce)
				throw std::invalid_argument("Nonce mismatch!");

			std::vector<uint8_t> client_key = scram_ctx.calculate_client_key(this->hash);
			std::vector<uint8_t> stored_key = scram_ctx.calculate_stored_key(client_key);
			Anope::string auth_message = this->client_first + "," + this->server_first + "," + line.substr(0, line.rfind(",p="));
			std::vector<uint8_t> client_signature = scram_ctx.calculate_client_signature(stored_key, auth_message);
			std::vector<uint8_t> client_proof = scram_ctx.calculate_client_proof(client_key, client_signature);
			std::vector<uint8_t> server_key = scram_ctx.calculate_server_key(std::vector<uint8_t>(this->hash.begin(), this->hash.end()));
			std::vector<uint8_t> server_signature = scram_ctx.calculate_server_signature(server_key, auth_message);

			// Verify proof - if the proof is incorrect,, we return "", which our caller must take as a sign to abort
			{
				Anope::string client_proof_b64;
				Anope::B64Encode(Anope::string(client_proof.begin(), client_proof.end()), client_proof_b64);
				if (client_proof_b64 != fields['p'])
					return "";
			}

			// Send server signature, so the client can verify us
			Anope::string server_signature_base64;
			Anope::B64Encode(Anope::string(server_signature.begin(), server_signature.end()), server_signature_base64);
			return "v=" + server_signature_base64;
		}

		SCRAMSession(SCRAM *m, const Anope::string &u, scram_context &_scram_ctx)
			: SASL::Session(m, u), parent(m), scram_ctx(_scram_ctx), state(SCRAM_INIT)
		{
		}

		~SCRAMSession()
		{
		}
	};

	SASL::Session *CreateSession(const Anope::string &uid) anope_override
	{
		return new SCRAMSession(this, uid, scram_ctx);
	}
	SCRAM(Module *mod, scram_context &_scram_ctx) : Mechanism(mod, "SCRAM-SHA-256"), scram_ctx(_scram_ctx), scram_salt(mod, "scram_salt"),
		scram_hash(mod, "scram_hash"), scram_iterations(mod, "scram_iterations")
	{
	}

	~SCRAM()
	{
	}

	void ProcessMessage(SASL::Session *session, const SASL::Message &m) anope_override
	{
		SCRAMSession *sess = anope_dynamic_static_cast<SCRAMSession *>(session);

		if (m.type == "S")
		{
			if (sess->state != SCRAMSession::SCRAM_INIT)
				return Abort(sess);

			sasl->SendMessage(sess, "C", "+");
			sess->state = SCRAMSession::SCRAM_FIRST;
		}
		else if (m.type == "C")
		{
			try
			{
				Anope::string b64data;
				Anope::B64Decode(m.data, b64data);
				if (b64data.empty())
					throw std::invalid_argument("Expected m.data to be Base64-encoded");

				Anope::string reply;
				if (sess->state ==SCRAMSession::SCRAM_FIRST)
				{
					reply = sess->handle_first(b64data);
					sess->state = SCRAMSession::SCRAM_LAST;
				}
				else if (sess->state ==SCRAMSession::SCRAM_LAST)
				{
					reply = sess->handle_last(b64data);
					if (!reply.empty())
					{
						const NickAlias *na = NickAlias::Find(sess->username);
						if (!na)
							reply.clear();
						else
						{
							sasl->Succeed(sess, na->nc);
							delete sess;
							return;
						}
					}
				}
				else
					throw std::invalid_argument("Invalid SCRAM-SHA-256 state");

				if (reply.empty())
					return Err(sess);

				Anope::B64Encode(reply, b64data);
				sasl->SendMessage(sess, "C", b64data);
			}
			catch (std::exception &ex)
			{
				Log(Config->GetClient("NickServ"), "sasl") << ex.what() << " for " << sess->uid << ", data: " << m.data;
				return Abort(sess);
			}
		}
	}
};


class ModuleSASLSCRAMSHA256 : public Module
{
	unsigned int scram_iterations;
	scram_context scram_ctx;
	SCRAM scram;

	void updateSCRAMFields(NickCore *nc, const Anope::string &pass)
	{
		std::vector<uint8_t> scram_salt(32);
		if (!RAND_bytes(reinterpret_cast<uint8_t *>(scram_salt.data()), scram_salt.size()))
			throw ModuleException("Call to RAND_bytes() failed");

		std::vector<uint8_t> scram_hash = scram_ctx.calculate_hash(pass, scram_salt, this->scram_iterations);
		this->scram.scram_salt.Set(nc, Anope::string(scram_salt.begin(), scram_salt.end()));
		this->scram.scram_hash.Set(nc, Anope::string(scram_hash.begin(), scram_hash.end()));
		this->scram.scram_iterations.Set(nc, this->scram_iterations);
	}

public:
	ModuleSASLSCRAMSHA256(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR | EXTRA),
		scram_ctx(EVP_sha256()), scram(this, scram_ctx)
	{
	}

	void OnIdentifyRequestSuccess(::IdentifyRequest *req) anope_override
	{
		const NickAlias *na = NickAlias::Find(req->GetAccount());
		if (na == NULL || this->scram.scram_hash.HasExt(na->nc))
			return;

		updateSCRAMFields(na->nc, req->GetPassword());
	}

	void OnPasswordChanged(NickCore *nc, const Anope::string &pass) anope_override
	{
		updateSCRAMFields(nc, pass);
	}

	void OnNickRegister(User *, NickAlias *na, const Anope::string &pass) anope_override
	{
		updateSCRAMFields(na->nc, pass);
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		Configuration::Block *config = Config->GetModule(this);
		this->scram_iterations = config->Get<unsigned int>("iterations", "4096");
	}
};

MODULE_INIT(ModuleSASLSCRAMSHA256)
