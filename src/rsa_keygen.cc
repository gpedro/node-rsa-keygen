#include <node.h>
#include <nan.h>
#include <v8.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

using namespace v8;
using namespace node;

static RSA *generateKey(int num, unsigned long e) {
#if OPENSSL_VERSION_NUMBER < 0x009080001
    return RSA_generate_key(num, e, NULL, NULL);
#else
    BIGNUM *eBig = BN_new();

    if (eBig == NULL) {
        return NULL;
    }

    if (!BN_set_word(eBig, e)) {
        BN_free(eBig);
        return NULL;
    }

    RSA *result = RSA_new();

    if (result == NULL) {
        BN_free(eBig);
        return NULL;
    }

    if (RSA_generate_key_ex(result, num, eBig, NULL) < 0) {
        RSA_free(result);
        result = NULL;
    }

    BN_free(eBig);

    return result;
#endif
}

static Handle<Object> toBuffer(BIO *bio) {
    char *data;
    long length = BIO_get_mem_data(bio, &data);
    Local<Object> result = NanNewBufferHandle(length);

    memcpy(Buffer::Data(result), data, length);

    return result;
}

NAN_METHOD(Generate) {
	NanScope();
	
	int modulusBits = 2048;
	int exponent = 65537;

	if (args[0]->IsInt32()) {
		modulusBits = args[0]->ToInt32()->Value();
	}

	if (args[1]->IsInt32()) {
		exponent = args[1]->ToInt32()->Value();
	}

	if (modulusBits < 512) {
		NanThrowError(NanTypeError("Expected modulus bit count bigger than 512."));
		NanReturnUndefined();
	}

	if (exponent < 0) {
		NanThrowError(NanTypeError("Expected positive exponent."));
		NanReturnUndefined();
	}

	if ((exponent & 1) == 0) {
		NanThrowError(NanTypeError("Expected odd exponent."));
		NanReturnUndefined();
	}

	RSA *rsa = generateKey(modulusBits, (unsigned int)exponent);

	if (!rsa) {
		NanThrowError(NanError("Failed creating RSA context."));
		NanReturnUndefined();
	}

	BIO *publicBio = BIO_new(BIO_s_mem());
	BIO *privateBio = BIO_new(BIO_s_mem());

	if (!publicBio || !privateBio) {
		if (publicBio) {
			BIO_vfree(publicBio);
		}

		if (privateBio) {
			BIO_vfree(privateBio);
		}

		RSA_free(rsa);

		NanThrowError(NanError("Failed to allocate OpenSSL buffers."));
		NanReturnUndefined();
	}

	if (!PEM_write_bio_RSA_PUBKEY(publicBio, rsa)) {
		BIO_vfree(publicBio);
		BIO_vfree(privateBio);
		RSA_free(rsa);

		NanThrowError(NanError("Failed exporting public key."));
		NanReturnUndefined();
	}

	if (!PEM_write_bio_RSAPrivateKey(privateBio, rsa, NULL, NULL, 0, NULL, NULL)) {
		BIO_vfree(publicBio);
		BIO_vfree(privateBio);
		RSA_free(rsa);

		NanThrowError(NanError("Failed exporting private key."));
		NanReturnUndefined();
	}

	Local<Object> publicKey = toBuffer(publicBio);
	Local<Object> privateKey = toBuffer(privateBio);

	BIO_vfree(publicBio);
	BIO_vfree(privateBio);
	RSA_free(rsa);

	Local<Object> result = NanNew<Object>();

	result->Set(NanNew<String>("public_key"), publicKey);
	result->Set(NanNew<String>("private_key"), privateKey);

	NanReturnValue(result);
}

void InitAll(Handle<Object> exports) {
	exports->Set(NanNew<String>("generate"), NanNew<FunctionTemplate>(Generate)->GetFunction());
}

NODE_MODULE(rsa_keygen, InitAll)

