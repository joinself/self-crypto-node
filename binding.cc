// Copyright 2020 Self Group Ltd. All Rights Reserved.

#include <node_api.h>

#include <stdio.h>

#include <sodium.h>

#include <string.h>

#include <self_olm/olm.h>

#include <stdlib.h>

// The compiler for some reason wants to treat self_omemo as a
// C++ library, and mangles the symbols resulting in undefined symbols at runtime. 
// Tell it to explicitly include self_omemo as a C library.
extern "C" {
    #include <self_omemo.h>
}

namespace self_crypto {

    napi_value create_olm_account(napi_env env, napi_callback_info info) {
        if (sodium_init() == -1) {
            napi_throw_error(env, "ENOMEM", "Sodium not ready");
            return NULL;
        }

        void * abuf = malloc(olm_account_size());

        if (abuf == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        OlmAccount * account = olm_account(abuf);

        size_t rand_len = olm_create_account_random_length(account);

        void * rand = malloc(rand_len);

        if (rand == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        if (sodium_init() == -1) {
            napi_throw_error(env, "ERROR", "Sodium not ready");
            return NULL;
        }

        randombytes_buf(rand, rand_len);

        if (olm_create_account(account, rand, rand_len) != 0) {
            napi_throw_error(env, "ERROR", "Could not create olm account");
            return NULL;
        }

        free(rand);

        napi_value aref;

        napi_status status = napi_create_external(env, account, NULL, NULL, & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm account reference");
            return NULL;
        }

        return aref;
    }

    napi_value create_olm_account_derrived_keys(napi_env env, napi_callback_info info) {
        napi_value argv[1];
        size_t argc = 1;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        if (sodium_init() == -1) {
            napi_throw_error(env, "ENOMEM", "Sodium not ready");
            return NULL;
        }

        u_char * seed;
        char * encoded_seed;
        size_t seed_len = 0;
        size_t encoded_seed_len = 0;

        void * abuf = malloc(olm_account_size());

        if (abuf == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        OlmAccount * account = olm_account(abuf);

        // get the encoded seed
        napi_status status = napi_get_value_string_utf8(env, argv[0], NULL, 0, & encoded_seed_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid encoded seed size");
            return NULL;
        }

        encoded_seed = (char * ) malloc(encoded_seed_len);
        if (encoded_seed == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate encoded seed buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[0], encoded_seed, encoded_seed_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid encoded seed");
            return NULL;
        }

        // allocate memory for the decoded seed
        seed_len = crypto_sign_publickeybytes();

        seed = (u_char * ) malloc(seed_len);
        if (seed == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate seed buffer");
            return NULL;
        }

        size_t success = sodium_base642bin(
            seed,
            seed_len,
            encoded_seed,
            encoded_seed_len,
            NULL, &
            seed_len,
            NULL,
            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
        );

        free(encoded_seed);

        if (success != 0) {
            free(seed);
            napi_throw_error(env, "ERROR", "Could not decode seed");
            return NULL;
        }

        olm_create_account_derrived_keys(
            account,
            seed,
            seed_len
        );

        free(seed);

        napi_value aref;

        status = napi_create_external(env, account, NULL, NULL, & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm account reference");
            return NULL;
        }

        return aref;
    }

    napi_value pickle_account(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * aref;
        char * pickle;
        char * password;
        size_t password_len = 0;

        // get the account
        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        if (argc > 1) {
            // get the pickles password if provided
            napi_status status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & password_len);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password size");
                return NULL;
            }

            password = (char * ) malloc(password_len);
            if (password == NULL) {
                napi_throw_error(env, "ERROR", "Could not allocate pickle password buffer");
                return NULL;
            }

            status = napi_get_value_string_utf8(env, argv[1], password, password_len + 1, NULL);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password");
                return NULL;
            }
        }

        size_t pickle_len = olm_pickle_account_length(account);

        pickle = (char * ) malloc(pickle_len);
        if (pickle == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate pickle buffer");
            return NULL;
        }

        olm_pickle_account(
            account,
            password,
            password_len,
            pickle,
            pickle_len
        );

        if (password != NULL) {
            free(password);
        }

        status = napi_create_string_utf8(env, (const char * )(pickle), pickle_len, & result);

        free(pickle);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid alm account keys");
            return NULL;
        }

        return result;
    }

    napi_value unpickle_account(napi_env env, napi_callback_info info) {
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        char * pickle;
        char * password;
        size_t pickle_len = 0;
        size_t password_len = 0;

        // get the pickle
        napi_status status = napi_get_value_string_utf8(env, argv[0], NULL, 0, & pickle_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid pickle size");
            return NULL;
        }

        pickle = (char * ) malloc(pickle_len);
        if (pickle == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate pickle buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[0], pickle, pickle_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid pickle");
            return NULL;
        }

        if (argc > 1) {
            // get the pickles password if provided
            napi_status status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & password_len);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password size");
                return NULL;
            }

            password = (char * ) malloc(password_len);
            if (password == NULL) {
                napi_throw_error(env, "ERROR", "Could not allocate pickle password buffer");
                return NULL;
            }

            status = napi_get_value_string_utf8(env, argv[1], password, password_len + 1, NULL);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password");
                return NULL;
            }
        }

        void * abuf = malloc(olm_account_size());

        if (abuf == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        OlmAccount * account = olm_account(abuf);

        olm_unpickle_account(
            account,
            password,
            password_len,
            pickle,
            pickle_len
        );

        if (password != NULL) {
            free(password);
        }

        free(pickle);

        napi_value aref;

        status = napi_create_external(env, account, NULL, NULL, & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm account reference");
            return NULL;
        }

        return aref;
    }

    napi_value create_account_one_time_keys(napi_env env, napi_callback_info info) {
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 2) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * aref;
        int32_t num_keys;

        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        status = napi_get_value_int32(env, argv[1], & num_keys);
        if (status != napi_ok) {
            napi_throw_error(env, "EINVAL", "Must specify number of keys to generate");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        size_t rand_len = olm_account_generate_one_time_keys_random_length(account, num_keys);

        void * rand = malloc(rand_len);

        if (rand == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        if (sodium_init() == -1) {
            napi_throw_error(env, "ERROR", "Sodium not ready");
            return NULL;
        }

        randombytes_buf(rand, rand_len);

        size_t ret = olm_account_generate_one_time_keys(account, num_keys, rand, rand_len);

        free(rand);

        if (ret != (size_t)(num_keys)) {
            napi_throw_error(env, "ERROR", olm_account_last_error(account));
            return NULL;
        }

        return NULL;
    }

    napi_value one_time_keys(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[1];
        size_t argc = 1;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * aref;

        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        size_t klen = olm_account_one_time_keys_length(account);

        void * keys = malloc(klen);

        if (keys == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        klen = olm_account_one_time_keys(account, keys, klen);

        if (klen < 1) {
            napi_throw_error(env, "ERROR", olm_account_last_error(account));
            return NULL;
        }

        status = napi_create_string_utf8(env, (const char * )(keys), klen, & result);

        free(keys);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account keys");
            return NULL;
        }

        return result;
    }

    napi_value identity_keys(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[1];
        size_t argc = 1;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * aref;

        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        size_t klen = olm_account_identity_keys_length(account);

        void * keys = malloc(klen);

        if (keys == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        klen = olm_account_identity_keys(account, keys, klen);

        if (klen < 1) {
            napi_throw_error(env, "ERROR", olm_account_last_error(account));
            return NULL;
        }

        status = napi_create_string_utf8(env, (const char * )(keys), klen, & result);

        free(keys);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account keys");
            return NULL;
        }

        return result;
    }

    napi_value remove_one_time_keys(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 2) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * sref;
        void * aref;

        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        status = napi_get_value_external(env, argv[1], & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm session");
            return NULL;
        }

        OlmSession * session = (OlmSession * )(sref);

        olm_remove_one_time_keys(account, session);

        const char * err = olm_account_last_error(account);
        if (strcmp(err, "SUCCESS") != 0) {
            napi_throw_error(env, "ERROR", err);
            return NULL;
        }

        return result;
    }

    napi_value create_outbound_session(napi_env env, napi_callback_info info) {
        napi_value argv[3];
        size_t argc = 3;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 3) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * aref;
        char * identity_key;
        char * one_time_key;
        size_t identity_key_len = 0;
        size_t one_time_key_len = 0;

        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        // get the size of the identity and one time keys
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & identity_key_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm identity key size");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[2], NULL, 0, & one_time_key_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm one time key size");
            return NULL;
        }

        // get the identity and one time keys
        identity_key = (char * ) malloc(identity_key_len);
        if (identity_key == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate identity key buffer");
            return NULL;
        }

        one_time_key = (char * ) malloc(one_time_key_len);
        if (one_time_key == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate one time key buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], identity_key, identity_key_len + 1, & identity_key_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm identity key");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[2], one_time_key, one_time_key_len + 1, & one_time_key_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm one time key");
            return NULL;
        }

        // allocate the session
        void * sbuf = malloc(olm_session_size());
        if (sbuf == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        OlmSession * session = olm_session(sbuf);

        // generate some random data
        size_t rand_len = olm_create_outbound_session_random_length(session);

        void * rand = malloc(rand_len);
        if (rand == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        if (sodium_init() == -1) {
            free(rand);
            free(identity_key);
            free(one_time_key);
            napi_throw_error(env, "ERROR", "Sodium not ready");
            return NULL;
        }

        randombytes_buf(rand, rand_len);

        olm_create_outbound_session(
            session,
            account,
            identity_key,
            identity_key_len,
            one_time_key,
            one_time_key_len,
            rand,
            rand_len
        );

        free(rand);
        free(identity_key);
        free(one_time_key);

        const char * serr = olm_session_last_error(session);
        if (strcmp(serr, "SUCCESS") != 0) {
            napi_throw_error(env, "ERROR", serr);
            return NULL;
        }

        napi_value sref;

        status = napi_create_external(env, session, NULL, NULL, & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm session reference");
            return NULL;
        }

        return sref;
    }

    napi_value create_inbound_session(napi_env env, napi_callback_info info) {
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 2) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * aref;
        char * ciphertext;
        size_t ciphertext_len = 0;

        napi_status status = napi_get_value_external(env, argv[0], & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account");
            return NULL;
        }

        OlmAccount * account = (OlmAccount * )(aref);

        // get the size of the ciphertext one time message
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & ciphertext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid one time message ciphertext size");
            return NULL;
        }

        // get the ciphertext one time message
        ciphertext = (char * ) malloc(ciphertext_len);
        if (ciphertext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate one time message ciphertext buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], ciphertext, ciphertext_len + 1, & ciphertext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid one time message ciphertext");
            return NULL;
        }

        // allocate the session
        void * sbuf = malloc(olm_session_size());
        if (sbuf == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        OlmSession * session = olm_session(sbuf);

        olm_create_inbound_session(
            session,
            account,
            ciphertext,
            ciphertext_len
        );

        const char * serr = olm_session_last_error(session);
        if (strcmp(serr, "SUCCESS") != 0) {
            napi_throw_error(env, "ERROR", serr);
            return NULL;
        }

        napi_value sref;

        status = napi_create_external(env, session, NULL, NULL, & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm session reference");
            return NULL;
        }

        return sref;
    }

    napi_value pickle_session(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * sref;
        char * pickle;
        char * password;
        size_t password_len = 0;

        // get the session
        napi_status status = napi_get_value_external(env, argv[0], & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm session");
            return NULL;
        }

        OlmSession * session = (OlmSession * )(sref);

        if (argc > 1) {
            // get the pickles password if provided
            napi_status status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & password_len);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password size");
                return NULL;
            }

            password = (char * ) malloc(password_len);
            if (password == NULL) {
                napi_throw_error(env, "ERROR", "Could not allocate pickle password buffer");
                return NULL;
            }

            status = napi_get_value_string_utf8(env, argv[1], password, password_len + 1, NULL);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password");
                return NULL;
            }
        }

        size_t pickle_len = olm_pickle_session_length(session);

        pickle = (char * ) malloc(pickle_len);
        if (pickle == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate pickle buffer");
            return NULL;
        }

        olm_pickle_session(
            session,
            password,
            password_len,
            pickle,
            pickle_len
        );

        if (password != NULL) {
            free(password);
        }

        status = napi_create_string_utf8(env, (const char * )(pickle), pickle_len, & result);

        free(pickle);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm session pickle");
            return NULL;
        }

        return result;
    }

    napi_value unpickle_session(napi_env env, napi_callback_info info) {
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        char * pickle;
        char * password;
        size_t pickle_len = 0;
        size_t password_len = 0;

        // get the pickle
        napi_status status = napi_get_value_string_utf8(env, argv[0], NULL, 0, & pickle_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid pickle size");
            return NULL;
        }

        pickle = (char * ) malloc(pickle_len);
        if (pickle == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate pickle buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[0], pickle, pickle_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid pickle");
            return NULL;
        }

        if (argc > 1) {
            // get the pickles password if provided
            napi_status status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & password_len);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password size");
                return NULL;
            }

            password = (char * ) malloc(password_len);
            if (password == NULL) {
                napi_throw_error(env, "ERROR", "Could not allocate pickle password buffer");
                return NULL;
            }

            status = napi_get_value_string_utf8(env, argv[1], password, password_len + 1, NULL);
            if (status != napi_ok) {
                napi_throw_error(env, "ERROR", "Invalid pickle password");
                return NULL;
            }
        }

        void * sbuf = malloc(olm_session_size());

        if (sbuf == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
            return NULL;
        }

        OlmSession * session = olm_session(sbuf);

        olm_unpickle_session(
            session,
            password,
            password_len,
            pickle,
            pickle_len
        );

        if (password != NULL) {
            free(password);
        }

        free(pickle);

        napi_value aref;

        status = napi_create_external(env, session, NULL, NULL, & aref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm session reference");
            return NULL;
        }

        return aref;
    }

    napi_value encrypt(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 2) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * sref;
        char * plaintext;
        size_t plaintext_len = 0;

        napi_status status = napi_get_value_external(env, argv[0], & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm session");
            return NULL;
        }

        OlmSession * session = (OlmSession * )(sref);

        // get the size of the identity and one time keys
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & plaintext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext size");
            return NULL;
        }

        // get the plaintext
        plaintext = (char * ) malloc(plaintext_len);
        if (plaintext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate plaintext buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], plaintext, plaintext_len + 1, & plaintext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext");
            return NULL;
        }

        size_t rand_len = olm_encrypt_random_length(session);
        size_t ciphertext_len = olm_encrypt_message_length(
            session,
            plaintext_len
        );

        const char * serr = olm_session_last_error(session);
        if (strcmp(serr, "SUCCESS") != 0) {
            napi_throw_error(env, "ERROR", serr);
            return NULL;
        }

        void * ciphertext = malloc(ciphertext_len);
        if (ciphertext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate ciphertext buffer");
            return NULL;
        }

        // generate some random data
        void * rand = malloc(rand_len);
        if (rand == NULL) {
            napi_throw_error(env, "ENOMEM", "Could not allocate ciphertext random memory");
            return NULL;
        }

        if (sodium_init() == -1) {
            napi_throw_error(env, "ERROR", "Sodium not ready");
            return NULL;
        }

        randombytes_buf(rand, rand_len);

        olm_encrypt(
            session,
            plaintext,
            plaintext_len,
            rand,
            rand_len,
            ciphertext,
            ciphertext_len
        );

        free(plaintext);
        free(rand);

        serr = olm_session_last_error(session);
        if (strcmp(serr, "SUCCESS") != 0) {
            free(ciphertext);
            napi_throw_error(env, "ERROR", serr);
            return NULL;
        }

        status = napi_create_string_utf8(env, (const char * )(ciphertext), ciphertext_len, & result);

        free(ciphertext);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm account keys");
            return NULL;
        }

        return result;
    }

    napi_value decrypt(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[3];
        size_t argc = 3;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 3) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * sref;
        char * ciphertext;
        char * ciphertext_copy;
        size_t ciphertext_len = 0;
        int32_t message_type = 0;

        napi_status status = napi_get_value_external(env, argv[0], & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm session");
            return NULL;
        }

        OlmSession * session = (OlmSession * )(sref);

        // get the size of the ciphertext
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & ciphertext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid ciphertext size");
            return NULL;
        }

        // get the ciphertext
        ciphertext = (char * ) malloc(ciphertext_len);
        if (ciphertext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate ciphertext buffer");
            return NULL;
        }

        ciphertext_copy = (char * ) malloc(ciphertext_len);
        if (ciphertext_copy == NULL) {
            free(ciphertext);
            napi_throw_error(env, "ERROR", "Could not allocate ciphertext Copy buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], ciphertext, ciphertext_len + 1, & ciphertext_len);
        if (status != napi_ok) {
            free(ciphertext);
            free(ciphertext_copy);
            napi_throw_error(env, "ERROR", "Invalid ciphertext");
            return NULL;
        }

        strcpy(ciphertext_copy, ciphertext);

        // get the message type
        status = napi_get_value_int32(env, argv[2], & message_type);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid Message Type Argument");
            return NULL;
        }

        size_t plaintext_len = olm_decrypt_max_plaintext_length(
            session,
            message_type,
            ciphertext_copy,
            ciphertext_len
        );

        const char * serr = olm_session_last_error(session);
        if (strcmp(serr, "SUCCESS") != 0) {
            free(ciphertext);
            free(ciphertext_copy);
            napi_throw_error(env, "ERROR", serr);
            return NULL;
        }

        void * plaintext = malloc(plaintext_len);
        if (plaintext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate plaintext buffer");
            return NULL;
        }

        plaintext_len = olm_decrypt(
            session,
            message_type,
            ciphertext,
            ciphertext_len,
            plaintext,
            plaintext_len
        );

        free(ciphertext);

        serr = olm_session_last_error(session);
        if (strcmp(serr, "SUCCESS") != 0) {
            free(plaintext);
            napi_throw_error(env, "ERROR", serr);
            return NULL;
        }

        status = napi_create_string_utf8(env, (const char * )(plaintext), plaintext_len, & result);

        free(plaintext);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext");
            return NULL;
        }

        return result;
    }

    napi_value create_group_session(napi_env env, napi_callback_info info) {
        napi_value argv[1];
        size_t argc = 1;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        char * identity;
        size_t identity_len = 0;

        // get the identity
        napi_status status = napi_get_value_string_utf8(env, argv[0], NULL, 0, & identity_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid Identity size");
            return NULL;
        }

        identity = (char * ) malloc(identity_len);
        if (identity == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate Identity buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[0], identity, identity_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid Identity");
            return NULL;
        }

        GroupSession * group_session = omemo_create_group_session();
        omemo_set_identity(group_session, identity);

        napi_value sref;

        status = napi_create_external(env, group_session, NULL, NULL, & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Could not create olm session reference");
            return NULL;
        }

        return sref;
    }

    napi_value destroy_group_session(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[1];
        size_t argc = 1;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * gsref;

        // get the group session
        napi_status status = napi_get_value_external(env, argv[0], & gsref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid group session");
            return NULL;
        }

        GroupSession * group_session = (GroupSession * )(gsref);

        omemo_destroy_group_session(group_session);

        return result;
    }

    napi_value add_group_participant(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[3];
        size_t argc = 3;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 3) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * sref;
        void * gsref;
        char * identity;
        size_t identity_len = 0;

        // get the group session
        napi_status status = napi_get_value_external(env, argv[0], & gsref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid group session");
            return NULL;
        }

        GroupSession * group_session = (GroupSession * )(gsref);

        // get the identity
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & identity_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid identity size");
            return NULL;
        }

        identity = (char * ) malloc(identity_len);
        if (identity == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate identity buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], identity, identity_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid identity");
            return NULL;
        }

        // get the olm session
        status = napi_get_value_external(env, argv[2], & sref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid olm session");
            return NULL;
        }

        OlmSession * session = (OlmSession * )(sref);

        omemo_add_group_participant(group_session, identity, session);

        return result;
    }

    napi_value group_encrypt(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[2];
        size_t argc = 2;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 2) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * gsref;
        uint8_t * plaintext;
        size_t plaintext_len = 0;

        // get the group session
        napi_status status = napi_get_value_external(env, argv[0], & gsref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid group session");
            return NULL;
        }

        GroupSession * group_session = (GroupSession * )(gsref);

        // get the plaintext
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & plaintext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext size");
            return NULL;
        }

        plaintext = (uint8_t * ) malloc(plaintext_len);
        if (plaintext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate plaintext buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], (char * )(plaintext), plaintext_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext");
            return NULL;
        }

        size_t ciphertext_len = omemo_encrypted_size(group_session, plaintext_len);

        uint8_t * ciphertext = (uint8_t * ) malloc(ciphertext_len);
        if (ciphertext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate ciphertext buffer");
            return NULL;
        }

        ciphertext_len = omemo_encrypt(
            group_session,
            plaintext,
            plaintext_len,
            ciphertext,
            ciphertext_len
        );

        free(plaintext);

        if (ciphertext_len <= 0) {
            free(ciphertext);
            napi_throw_error(env, "ERROR", "Could not group encrypt message");
            return NULL;
        }

        status = napi_create_string_utf8(env, (const char * )(ciphertext), ciphertext_len, & result);

        free(ciphertext);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext");
            return NULL;
        }

        return result;
    }

    napi_value group_decrypt(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[3];
        size_t argc = 3;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 3) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        void * gsref;
        char * sender;
        uint8_t * ciphertext;
        size_t sender_len;
        size_t ciphertext_len = 0;

        // get the group session
        napi_status status = napi_get_value_external(env, argv[0], & gsref);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid group session");
            return NULL;
        }

        GroupSession * group_session = (GroupSession * )(gsref);

        // get the senders id
        status = napi_get_value_string_utf8(env, argv[1], NULL, 0, & sender_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid sender size");
            return NULL;
        }

        sender = (char * ) malloc(sender_len);
        if (sender == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate sender buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[1], sender, sender_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid sender");
            return NULL;
        }

        // get the ciphertext
        status = napi_get_value_string_utf8(env, argv[2], NULL, 0, & ciphertext_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid ciphertext size");
            return NULL;
        }

        ciphertext = (uint8_t * ) malloc(ciphertext_len);
        if (ciphertext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate ciphertext buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[2], (char * )(ciphertext), ciphertext_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext");
            return NULL;
        }

        size_t plaintext_len = omemo_decrypted_size(group_session, ciphertext, ciphertext_len);

        uint8_t * plaintext = (uint8_t * ) malloc(plaintext_len);
        if (plaintext == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate plaintext buffer");
            return NULL;
        }

        plaintext_len = omemo_decrypt(
            group_session,
            sender,
            plaintext,
            plaintext_len,
            ciphertext,
            ciphertext_len
        );

        free(ciphertext);
        free(sender);

        if (plaintext_len <= 0) {
            free(plaintext);
            napi_throw_error(env, "ERROR", "Could not group decrypt message");
            return NULL;
        }

        status = napi_create_string_utf8(env, (const char * )(plaintext), plaintext_len, & result);

        free(plaintext);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid plaintext");
            return NULL;
        }

        return result;
    }

    napi_value ed25519_pk_to_curve25519(napi_env env, napi_callback_info info) {
        napi_value result;
        napi_value argv[1];
        size_t argc = 1;

        napi_get_cb_info(env, info, & argc, argv, NULL, NULL);

        if (argc < 1) {
            napi_throw_error(env, "EINVAL", "Too few arguments");
            return NULL;
        }

        uint8_t * ed25519_pk;
        char * encoded_ed25519_pk;
        size_t encoded_ed25519_pk_len = 0;

        // get the ed25519 key
        napi_status status = napi_get_value_string_utf8(env, argv[0], NULL, 0, & encoded_ed25519_pk_len);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid ed25519 public key size");
            return NULL;
        }

        encoded_ed25519_pk = (char * ) malloc(encoded_ed25519_pk_len);
        if (encoded_ed25519_pk == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate ed25519 public key buffer");
            return NULL;
        }

        status = napi_get_value_string_utf8(env, argv[0], (char * )(encoded_ed25519_pk), encoded_ed25519_pk_len + 1, NULL);
        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid ed25519 public key");
            return NULL;
        }

        // decode the ed25519 pk
        size_t ed25519_pk_len = crypto_sign_publickeybytes();

        if ((ed25519_pk = (uint8_t * ) malloc(ed25519_pk_len)) == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate ed25519 public key");
            return NULL;
        }

        size_t success = sodium_base642bin(
            ed25519_pk,
            ed25519_pk_len,
            encoded_ed25519_pk,
            encoded_ed25519_pk_len,
            NULL, &
            ed25519_pk_len,
            NULL,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        );

        free(encoded_ed25519_pk);

        if (success != 0) {
            free(ed25519_pk);
            napi_throw_error(env, "ERROR", "Could not decode ed25519 public key");
            return NULL;
        }

        uint8_t * curve25519_pk;
        char * encoded_curve25519_pk;
        size_t encoded_curve25519_pk_len;

        size_t curve25519_pk_len = crypto_sign_publickeybytes();

        if ((curve25519_pk = (uint8_t * ) malloc(curve25519_pk_len)) == NULL) {
            napi_throw_error(env, "ERROR", "Could not allocate curve25519 public key");
            return NULL;
        }

        success = crypto_sign_ed25519_pk_to_curve25519(
            curve25519_pk,
            ed25519_pk
        );

        free(ed25519_pk);

        if (success != 0) {
            free(curve25519_pk);
            napi_throw_error(env, "ERROR", "Could not convert ed25519 public key to curve25519 public key");
            return NULL;
        }

        encoded_curve25519_pk_len = sodium_base64_ENCODED_LEN(
            curve25519_pk_len,
            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
        );

        if ((encoded_curve25519_pk = (char * ) malloc(encoded_curve25519_pk_len)) == NULL) {
            free(curve25519_pk);
            napi_throw_error(env, "ERROR", "Could not allocate memory for encoded curve25519 public key");
            return NULL;
        }

        sodium_bin2base64(
            encoded_curve25519_pk,
            encoded_curve25519_pk_len,
            curve25519_pk,
            curve25519_pk_len,
            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
        );

        free(curve25519_pk);

        status = napi_create_string_utf8(env, (const char * )(encoded_curve25519_pk), encoded_curve25519_pk_len-1, & result);

        free(encoded_curve25519_pk);

        if (status != napi_ok) {
            napi_throw_error(env, "ERROR", "Invalid encoded curve25519 public key");
            return NULL;
        }

        return result;
    }

    napi_value init_all(napi_env env, napi_value exports) {
        napi_value create_account_fn;
        napi_value create_olm_account_derrived_keys_fn;
        napi_value pickle_account_fn;
        napi_value unpickle_account_fn;
        napi_value create_account_one_time_keys_fn;
        napi_value one_time_keys_fn;
        napi_value identity_keys_fn;
        napi_value remove_one_time_keys_fn;
        napi_value create_outbound_session_fn;
        napi_value create_inbound_session_fn;
        napi_value pickle_session_fn;
        napi_value unpickle_session_fn;
        napi_value encrypt_fn;
        napi_value decrypt_fn;
        napi_value create_group_session_fn;
        napi_value destroy_group_session_fn;
        napi_value add_group_participant_fn;
        napi_value group_encrypt_fn;
        napi_value group_decrypt_fn;
        napi_value ed25519_pk_to_curve25519_fn;

        napi_create_function(env, NULL, 0, create_olm_account, NULL, & create_account_fn);
        napi_set_named_property(env, exports, "create_olm_account", create_account_fn);

        napi_create_function(env, NULL, 0, create_olm_account_derrived_keys, NULL, & create_olm_account_derrived_keys_fn);
        napi_set_named_property(env, exports, "create_olm_account_derrived_keys", create_olm_account_derrived_keys_fn);

        napi_create_function(env, NULL, 0, create_account_one_time_keys, NULL, & create_account_one_time_keys_fn);
        napi_set_named_property(env, exports, "create_account_one_time_keys", create_account_one_time_keys_fn);

        napi_create_function(env, NULL, 0, pickle_account, NULL, & pickle_account_fn);
        napi_set_named_property(env, exports, "pickle_account", pickle_account_fn);

        napi_create_function(env, NULL, 0, unpickle_account, NULL, & unpickle_account_fn);
        napi_set_named_property(env, exports, "unpickle_account", unpickle_account_fn);

        napi_create_function(env, NULL, 0, one_time_keys, NULL, & one_time_keys_fn);
        napi_set_named_property(env, exports, "one_time_keys", one_time_keys_fn);

        napi_create_function(env, NULL, 0, identity_keys, NULL, & identity_keys_fn);
        napi_set_named_property(env, exports, "identity_keys", identity_keys_fn);

        napi_create_function(env, NULL, 0, remove_one_time_keys, NULL, & remove_one_time_keys_fn);
        napi_set_named_property(env, exports, "remove_one_time_keys", remove_one_time_keys_fn);

        napi_create_function(env, NULL, 0, create_outbound_session, NULL, & create_outbound_session_fn);
        napi_set_named_property(env, exports, "create_outbound_session", create_outbound_session_fn);

        napi_create_function(env, NULL, 0, create_inbound_session, NULL, & create_inbound_session_fn);
        napi_set_named_property(env, exports, "create_inbound_session", create_inbound_session_fn);

        napi_create_function(env, NULL, 0, pickle_session, NULL, & pickle_session_fn);
        napi_set_named_property(env, exports, "pickle_session", pickle_session_fn);

        napi_create_function(env, NULL, 0, unpickle_session, NULL, & unpickle_session_fn);
        napi_set_named_property(env, exports, "unpickle_session", unpickle_session_fn);

        napi_create_function(env, NULL, 0, encrypt, NULL, & encrypt_fn);
        napi_set_named_property(env, exports, "encrypt", encrypt_fn);

        napi_create_function(env, NULL, 0, decrypt, NULL, & decrypt_fn);
        napi_set_named_property(env, exports, "decrypt", decrypt_fn);

        napi_create_function(env, NULL, 0, create_group_session, NULL, & create_group_session_fn);
        napi_set_named_property(env, exports, "create_group_session", create_group_session_fn);

        napi_create_function(env, NULL, 0, destroy_group_session, NULL, & destroy_group_session_fn);
        napi_set_named_property(env, exports, "destroy_group_session", destroy_group_session_fn);

        napi_create_function(env, NULL, 0, add_group_participant, NULL, & add_group_participant_fn);
        napi_set_named_property(env, exports, "add_group_participant", add_group_participant_fn);

        napi_create_function(env, NULL, 0, group_encrypt, NULL, & group_encrypt_fn);
        napi_set_named_property(env, exports, "group_encrypt", group_encrypt_fn);

        napi_create_function(env, NULL, 0, group_decrypt, NULL, & group_decrypt_fn);
        napi_set_named_property(env, exports, "group_decrypt", group_decrypt_fn);

        napi_create_function(env, NULL, 0, ed25519_pk_to_curve25519, NULL, & ed25519_pk_to_curve25519_fn);
        napi_set_named_property(env, exports, "ed25519_pk_to_curve25519", ed25519_pk_to_curve25519_fn);

        return exports;
    }

    NAPI_MODULE(NODE_GYP_MODULE_NAME, init_all)
}