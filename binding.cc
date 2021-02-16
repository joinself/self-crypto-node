// Copyright 2020 Self Group Ltd. All Rights Reserved.

#include <node_api.h>
#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <self_olm/olm.h>

namespace self_crypto {

  napi_value create_olm_account(napi_env env, napi_callback_info info) {
    if (sodium_init() == -1) {
      napi_throw_error(env, "ENOMEM", "Sodium not ready");
      return NULL;
    }

    void *abuf = malloc(olm_account_size()); 
    
    if (abuf == NULL) {
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    OlmAccount *account = olm_account(abuf);

    size_t rlen = olm_create_account_random_length(account);

    void *rand = malloc(rlen); 

    if (rand == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    if (sodium_init() == -1) {
      napi_throw_error(env, "ERROR", "Sodium not ready");
      return NULL;
    }

    randombytes_buf(rand, rlen);

    if (olm_create_account(account, rand, rlen) != 0) {
      napi_throw_error(env, "ERROR", "Could not create olm account");
      return NULL;
    }

    free(rand);

    napi_value aref;

    napi_status status = napi_create_external(env, account, NULL, NULL, &aref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Could not create olm account reference");
      return NULL;
    }

    return aref;
  }

  napi_value create_account_one_time_keys(napi_env env, napi_callback_info info) {
    napi_value argv[2];
    size_t argc = 2;

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    if (argc < 2) {
      napi_throw_error(env, "EINVAL", "Too few arguments");
      return NULL;
    }

    void *aref;
    int32_t num_keys;

    napi_status status = napi_get_value_external(env, argv[0], &aref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account");
      return NULL;
    }

    status = napi_get_value_int32(env, argv[1], &num_keys);
     if (status != napi_ok) {
      napi_throw_error(env, "EINVAL", "Must specify number of keys to generate");
      return NULL;
    }

    OlmAccount *account = (OlmAccount*)(aref);

    size_t rlen = olm_account_generate_one_time_keys_random_length(account, num_keys);

    void *rand = malloc(rlen); 

    if (rand == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    if (sodium_init() == -1) {
      napi_throw_error(env, "ERROR", "Sodium not ready");
      return NULL;
    }

    randombytes_buf(rand, rlen);

    size_t ret = olm_account_generate_one_time_keys(account, num_keys, rand, rlen);

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

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    if (argc < 1) {
      napi_throw_error(env, "EINVAL", "Too few arguments");
      return NULL;
    }

    void *aref;

    napi_status status = napi_get_value_external(env, argv[0], &aref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account");
      return NULL;
    }

    OlmAccount *account = (OlmAccount*)(aref);

    size_t klen = olm_account_one_time_keys_length(account);

    void *keys = malloc(klen); 

    if (keys == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    klen = olm_account_one_time_keys(account, keys, klen);

    if (klen < 1) {
      napi_throw_error(env, "ERROR", olm_account_last_error(account));
      return NULL;
    }

    status = napi_create_string_utf8(env, (const char*)(keys), klen, &result);

    free(keys);

    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account Keys");
      return NULL;
    }

    return result;
  }

  napi_value identity_keys(napi_env env, napi_callback_info info) {
    napi_value result;
    napi_value argv[1];
    size_t argc = 1;

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    if (argc < 1) {
      napi_throw_error(env, "EINVAL", "Too few arguments");
      return NULL;
    }

    void *aref;

    napi_status status = napi_get_value_external(env, argv[0], &aref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account");
      return NULL;
    }

    OlmAccount *account = (OlmAccount*)(aref);

    size_t klen = olm_account_identity_keys_length(account);

    void *keys = malloc(klen); 

    if (keys == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    klen = olm_account_identity_keys(account, keys, klen);

    if (klen < 1) {
      napi_throw_error(env, "ERROR", olm_account_last_error(account));
      return NULL;
    }

    status = napi_create_string_utf8(env, (const char*)(keys), klen, &result);

    free(keys);

    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account Keys");
      return NULL;
    }

    return result;
  }

  napi_value remove_one_time_keys(napi_env env, napi_callback_info info) {
    napi_value result;
    napi_value argv[2];
    size_t argc = 2;

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    if (argc < 2) {
      napi_throw_error(env, "EINVAL", "Too few arguments");
      return NULL;
    }

    void *sref;
    void *aref;

    napi_status status = napi_get_value_external(env, argv[0], &aref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account");
      return NULL;
    }

    OlmAccount *account = (OlmAccount*)(aref);

    status = napi_get_value_external(env, argv[1], &sref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Session");
      return NULL;
    }

    OlmSession *session = (OlmSession*)(sref);

    olm_remove_one_time_keys(account, session);

    const char *err = olm_account_last_error(account);
    if (strcmp(err, "SUCCESS") != 0) {
      napi_throw_error(env, "ERROR", err);
      return NULL;
    }

    return result;
  }

  napi_value create_outbound_session(napi_env env, napi_callback_info info) {
    napi_value argv[3];
    size_t argc = 3;

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    if (argc < 3) {
      napi_throw_error(env, "EINVAL", "Too few arguments");
      return NULL;
    }

    void *aref;
    char *identity_key;
    char *one_time_key;
    size_t identity_key_len = 0;
    size_t one_time_key_len = 0;

    napi_status status = napi_get_value_external(env, argv[0], &aref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Account");
      return NULL;
    }

    OlmAccount *account = (OlmAccount*)(aref);

    const char *aerr = olm_account_last_error(account);
    if (strcmp(aerr, "SUCCESS") != 0) {
      napi_throw_error(env, "ERROR", aerr);
      return NULL;
    }

    // get the size of the identity and one time keys
    status = napi_get_value_string_utf8(env, argv[1], NULL, 0, &identity_key_len);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Identity Key Size");
      return NULL;
    }

    status = napi_get_value_string_utf8(env, argv[2], NULL, 0, &one_time_key_len);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm One Time Key Size");
      return NULL;
    }
    
    // get the identity and one time keys
    identity_key = (char *)malloc(identity_key_len);
    if (identity_key == NULL) {
      napi_throw_error(env, "ERROR", "Could not allocate Identity Key buffer");
      return NULL;
    }

    one_time_key = (char *)malloc(one_time_key_len);
    if (one_time_key == NULL) {
      napi_throw_error(env, "ERROR", "Could not allocate One Time Key buffer");
      return NULL;
    }

    status = napi_get_value_string_utf8(env, argv[1], identity_key, identity_key_len, NULL);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm Identity Key");
      return NULL;
    }

    status = napi_get_value_string_utf8(env, argv[2], one_time_key, one_time_key_len, NULL);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Invalid Olm One Time Key");
      return NULL;
    }

    void *sbuf = malloc(olm_session_size());
    if (sbuf == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

	  OlmSession *session = olm_session(sbuf);
    
    // generate some random data
    size_t rlen = olm_create_outbound_session_random_length(session);

    void *rand = malloc(rlen); 
    if (rand == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    if (sodium_init() == -1) {
      napi_throw_error(env, "ERROR", "Sodium not ready");
      return NULL;
    }

    /*
      TODO : are values being trimmed?
      printf("%s\n", identity_key);
      printf("%s\n", one_time_key);
    */

    randombytes_buf(rand, rlen);

    olm_create_outbound_session(
		  session,
		  account,
		  identity_key,
		  identity_key_len,
		  one_time_key,
		  one_time_key_len,
		  rand,
		  rlen
	  );

    free(rand);
    free(identity_key);
    free(one_time_key);

    const char *serr = olm_session_last_error(session);
    if (strcmp(serr, "SUCCESS") != 0) {
      napi_throw_error(env, "ERROR", serr);
      return NULL;
    }

    napi_value sref;

    status = napi_create_external(env, session, NULL, NULL, &sref);
    if (status != napi_ok) {
      napi_throw_error(env, "ERROR", "Could not create olm session reference");
      return NULL;
    }

    return sref;
  }

  napi_value init_all (napi_env env, napi_value exports) {
    napi_value create_account_fn;
    napi_value create_account_one_time_keys_fn;
    napi_value one_time_keys_fn;
    napi_value identity_keys_fn;
    napi_value remove_one_time_keys_fn;
    napi_value create_outbound_session_fn;

    napi_create_function(env, NULL, 0, create_olm_account, NULL, &create_account_fn);
    napi_set_named_property(env, exports, "create_olm_account", create_account_fn);
    
    napi_create_function(env, NULL, 0, create_account_one_time_keys, NULL, &create_account_one_time_keys_fn);
    napi_set_named_property(env, exports, "create_account_one_time_keys", create_account_one_time_keys_fn);
    
    napi_create_function(env, NULL, 0, one_time_keys, NULL, &one_time_keys_fn);
    napi_set_named_property(env, exports, "one_time_keys", one_time_keys_fn);

    napi_create_function(env, NULL, 0, identity_keys, NULL, &identity_keys_fn);
    napi_set_named_property(env, exports, "identity_keys", identity_keys_fn);

    napi_create_function(env, NULL, 0, remove_one_time_keys, NULL, &remove_one_time_keys_fn);
    napi_set_named_property(env, exports, "remove_one_time_keys", remove_one_time_keys_fn);

    napi_create_function(env, NULL, 0, create_outbound_session, NULL, &create_outbound_session_fn);
    napi_set_named_property(env, exports, "create_outbound_session", create_outbound_session_fn);

    return exports;
  }

  NAPI_MODULE(NODE_GYP_MODULE_NAME, init_all)
}

