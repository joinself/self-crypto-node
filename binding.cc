#include <node_api.h>
#include <stdio.h>
#include <sodium.h>
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

  napi_value create_account_prekeys(napi_env env, napi_callback_info info) {
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

    OlmAccount *account = olm_account(aref);

    size_t rlen = olm_account_generate_one_time_keys_random_length(account, num_keys);

    void *rand = malloc(rlen); 

    if (rand == NULL){
      napi_throw_error(env, "ENOMEM", "Could not allocate account memory");
      return NULL;
    }

    if (olm_account_generate_one_time_keys(account, num_keys, rand, rlen) != 0) {
      napi_throw_error(env, "ERROR", olm_account_last_error(account));
      return NULL;
    }
    
    return NULL;
  }


  napi_value init_all (napi_env env, napi_value exports) {
    napi_value olm_create_account_fn;
    napi_value create_account_prekeys_fn;

    napi_create_function(env, NULL, 0, create_olm_account, NULL, &olm_create_account_fn);
    napi_set_named_property(env, exports, "create_olm_account", olm_create_account_fn);
    
    napi_create_function(env, NULL, 0, create_account_prekeys, NULL, &create_account_prekeys_fn);
    napi_set_named_property(env, exports, "create_account_prekeys", create_account_prekeys_fn);
    

    return exports;
  }

  NAPI_MODULE(NODE_GYP_MODULE_NAME, init_all)
}

