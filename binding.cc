#include <node_api.h>
#include <stdio.h>
#include <sodium.h>
#include <self_olm/olm.h>

namespace self_crypto {

  napi_value create_olm_account(napi_env env, napi_callback_info info) {
    napi_value argv[1];
    size_t argc = 1;

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    if (argc < 1) {
      napi_throw_error(env, "EINVAL", "Too few arguments");
      return NULL;
    }

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

    return account;
  }


  napi_value init_all (napi_env env, napi_value exports) {
    napi_value olm_create_account_fn;
    napi_create_function(env, NULL, 0, create_olm_account, NULL, &olm_create_account_fn);
    napi_set_named_property(env, exports, "create_olm_account", olm_create_account_fn);
    return exports;
  }

  NAPI_MODULE(NODE_GYP_MODULE_NAME, init_all)
}

