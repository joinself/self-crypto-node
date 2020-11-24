var self_crypto = require('./')

var account = self_crypto.create_olm_account();
console.log(account);

self_crypto.create_account_prekeys(account, 1);

