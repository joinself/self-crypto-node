// Copyright 2020 Self Group Ltd. All Rights Reserved.

var self_crypto = require('./')

var account = self_crypto.create_olm_account();
console.log(account);

self_crypto.create_account_prekeys(account, 1);

