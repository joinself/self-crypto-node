// Copyright 2020 Self Group Ltd. All Rights Reserved.

var self_crypto = require('./')

var account = self_crypto.create_olm_account();

console.log(self_crypto.create_account_one_time_keys(account, 100));

var keys = self_crypto.one_time_keys(account);
console.log(keys);
