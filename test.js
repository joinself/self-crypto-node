// Copyright 2020 Self Group Ltd. All Rights Reserved.

var self_crypto = require('./')

var account = self_crypto.create_olm_account();

console.log(self_crypto.create_account_one_time_keys(account, 100));

var keys = self_crypto.one_time_keys(account);
console.log(keys);

var id_keys = self_crypto.identity_keys(account);
console.log(id_keys);

var session = self_crypto.create_outbound_session(account, "gliSBuE/PavNATcg8rEcjLKRkhvQHxsZFfm3m4yBdjA", "oC+cAFahU532Bnm/NtN/nWPAln7J67eDYxt33MvEmxA");
console.log(session);

console.log(self_crypto.encrypt(session, "hello there"));