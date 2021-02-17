// Copyright 2020 Self Group Ltd. All Rights Reserved.

var self_crypto = require('./')

// setup the two accounts
var alice_account = self_crypto.create_olm_account();
var bob_account = self_crypto.create_olm_account();

// get bob's identity keys
var bobs_identity_keys = self_crypto.identity_keys(bob_account);
var bobs_identity_keys_json = JSON.parse(bobs_identity_keys);

// generate some one time keys for bob
self_crypto.create_account_one_time_keys(bob_account, 100);
var bobs_one_time_keys = self_crypto.one_time_keys(bob_account);
var bobs_one_time_keys_json = JSON.parse(bobs_one_time_keys);

// create a session from alice to bob
var bob_session = self_crypto.create_outbound_session(alice_account, bobs_identity_keys_json["curve25519"], bobs_one_time_keys_json["curve25519"]["AAAAAQ"]);
var ciphertext_for_bob = self_crypto.encrypt(bob_session, "hello from alice");

// create a session to bob from alice
var alice_session = self_crypto.create_inbound_session(bob_account, ciphertext_for_bob);
var plaintext_for_bob = self_crypto.decrypt(alice_session, ciphertext_for_bob, 0);

console.log(plaintext_for_bob);


// create a group session

var group_session_with_bob = self_crypto.create_group_session("alice");
console.log(group_session_with_bob);

self_crypto.add_group_participant(group_session_with_bob, "bob", bob_session);

var group_ciphertext_for_bob = self_crypto.group_encrypt(group_session_with_bob, "hello bob and other group members");
console.log(group_ciphertext_for_bob);