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
self_crypto.add_group_participant(group_session_with_bob, "bob", bob_session);

// encrypt some data for bob in a group message
var group_ciphertext_for_bob = self_crypto.group_encrypt(group_session_with_bob, "hello bob and other group members");
console.log(group_ciphertext_for_bob);

// create a group session with alice
var group_session_with_alice = self_crypto.create_group_session("bob");
self_crypto.add_group_participant(group_session_with_alice, "alice", alice_session);

// decrypt the group message from alice
var group_plaintext_for_bob = self_crypto.group_decrypt(group_session_with_alice, "alice", group_ciphertext_for_bob);
console.log(group_plaintext_for_bob);

var charlie_account = self_crypto.create_olm_account_derrived_keys("uUG4E51Hv5k4QH5lgF+5CG44SsxGz/PlM1phmLc2eqE");
console.log(self_crypto.identity_keys(charlie_account));

// pickle an account
var alice_account_pickle = self_crypto.pickle_account(alice_account);
console.log(alice_account_pickle);

// pickle an account with password
var alice_account_pickle = self_crypto.pickle_account(alice_account, "password");
console.log(alice_account_pickle);

var alice_unpickled_account = self_crypto.unpickle_account(alice_account_pickle, "password");
console.log(self_crypto.identity_keys(alice_unpickled_account));

// pickle a session
var alice_session_pickle = self_crypto.pickle_session(alice_session, "password");
var session_with_alice_unpickled = self_crypto.unpickle_session(alice_session_pickle, "password");

// convert a key
var charlie_identity_keys_json = self_crypto.identity_keys(charlie_account);
var charlie_identity_keys = JSON.parse(charlie_identity_keys_json);

console.log(charlie_identity_keys["curve25519"])

// fails as self uses URLSAFE encoded keys, whereas olm returns keys encoded with a normal base64 variant
var charlie_curve25519_pk = self_crypto.ed25519_pk_to_curve25519(charlie_identity_keys["ed25519"])
console.log(charlie_curve25519_pk);
