use hashbrown::HashMap;
 
use hex_literal::hex;
//use ::hkdf::Hkdf;
//use hmac::{Hmac, Mac};
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptTrait};
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::ScalarPrimitive;
use p256::{self, NistP256, PublicKey, SecretKey};
// use p256::{ecdh, ecdsa, NistP256, NonZeroScalar};
// use p256::{ecdh::EphemeralSecret, EncodedPoint, ecdsa::PubKey};
use rand_core::{RngCore, OsRng};
use sha2::{Digest, Sha256};


//this section allows use of the functions in the above folders
use super::Hash256;
use super::aes256;
use super::cbc;
use super::ecdh;
use super::ecdsa;
use super::hkdf;
use super::hmac;
use super::sha256;
use super::util;

//use super::Hash256 as Sha256;
use alloc::string::String;
use crate::alloc::vec::Vec;
use crate::alloc::borrow::ToOwned;
use crate::alloc::string::ToString;


#[derive(Clone, Debug)]
struct YK { //YK stands for YubiKey
    backup_keys: Vec<ecdsa::PubKey>,
    backup_public: ecdsa::PubKey,
    backup_private: SecretKey,
    master: MagicCrypt256,
    login_keys: Vec<ecdsa::PubKey>,
    recovery_credentials_state: u32,
}

#[derive(Clone, Debug)]
struct Account {
    username: String,
    login: (ecdsa::PubKey, Vec<u8>),
    backups: HashMap<Vec<u8>, ecdsa::PubKey>,
    recovery_credentials_state: u32,
}

#[derive(Clone, Debug)]
struct RP {
    accounts: HashMap<String, Account>, //the map is {cred_ids, B}
    rp_id: [u8; 8],
}


 




//////////////////////////////////////////////////////SETUP////////////////////////////////////////////////////////

pub fn initialize_key() -> YK {
    //Creates a new key with a random master key and a random backup key.
    ////println!("Initializing key");
    let mut random = OsRng;
    let mut master_key = [0u8; 32];
    random.fill_bytes(&mut master_key);
    let backup = SecretKey::random(&mut OsRng);
    YK {
        backup_keys: Vec::<ecdsa::PubKey>::new(),
        backup_public: backup.genpk(),
        backup_private: backup,
        master: new_magic_crypt!(&master_key, 256),
        login_keys: Vec::<ecdsa::PubKey>::new(),
        recovery_credentials_state: 0,
    }
}

pub fn hkdf_primary(private_key: &EphemeralSecret, public_key: ecdsa::PubKey, info: &[u8; 26]) -> [u8; 32] 
{
    //Uses an ephemeral secret and a public key for diffie hellman key agreement, then
    //runs the shared secret through hkdf.
    let shared_secret = private_key.diffie_hellman(&public_key);
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut hkdf_try = [0u8; 32];
    hkdf::hkdf_256::<sha256::Sha256>(&shared_secret.raw_secret_bytes(), &salt, info, &mut hkdf_try);
    hkdf_try
}

pub fn hkdf_backup(private_key: &SecretKey, public_key: ecdsa::PubKey, info: &[u8; 26]) -> [u8; 32] {
    //Uses a secret key and a public key for diffie hellman key agreement, then
    //runs the shared secret through hkdf. Different from hkdf_primary because it
    //uses a secret key instead of an ephemeral secret. This is called by the backup
    //when recovering credentials.
    ////println!("Running hkdf_backup");
    let shared_secret =
        p256::ecdh::diffie_hellman(private_key.to_nonzero_scalar(), public_key.as_affine());
    let salt = [0u8; 32];
    let mut hkdf_new = [0u8; 32];
    hkdf::hkdf_256::<sha256::Sha256>( &shared_secret.raw_secret_bytes(), &salt, info, &mut hkdf_new);
    hkdf_new
}

pub fn mac(key: [u8; 32], data: &[u8]) -> [u8; 32] {
    //Takes a key and some data and makes a MAC with it.
    ////println!("Running mac");
    let mut hmac_result = [0u8; 32];
    hmac::hmac_256::<sha256::Sha256>(&key, data, &mut hmac_result);
    hmac_result
}






///////////////////////////////////////////////////////STEP 1/////////////////////////////////////////////////////////////

    //PRIMARY <- BACKUP

pub fn import_backup_key(primary_authenticator: &mut YK, backup_authenticator: &mut YK) {
    //println!("Importing backup key");
    primary_authenticator
        .backup_keys
        .push(backup_authenticator.backup_public);
    primary_authenticator.recovery_credentials_state += 1;
}





/////////////////////////////////////////////////////////////STEP 2//////////////////////////////////////////////////////

    //RP

pub fn initialize_rp(id: &[u8; 8]) -> RP {
    //println!("Initializing RP");
    RP {
        accounts: HashMap::<String, Account>::new(),
        rp_id: id.to_owned(),
    }
}


    //PRIMARY

pub fn register(userid: String, key: &mut YK, relying_party: &mut RP) {
    //Creates an account and sends it to the relying party.
    //println!("Registering");
    relying_party.accounts.insert(
        userid.to_owned(),
        make_account(userid, key, &relying_party.rp_id),
    );
}
    //all functions in this block are called by register
    pub fn make_account(userid: String, key: &mut YK, rp_id: &[u8; 8]) -> Account {
        //Create an account for the relying party with userid as the username
        //and the relevant data from the key.
        //println!("Making account");
        //let private_key = SecretKey::random(&mut OsRng);
        let private_key = ecdsa::SecKey::gensk(&mut OsRng);
        let public_key = ecdsa::SecKey::genpk(&private_key);
        let mut private_key_bytes = [0u8; 32];
        private_key.to_bytes(&mut private_key_bytes);
        let credential = key.master.encrypt_bytes_to_bytes(&private_key_bytes);
        key.login_keys.push(public_key);
        ////println!("key : {:?}", key.clone().backup_public);
        Account {
            username: userid,
            login: (public_key, credential),
            backups: make_backup_credential_list(&key.clone(), rp_id),
            recovery_credentials_state: key.recovery_credentials_state.clone(),
        }
    }

    pub fn make_backup_credential_list(primary_key: &YK, rp_id: &[u8; 8]) -> HashMap<Vec<u8>, ecdsa::PubKey> {
        //Create a backup credential for each backup key that primary_key is associated
        //with. Return a hashmap that has the credential_ids paired with the credential
        //public keys.
        //println!("Making backup credential list");
        let mut backup_credential_list: HashMap<Vec<u8>, ecdsa::PubKey> = HashMap::new();
        for key in primary_key.backup_keys.clone() {
            let credential = make_backup_credential(key, rp_id);
            backup_credential_list.insert(credential.0, credential.1);
        }
        backup_credential_list
    }

    pub fn make_backup_credential(backup_key: ecdsa::PubKey, rp_id: &[u8; 8]) -> (Vec<u8>, ecdsa::PubKey) {
        //Generate an ephemeral key pair for use in diffie-hellman
        //println!("Making backup credential");
        let ephemeral_private = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral_private.public_key();
    
        //Generate cred_key and mac_key
        let cred_key = make_cred_key(&ephemeral_private, backup_key);
        let mac_key = make_mac_key(&ephemeral_private, backup_key);
    
        //Generate credential public key and credential id
        let cred_id = make_cred_id(&ephemeral_public, mac_key, rp_id);
        let credential_public_key = make_backup_credential_public_key(cred_key, backup_key);
    
        (cred_id, credential_public_key)
    }
        //all functions in this block are called by make_backup_credential
        pub fn make_cred_key(private_key: &EphemeralSecret, public_key: ecdsa::PubKey) -> [u8; 32] 
        {
            //Calls hkdf with correct info to produce cred_key
            //println!("Making cred key");
            hkdf_primary(private_key, public_key, b"webauthn.recovery.cred_key")
        }
    
        pub fn make_mac_key(private_key: &EphemeralSecret, public_key: ecdsa::PubKey) -> [u8; 32] 
        {
            //Calls hkdf with correct info to produce mac_key
            ////println!("Making mac key");
            hkdf_primary(private_key, public_key, b"webauthn.recovery.mac_key.")
        }
    
        pub fn make_cred_id(E: &ecdsa::PubKey, mac_key: [u8; 32], rp_id: &[u8; 8]) -> Vec<u8> {
            //Use the the temporary public key and a mac made of mac_key and
            //rp_id to form the credential ID that gets sent to the RP as part
            //of the backup credentials.
            //println!("Making cred id");
            let mut hasher = Sha256::new();
            hasher.update(rp_id);
            let rp_hash = hasher.finalize();
            let mac_data = [&E.to_encoded_point(false).as_bytes()[..], &rp_hash[..]].concat();
            let mac = mac(mac_key, &mac_data);
            let cred_id = [&E.to_sec1_bytes()[..], &mac[0..16]].concat();
            cred_id
        }

        pub fn make_backup_credential_public_key(cred_key: [u8; 32], backup_public_key: ecdsa::PubKey) -> ecdsa::PubKey { //makes B
            //Format cred_key as a private key, which lets us extract a public key from it. We then
            //add that public key to backup_public_key to create the public key that will be sent as
            //a backup credential.
            //println!("Making backup credential public key");
            let cred_key_scalar = ScalarPrimitive::from_slice(&cred_key).unwrap();
            let cred_key_private = SecretKey::new(cred_key_scalar);
            let cred_key_public = cred_key_private.public_key().to_projective();
            let credential_public_as_projective = cred_key_public + backup_public_key.to_projective();
            ecdsa::PubKey::from_affine(credential_public_as_projective.to_affine()).unwrap()
        }




/////////////////////////////////////////////////////////////STEP 3//////////////////////////////////////////////////////

    //RP
pub fn recover(backup_authenticator: &mut YK, relying_party: &mut RP, userid: String) {
    //Calls check credentials to find the correct credential for backup_authenticator,
    //then calculates the recovery private key and verifies that it matches the
    //recovery public key associated with that credential. Updates the account to
    //recognize the backup, not the primary.
    //println!("Recovering");
    let account = relying_party.accounts.get(&userid).unwrap();
    let backups: Vec<&Vec<u8>> = account.backups.keys().collect();
    if let Some(credential) =
        check_credentials(&backup_authenticator, backups, &relying_party.rp_id)
    {
        let cred_key_prime = credential.1;
        let private_key = SecretKey::new(
            ScalarPrimitive::from_slice(&cred_key_prime).unwrap()
                + backup_authenticator.backup_private.as_scalar_primitive(),
        )
        .to_bytes()
        .to_vec();
        let public_key = account.backups.get(&credential.0).unwrap();
        if authenticate(&private_key, &public_key) {
            relying_party.accounts.remove(&userid);
            relying_party.accounts.insert(
                userid.clone(),
                make_account(userid, backup_authenticator, &relying_party.rp_id),
            );
            //println!("Successful account recovery!");
        }
    } else {
        //println!("This authenticator doesn't go with this account");
    }
}

    pub fn check_credentials(
        backup_authenticator: &YK,
        credential_list: Vec<&Vec<u8>>,
        rp_id: &[u8; 8],
    ) -> Option<(Vec<u8>, [u8; 32])> {
        //Test all the credentials to see if they're associated with this authenticator.
        //println!("Checking credentials");
        for cred_id in credential_list {
            let test_credential_public_key = process_credential(&cred_id);
            let test_credential =
                make_backup_credential_prime(test_credential_public_key, &backup_authenticator, rp_id);
            // //println!("cred_id: {:?}", cred_id);
            // //println!("test_cred_id: {:?}", test_credential.0);
            if test_credential.0 == cred_id.to_owned() {
                return Some(test_credential);
            }
        }
        return None;
    }

pub fn authenticate(private_key: &Vec<u8>, public_key: &ecdsa::PubKey) -> bool {
    //Signs a key with private_key, then verifies that signature with
    //public_key.
    //println!("Authenticating");
    let challenge = get_challenge();
    let response = sign_challenge(private_key, challenge);
    verify_challenge(challenge, response, public_key)
}

pub fn verify_challenge(challenge: [u8; 32], response: Signature, public_key: &ecdsa::PubKey) -> bool {
    //Returns true if the challenge is valid and false otherwise.
    //println!("Verifying challenge");
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key.to_sec1_bytes()).unwrap();
    let result = verifying_key.verify(&challenge, &response);
    result.is_ok()
}

    //BACKUP

pub fn get_challenge() -> [u8; 32] {
    //Returns a tuple containing a challenge and the account handle,
    //which is the signing key, encrypted by the authenticator's
    //master key.
    //println!("Getting challenge");
    let mut random = OsRng;
    let mut challenge = [0u8; 32];
    random.fill_bytes(&mut challenge);
    challenge
}

pub fn process_credential(cred_id: &Vec<u8>) -> ecdsa::PubKey {
    //Extract the public key from a cred_id.
    //println!("Processing credential");
    ecdsa::PubKey::from_sec1_bytes(&cred_id[0..65]).unwrap()
}

pub fn make_cred_key_prime(private_key: &SecretKey, public_key: ecdsa::PubKey) -> [u8; 32] {
    //Calls hkdf_primary with correct info to produce cred_key_prime
    //println!("Making cred key prime");
    hkdf_backup(private_key, public_key, b"webauthn.recovery.cred_key")
}

pub fn make_mac_key_prime(private_key: &SecretKey, public_key: ecdsa::PubKey) -> [u8; 32] {
    //Calls hkdf_backup with correct info to produce mac_key_prime
    //println!("Making mac key prime");
    hkdf_backup(private_key, public_key, b"webauthn.recovery.mac_key.")
}

pub fn sign_challenge(private_key: &Vec<u8>, challenge: [u8; 32]) -> Signature {
    //Uses the authenticator to derive the signing key from account
    //handle and signs the challenge.
    //println!("Signing challenge");
    let signing_key = SigningKey::from_slice(private_key.as_slice()).unwrap();
    signing_key.sign(&challenge)
}

pub fn make_backup_credential_prime(
    public_key: ecdsa::PubKey,
    backup_authenticator: &YK,
    rp_id: &[u8; 8],
) -> (Vec<u8>, [u8; 32]) {
    //Generate a credential based on the key that came from the cred_id from the
    //relying party. This credential will be compared with cred_id to determine
    //if this credential is associated with backup_authenticator.
    //println!("Making backup credential prime");

    //Generate cred_key_prime and mac_key_prime
    let cred_key_prime = make_cred_key_prime(&backup_authenticator.backup_private, public_key);
    let mac_key = make_mac_key_prime(&backup_authenticator.backup_private, public_key);

    //Generate credential public key and credential id
    let cred_id_prime = make_cred_id(&public_key, mac_key, rp_id);

    (cred_id_prime, cred_key_prime)
}






//LOGIN/TEST STUFF
pub fn login(userid: String, key: &YK, relying_party: &mut RP) {
    //Checks whether key matches the account.
    //Checks whether the number of backup keys on key has changed since
    //the last login. If not, ask to update that information.
    //println!("Logging in");
    let account = relying_party.accounts.get_mut(&userid).unwrap();
    if !authenticate_with_key(&key, &account) {
        //println!("Invalid credentials");
        return;
    }
    if account.recovery_credentials_state != key.recovery_credentials_state {
        // println!(
        //     "It looks like your list of backup keys has changed.\nWould you like to update it on our website? [y/n] "
        // );
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Oops, something went wrong");
        if input == "n" || input == "N" {
            return;
        } else {
            account.recovery_credentials_state = key.recovery_credentials_state;
            account.backups = make_backup_credential_list(key, &relying_party.rp_id);
        }
    }
    //println!("Successful login");
}
    
    pub fn authenticate_with_key(key: &YK, account: &Account) -> bool {
        //Uses the key to sign a challenge from the account on an RP.
        //Returns true if the challenge is signed successfully and
        //false otherwise.
        //println!("Authenticating with key");
        let private_key_result = get_private_key(key, &account.login.1);
        let private_key = match private_key_result {
            Ok(key) => key,
            Err(_error) => return false,
        };
        authenticate(&private_key, &account.login.0)
    }
        pub fn get_private_key( //comes from the RP handle
            key: &YK,
            encrypted_key: &Vec<u8>,
        ) -> Result<Vec<u8>, magic_crypt::MagicCryptError> {
            //Uses key.master to decrpyt encrypted_key.
            //println!("Getting private key");
            return key.master.decrypt_bytes_to_bytes(encrypted_key);
        }





////////////////////////////////////////////these functions actully start the process///////////////////////////////////////
pub fn do_the_thing() {
    //Sets up a bunch of keys and relying parties and stuff so you can
    //test things.

    //Make three keys and a relying party
    //println!("Doing the thing");
    let mut primary = initialize_key();
    let mut backup = initialize_key();
    let mut backup_2 = initialize_key();
    let mut rp = initialize_rp(b"12345678");

    //Pair 2 keys
    import_backup_key(&mut primary, &mut backup_2);

    //Register primary key with rp
    register("Isaac".to_string(), &mut primary, &mut rp);

    //Pair with another key
    import_backup_key(&mut primary, &mut backup);

    //Login with primary and register backup
    login("Isaac".to_string(), &primary, &mut rp);

    //Use backup to recover
    recover(&mut backup_2, &mut rp, "Isaac".to_string());

    // login("Isaac".to_string(), &primary, &mut rp);

    // login("Isaac".to_string(), &backup, &mut rp);
}

pub fn main() {
    //println!("starting main");
    do_the_thing();

    // //Backup:

    // //First we create D and d, which would be generated by the backup. Only
    // //the backup knows d, but D gets sent to the primary.
    // let d = SecretKey::random(&mut OsRng);
    // let D = d.public_key();

    // //Primary:

    // //Next the primary key creates an ephemeral pair, E and e.
    // let e = SecretKey::random(&mut OsRng);
    // let E = e.public_key();

    // //The primary key now uses e and D to calculate cred_key and mac_key.
    // let cred_key = make_cred_key_prime(&e, D);
    // let mac_key = make_mac_key_prime(&e, D);

    // //The primary key creates B using cred_key and D.
    // let cred_key_scalar: ScalarPrimitive<NistP256> =
    //     ScalarPrimitive::from_slice(&cred_key).unwrap();
    // //Formatting cred_key as a public key is the same as multiplying it by the generator:
    // let cred_key_public = p256::elliptic_curve::SecretKey::new(cred_key_scalar).public_key();
    // let B = cred_key_public.to_projective() + D.to_projective();

    // //The primary key creates cred_id. B and cred_id would be sent to the Relying Party.
    // //rp_id is just a random number that would be associated with the Relying Party.
    // let rp_id = b"12345678";
    // let cred_id = make_cred_id(&E, mac_key, rp_id);

    // //Backup:

    // //The backup uses cred_id to get E_prime, then calculates cred_key_prime and mac_key_prime.
    // let E_prime = p256::ecdsa::PubKey::from_sec1_bytes(&cred_id[0..65]).unwrap();
    // let cred_key_prime = make_cred_key_prime(&d, E_prime);
    // let mac_key_prime = make_mac_key_prime(&d, E_prime);

    // //The backup calculates cred_id_prime and asserts that it's equal to cred_id.
    // let cred_id_prime = make_cred_id(&E_prime, mac_key_prime, rp_id);
    // assert_eq!(cred_id, cred_id_prime);

    // //The backup calculates b using cred_key_prime and d.
    // let b_as_scalar =
    //     ScalarPrimitive::from_slice(&cred_key_prime).unwrap() + d.as_scalar_primitive();
    // let b = SecretKey::new(b_as_scalar);

    // //Assert that b is the private key associated with B
    // assert_eq!(b.public_key().as_affine().to_owned(), B.to_affine());

    // //println!("{:?}", E);
    // //println!("{:?}", E_prime);
    // //println!("Done");
}
