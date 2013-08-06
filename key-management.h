Key Management API -- ROUGH

/**
 * @brief stores an alias including its key pair and appropriate flags
 * @param in_use flags whether key is currently selected for this session
 * @param is_default flags whether alias is selected as the default key
 * @param pub_key the public key associated with the alias
 * @param priv_key the private key associated with the alias
 * @param alias_pass password to unlock the alias
 */
struct alias 
{
  bool in_use; 
  bool is_default; 
  char * pub_key; 
  char * priv_key;
  char * alias_pass;
}; ALIAS


/**
 * @brief stores an application or user as part of a 'favorites' or 'contacts' list
 * @param name name of the application or contact
 * @param fingerprint fingerprint of the application or contact
 * @param pub_key the public key
 * @param trust_level rating system for how trusted the key/user/application is
 */
struct contact
{
  char *name; 
  char *fingerprint; 
  char *pub_key; 
  int trust_level; 
}; CONTACT

// KEY MANAGEMENT (see key.h)

/**
 * @brief opens the keyring for reading/writing
 * @param context context 
 * @param keyring file where keys are stored
 * @param keyring_pass password to unlock the keyring file
 */
int co_open_keyring (co_ctx_t context, char * keyring, char * keyring_pass)

/**
 * @brief opens the contacts keyring (pub_keyring) for reading/writing
 * @param context context
 * @param pub_keyring file where public keys (for contacts or saved apps) are stored
 * @param keyring_pass password to unlock pub_keyring
 */
int co_open_contacts (co_ctx_t context, char * pub_keyring, char * keyring_pass)

 /**
  * @brief searches the (open and unlocked) keyring file for the specified alias
  * @param context context
  * @param alias name of desired alias
  * @param alias_pass password to unlock alias
  */
int co_get_alias (co_ctx_t context, char * alias, char * alias_pass)

/**
 * @brief generates a new alias and saves it to your private keyring
 * @param context context 
 * @param priv_keyring file where private keys are stored
 * @param alias human-readable name for the alias
 * @param alias_pass password to unlock the alias
 */
int co_generate_alias (co_ctx_t context, char * priv_keyring, char * alias, char * alias_pass)

/**
 * @brief deletes an alias from the user's private keyring
 * @param context context
 * @param priv_keyring file where aliases are stored
 * @param alias the human-readable name of the alias
 * @param alias_pass the password to unlock the alias
 */
int co_delete_alias (co_ctx_t context, char * priv_keyring, char * alias, char * alias_pass)

/**
 * @brief saves a public key (eg. of an app or another user)
 * @param context context
 * @param pub_key the public key to be saved
 * @param alias the name of the public key
 * @param pub_keyring the file in which public keys are stored
 */
int co_save_contact (co_ctx_t context, unsigned char * pub_key, char * alias, char * pub_keyring)

/**
 * @brief removes a public key from the list of saved keys
 * @param context context
 * @param alias the name of the public key
 * @param pub_keyring the file in which public keys are stored
 */
int co_remove_contact (co_ctx_t context, char * alias, char * pub_keyring)

/**
 * @brief switches the alias to be used for this session (if not invoked, default key is used)
 * @param context context
 * @param priv_keyring the file in which a user's aliases are stored
 * @param alias the name of the desired alias
 * @param alias_pass the password to unlock the alias
 */
int co_switch_alias (co_ctx_t context, unsigned char * priv_keyring, char * alias, char * alias_pass)


/**
 * @brief sets the default alias to be used on startup
 * @param context context
 * @param priv_keyring the file in which a user's private keys are stored
 * @param alias the name of the desired alias
 * @param alias_pass the password to unlock the alias
 */
int co_set_default_alias (co_ctx_t context, unsigned char * priv_keyring, char * alias, char * alias_pass)

/**
 * @brief gets the private key for the specified alias
 * @param keyring keyring file
 * @param keyring_pass password to unlock keyring
 * @param alias name of the alias
 * @param alias_pass password to unlock alias
 */
int co_get_priv_key (char * keyring, char * keyring_pass, char * alias, char * alias_pass)

SIGNING and VERIFICATION

/**
 * @brief signs an object (eg. a message, service announcement, another key) using the specified private key
 * @param context context (eg. connection type)
 * @param object the object to be signed (converted to char * format)
 * @param object_len size (in bytes) of the object to be signed
 * @param priv_keyring file where user's private keys are stored
 * @param alias the desired alias to be used (if none specified, will use default key)
 * @param alias_pass the password/PIN to unlock the alias/private key (if none specified, password is blank)
 * @param buffer the buffer in which to store the signed object
 * @param buffer_len size of the buffer (in bytes)
 */
int co_sign (co_ctx_t context, unsigned char * object, int object_len, char * priv_keyring, char * alias, char * alias_pass, unsigned char * buffer, int buffer_len)

/**
 * @brief verifies an object's signature. Returns an int value based on whether signature is valid, known or unknown, as well as its user-assigned trust level
 * @param context context (eg. connection type, type of object)
 * @param object the signed object to be verified (converted to char * format)
 * @param object_len size (in bytes) of the object to be verified
 * @param pub_keyring file in which public keys are stored
 * @param buffer the buffer in which to store the signed object
 * @param buffer_len size of the buffer
 */
int co_verify (co_ctx_t context, unsigned char * object, int object_len, char * pub_keyring, unsigned char * buffer, unsigned char * buffer_len)

/**
 * @brief checks list of saved contacts for a specified alias (or alias id) to see if it is known
 * @param context context
 * @param pub_keyring keyring where public keys (saved contacts/apps) are stored
 * @param pub_keyring_pass password to unlock the public keyring
 * @param alias_id the alias name or id used as the search key
 */
int co_check_contacts (co_ctx_t context, char * pub_keyring, char * pub_keyring_pass, char * alias_id)


ENCRYPTION and DECRYPTION

/**
 * @brief encrypts an object using a specified key
 * @param context context (eg. connection type)
 * @param object the object to be encrypted
 * @param object_len size (in bytes) of the object
 * @param pub_keyring the file where public keys are stored
 * @param alias the human-readable name of the key to encrypt with
 * @param buffer the buffer in which to store the encrypted object
 * @param buffer_len size of the buffer (in bytes)
 */
int co_encrypt (co_ctx_t context, unsigned char * object, char * pub_keyring, int object_len, char * alias, unsigned char * buffer, int buffer_len)

/**
 * @brief decrypts an object using the specified private key
 * @param context context
 * @param object object to be decrypted
 * @param object-len size (in bytes) of the object
 * @param alias name of alias used to decrypt
 * @param alias_pass password to unlock alias
 * @param buffer buffer in which to store decrypted message
 * @param buffer_len size of the buffer
 */
int co_decrypt (co_ctx_t context, unsigned char * object, int object_len, char * alias, char * alias_pass, unsigned char * buffer, int buffer_len)