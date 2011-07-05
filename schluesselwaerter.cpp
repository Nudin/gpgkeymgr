#include <iostream>
#include <cstdlib>
#include <gpgme.h>
#include <string.h>

using namespace std;

const char* program_name="Schlüsselwärter";
const char* program_version="0.1.1";

int remove_key(gpgme_ctx_t ctx, gpgme_key_t key);
void print_key(gpgme_key_t key);
void help();

int main(int argc, char *argv[]) {

   /* First: get arguments */
   bool revoked = false;
   bool expired = false;
   bool novalid = false; int max_valid = 0;
   bool notrust = false; int max_trust = 0;
   bool altern = false;
   for(int i=1;i<argc;i++) {
	if ( strlen(argv[i]) != 2 )
	   { help(); return 7; }
	char c=argv[i][1];
	switch(c)
	{
	case 'r': revoked = true; break;
	case 'e': expired = true; break;
	case 'v':
	   novalid = true;
	   if ( i+1 < argc ) {
	     max_valid = atoi(argv[i+1]);
	     if ( max_valid != 0 )
	   	i++;
	   }
	   break;
	case 't':
	   notrust = true;
	   if ( i+1 < argc ) {
	     max_trust = atoi(argv[i+1]);
	     if ( max_valid != 0 )
	   	i++;
	   }
	   break;
	case 'o': altern = true; break;
	case 'h': help(); return 0;
	}
   }
   if ( !revoked && !expired && !novalid && !notrust ) {
	help();
	return 7;
	}
   cout << "Arguments: " << revoked << expired << novalid << notrust << max_valid << max_trust << endl;

   /* Now set up to use GPGME */
   char *p;
   gpgme_ctx_t ctx;
   gpgme_key_t key;
   gpgme_error_t err = gpgme_new (&ctx);
   gpgme_engine_info_t enginfo;

   setlocale (LC_ALL, "");
   p = (char *) gpgme_check_version(NULL);
   printf("version=%s\n",p);

   /* set locale, because tests do also */
   gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

   /* check for OpenPGP support */
   err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) return 1;

   p = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
   printf("Protocol name: %s\n",p);

   /* get engine information */
   err = gpgme_get_engine_info(&enginfo);
   if(err != GPG_ERR_NO_ERROR) return 2;
   printf("file=%s, home=%s\n",enginfo->file_name,enginfo->home_dir);

   /* create our own context */
   err = gpgme_new(&ctx);
   if(err != GPG_ERR_NO_ERROR) return 3;

   /* set protocol to use in our context */
   err = gpgme_set_protocol(ctx,GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) return 4;

   /* Now get all Keys */
   if (!err)
       {
         err = gpgme_op_keylist_start (ctx, NULL, 0);
         while (!err)
           {
             err = gpgme_op_keylist_next (ctx, &key);
             if (err) {
               gpgme_key_release (key);
	       break; }

	     if ( !key->uids )
		break;

	     /* Test if to remove key */
	     if ( altern ) { // any given kriteria induce deletion
		if ( revoked && key->revoked ) {
			print_key(key);
			remove_key(ctx, key); }
		if ( expired && key->expired ) {
			print_key(key);
			remove_key(ctx, key); }
		if ( novalid && key->uids->validity <= max_valid ) {
			print_key(key);
			remove_key(ctx, key); }
		if ( notrust && key->owner_trust <= max_trust  ) {
			print_key(key);
			remove_key(ctx, key); }
	     }
	     else { // all given kriteria together induce deletion
		if ( 	(!revoked || ( revoked && key->revoked ) ) &&
			(!expired || ( expired && key->expired ) ) &&
			(!novalid || ( novalid && key->uids->validity <= max_valid ) ) &&
			(!notrust || ( notrust && key->owner_trust <= max_trust ) )	) {
			   print_key(key);
			   remove_key(ctx, key);
			}
	     }


            gpgme_key_release (key);
           }
         gpgme_release (ctx);
       }
     if (gpg_err_code (err) != GPG_ERR_EOF)
       {
         fprintf (stderr, "can not list keys: %s\n", gpgme_strerror (err));
         exit (1);
       }
} // end main

/* Print out information about key */
void print_key(gpgme_key_t key) {
               printf ("%s:", key->subkeys->keyid);
               if (key->uids->name)
                   printf (" %s", key->uids->name);
               if (key->uids->email)
                   printf (" <%s>", key->uids->email);
               if (key->revoked)
                   printf (" revoked");
               if (key->expired)
                   printf (" expired");
               printf (" [%i|", key->uids->validity);
	       printf ("%i]", key->owner_trust);
               putchar ('\n');
}

/* Delete key from pubring */ 
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key) {
	gpgme_error_t err = gpgme_new (&ctx);
	err = gpgme_op_delete (ctx, key, 0 );
	if (gpg_err_code (err) == GPG_ERR_CONFLICT ) {
		cout << "\t=> Skipping secret key" << endl;
		return 1; }
	else if ( gpg_err_code (err) == GPG_ERR_NO_ERROR ) {
		cout << "\t=> deleted key" << endl;
		return 0; }
	else {
		cout << "\t=> unknown Error occurred" << endl;
		return 2; }
}

/* Print out help-Text */
void help() {
	cout << program_name << endl;
	cout << "\tVersion: " << program_version << endl;
	cout << "Note: this is still an experimental version. Before use, please backup your ~/.gnupg directory.\n" << endl;

	cout << "Use: ";
	cout << "schluesselwaerter [-o] TEST [MORE TESTS…]\n";

	cout << "\t-o\tremove key already if one given criteria is maching" << endl;
	cout << "\t-r\tremove revoked keys" << endl;
	cout << "\t-e\tremove expired keys" << endl;
	cout << "\t-v [N]\tremove not-valid keys" << endl;
	cout << "\t-t [N]\tremove not-trusted keys" << endl;
}

