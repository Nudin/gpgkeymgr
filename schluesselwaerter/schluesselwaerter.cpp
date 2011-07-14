/*
	Schlüsselwärter
	  A program to clean up an manage your keyring
	  Copyright: Michael F. Schönitzer; 2011
*/
/*  This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <gpgme.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>


#include <libintl.h>
#include <locale.h>


using namespace std;

const char* program_name="Schlüsselwärter";
const char* program_version="0.1.3";
const char* textpath="/usr/share/locale";

int mycopy(string dir, string filename, string destination);
int backup();
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key);
void print_key(gpgme_key_t key);
void help();

bool quiet = false; // For quiet-mode
bool yes = false; // For 'yes-mode'
bool dobackup = false;

int main(int argc, char *argv[]) {
   int count = 0; // count number of key's deleted

   /* i18n */
   setlocale( LC_ALL, "" );
   bindtextdomain( "schluesselwaerter", "/usr/share/locale" );
   textdomain( "schluesselwaerter" );

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
         case 'q': quiet = true; break;
         case 'y': yes = true; break;
         case 'b': dobackup=true; backup(); break;
         case 'h': help(); return 0;
   }
   }
   if ( !revoked && !expired && !novalid && !notrust ) {
      if ( dobackup )
         retrun 0;
      else {
         help();
         return 7;
         }
      }
   if (!quiet)
      cout << gettext("Arguments: ") << revoked << expired << novalid << notrust << max_valid << max_trust << endl;

   if (!yes)
   {
   cout << gettext("Do you realy want to delete the keys? [y/n] ");
   char c;
   cin >> c;
   if (c != 'y') {
   	cout << gettext("By") << endl;
   	return 0;
   	}
   }

   /* Now set up to use GPGME */
   char *p;
   gpgme_ctx_t ctx;
   gpgme_key_t key;
   gpgme_error_t err = gpgme_new (&ctx);
   gpgme_engine_info_t enginfo;
   
   p = (char *) gpgme_check_version(NULL);
   if (!quiet) printf(gettext("Version=%s\n"),p);

   /* check for OpenPGP support */
   err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) return 1;

   p = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
   if (!quiet) printf(gettext("Protocol name: %s\n"),p);

   /* get engine information */
   err = gpgme_get_engine_info(&enginfo);
   if(err != GPG_ERR_NO_ERROR) return 2;
   if (!quiet) printf(gettext("file=%s, home=%s\n\n"),enginfo->file_name,enginfo->home_dir);

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
         bool fail = true;
         err = gpgme_op_keylist_next (ctx, &key);
         if (err) {
            gpgme_key_release (key);
            break;
         }

         if ( !key->uids )
            break;

         /* Test if to remove key */
         if ( altern ) { // any given kriteria induce deletion
            if ( revoked && key->revoked ) {
               if (!quiet) print_key(key);
                  fail = remove_key(ctx, key); }
            else if ( expired && key->expired ) {
               if (!quiet) print_key(key);
                  fail = remove_key(ctx, key); }
            else if ( novalid && key->uids->validity <= max_valid ) {
               if (!quiet) print_key(key);
                  fail = remove_key(ctx, key); }
            else if ( notrust && key->owner_trust <= max_trust  ) {
               if (!quiet) print_key(key);
                  fail = remove_key(ctx, key); }
         }
         else { // all given kriteria together induce deletion
            if ( 	(!revoked || ( revoked && key->revoked ) ) &&
                  (!expired || ( expired && key->expired ) ) &&
                  (!novalid || ( novalid && key->uids->validity <= max_valid ) ) &&
                  (!notrust || ( notrust && key->owner_trust <= max_trust ) )	) {
                     if (!quiet) print_key(key);
                     fail = remove_key(ctx, key);
                  }
         }

         gpgme_key_release (key);
         if ( !fail )
            count++;
      } // end while
      gpgme_release (ctx);
   }
   if (gpg_err_code (err) != GPG_ERR_EOF)
   {
      fprintf (stderr, gettext("can not list keys: %s\n"), gpgme_strerror (err));
      exit (1);
   }
printf(gettext("Deleted %i key(s).\n"), count);
} // end main

/* Print out information about key */
void print_key(gpgme_key_t key) {
   printf ("%s:", key->subkeys->keyid);
   if (key->uids->name)
      printf (" %s", key->uids->name);
   if (key->uids->email)
      printf (" <%s>", key->uids->email);
   if (key->revoked)
      cout << " " << gettext("revoked");
   if (key->expired)
      cout << " " << gettext("expired");
   printf (" [%i|", key->uids->validity);
   printf ("%i]", key->owner_trust);
   putchar ('\n');
}

/* Delete key from pubring */ 
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key) {
   gpgme_error_t err = gpgme_new (&ctx);
   err = gpgme_op_delete (ctx, key, 0 );
   if (gpg_err_code (err) == GPG_ERR_CONFLICT ) {
      cout << "\t=> " <<  gettext("Skipping secret key") << endl;
      return 1; }
   else if ( gpg_err_code (err) == GPG_ERR_NO_ERROR ) {
      if (!quiet)  cout << "\t=> " << gettext("deleted key") << endl;
      return 0; }
   else {
      cout << "\t=> " << gettext("unknown Error occurred") << endl;
      return 2; }
}

int mycopy(string dir, string filename, string destination)
{
   struct passwd *pw = getpwuid(getuid()); // Get home-Directory
   const string homedir = pw->pw_dir;
   string strFilename = homedir + dir + filename; // Put file name together
   string strDestFilename = destination + filename;
   
   struct stat stFileInfo;
   int intStat;
   intStat = stat(strFilename.c_str(),&stFileInfo); // Test if file exists
   if(intStat == 0) {
      ifstream ifs(strFilename.c_str(), ios::binary);
      ofstream ofs(strDestFilename.c_str(), ios::binary);
      ofs << ifs.rdbuf();
      return 0;
   }
   else {
    cout << gettext("failed to open file: ") << strFilename << endl;
    return 1;
    }
}

int backup()
{
   string destination = "";
   cout << gettext("Where should I put the backup? (Directory must exist and path mus be absolute) ");
   cin >> destination;
   if ( destination == "" )
      destination="/backup/";
   if ( mycopy("/.gnupg/", "pubring.gpg", destination) )
      return 1;
   if ( mycopy("/.gnupg/", "pubring.kbx", destination) )
      return 1;
   cout << gettext("Succesfully backuped pubring.gpg and pubring.kbx") << endl;
   return 0;
}

/* Print out help-Text */
void help() {
   cout << program_name << endl;
   cout << "\t" << gettext("Version: ") << program_version << endl;
   cout << gettext("Note: this is still an experimental version. Before use, please backup your ~/.gnupg directory.\n") << endl;
   cout << gettext("Use: ");
   cout << "schluesselwaerter [-o] [-q] TEST [MORE TESTS…]\n";

   cout << "\t-o\t" << gettext("remove key already if one given criteria is maching") << endl;
   cout << "\t-q\t" << gettext("don't print out so much") << endl;
   cout << "\t-y\t" << gettext("Answer all questions with yes") << endl;
   cout << gettext("TESTs: ") << endl;
   cout << "\t-r\t" << gettext("remove revoked keys") << endl;
   cout << "\t-e\t" << gettext("remove expired keys") << endl;
   cout << "\t-v [N]\t" << gettext("remove not-valid keys") << endl;
   cout << "\t-t [N]\t" << gettext("remove not-trusted keys") << endl;
   cout << "\t\t\t" << gettext("with N you can increase the maximum level") << endl;
}

