/*
	gpgkeymgr
	  A program to clean up an manage your keyring
	  Copyright: Michael F. Schönitzer; 2011-2013
*/
/*  This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU Lesser General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU Lesser General Public License for more details.
*
*   You should have received a copy of the GNU Lesser General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <libintl.h>

#include "vectorutil.hpp"
#include "stringutil.hpp"
#include "copyfile.hpp"
#include "auditor.hpp"
#include "parsearguments.hpp"
#include "userinteraction.hpp"
#include "globalconsts.hpp"

#include <gpgme.h>

#define _(Text) gettext(Text) // _ as short version of gettext

using namespace std;


// definitions of functions, implementations see below
int backup(bool yes, string destination);
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key, bool quiet);
void print_key(gpgme_key_t key);


int main(int argc, char *argv[]) {
   int count = 0; // count number of key's deleted

   /* i18n */
   setlocale( LC_ALL, "" );
   bindtextdomain( program_name, textpath );
   textdomain( program_name );

   /* Parse arguments */
   // The auditor contains all the options an logic about deciding where to delete a key or not
   auditor keyauditor;
   bool dobackup       = false;
   string destination  = "";
   bool statistics     = false; // Print out statistics
   bool onlystatistics = false; // Do nothing but statistics, implies statistics==true
   bool quiet    = false;  // For quiet-mode
   bool dry      = false;  // For dry-mode
   bool yes      = false;  // For 'yes-mode'
   
   // Parse the arguments
   int parsestat = parsearguments(argc, argv, keyauditor, dobackup, destination,
                                  statistics, onlystatistics, quiet, dry, yes);

   if ( parsestat == -1) // option -h is given, exit
      return 0;
   else if ( parsestat != 0 ) // an error occurred, exit
      return parsestat;

   /* Make a backup */
   if ( dobackup ) {
      if ( backup(yes, destination) )
         return 3;
   }
   
   // Security-question
   if (!yes && !onlystatistics )
      if ( !ask_user(keyauditor.generatequestion()) ) {
         cout << _("By") << endl;
         return 0;
      }

   /* Now set up to use GPGME */
   char *p;
   gpgme_ctx_t ctx;
   gpgme_key_t key;
   gpgme_error_t err = gpgme_new (&ctx);
   gpgme_engine_info_t enginfo;
   
   p = (char *) gpgme_check_version(NULL);
   if (!quiet)
      printf(_("GPG-Version=%s\n"), p);

   /* check for OpenPGP support */
   err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
   if (err != GPG_ERR_NO_ERROR)       return 11;
   p = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
   if (!quiet)
      printf(_("Protocol name: %s\n"), p);

   /* get engine information */
   err = gpgme_get_engine_info(&enginfo);
   if (err != GPG_ERR_NO_ERROR)       return 12;
   if (!quiet)
      printf(_("file=%s, home=%s\n\n"), enginfo->file_name, enginfo->home_dir);

   /* create our own context */
   err = gpgme_new(&ctx);
   if (err != GPG_ERR_NO_ERROR)       return 13;

   /* set protocol to use in our context */
   err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
   if (err != GPG_ERR_NO_ERROR)       return 14;

   // For counting the number of keys
   int revokedkeys = 0;
   int expiredkeys = 0;
   int numberofkeys[6][6];
   for ( int i=0; i<6; i++)
      for ( int j=0; j<6; j++)
         numberofkeys[i][j]=0;
   
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
            
         if ( key->uids->validity > 6 || key->owner_trust > 6 )
            cerr << _("Warning: Some keys have validity  or trust biger than 5.") << endl;
         else
            numberofkeys[key->uids->validity][key->owner_trust]++;
         if ( key->revoked )
            revokedkeys++;
         if ( key->expired )
            expiredkeys++;

         if ( !onlystatistics )
            // Test if keys should be deleted
            if ( keyauditor.test(key->revoked, key->expired, key->uids->validity,
                                 key->owner_trust, key->subkeys->keyid) ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key, quiet);
            }

         gpgme_key_release (key);
         if ( !fail )
            count++;
      } // end while
      gpgme_release (ctx);
      
      if(statistics) {
         printstatistics(revokedkeys, expiredkeys, numberofkeys);
      }
   }
   if (gpg_err_code (err) != GPG_ERR_EOF)
   {
      cerr << _("can not list keys: ") << gpgme_strerror (err) << endl;
      return 10;
   }
   if ( !onlystatistics && !dry )
      printf(_("Deleted %i key(s).\n"), count);
} // end 'main'



/*
Backup keyring-files to a directory given by the user
*/
int backup(bool yes, string destination)
{
   if ( destination == "" ) {
      cout << _("Where should I put the backup? (Directory must exist) ");
      cin  >> destination;
   }
   if ( destination == "" )
      destination="backup/";
   if ( copyfile("/.gnupg/", "pubring.gpg", destination, yes) )
      return 1;
   if ( copyfile("/.gnupg/", "pubring.kbx", destination, yes) )
      return 1;
   cout << _("Successfully backuped pubring.gpg and pubring.kbx") << endl;
   return 0;
}



/*
Print out information about key
*/
void print_key(gpgme_key_t key)
{
   printf ("%s:", shortenuid(key->subkeys->keyid).c_str());
   if (key->uids->name)
      printf (" %s", key->uids->name);
   if (key->uids->email)
      printf (" <%s>", key->uids->email);
   if (key->revoked)
      cout << " " << _("revoked");
   if (key->expired)
      cout << " " << _("expired");
   printf (" [%i|", key->uids->validity);
   printf ("%i]", key->owner_trust);
   putchar ('\n');
}



/*
Delete key 'key' from pubring via context 'ctx'
*/ 
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key, bool quiet)
{
   gpgme_error_t err = gpgme_new (&ctx);
   err = gpgme_op_delete (ctx, key, 0 );
   if (gpg_err_code (err) == GPG_ERR_CONFLICT ) {
      cout << "\t=> " <<  _("Skipping secret key") << endl;
      return 1;
   }
   else if ( gpg_err_code (err) == GPG_ERR_NO_ERROR ) {
      if (!quiet)  cout << "\t=> " << _("deleted key") << endl;
      return 0;
   }
   else {
      cerr << "\t=> " << _("unknown Error occurred") << endl;
      return 2;
   }
}

