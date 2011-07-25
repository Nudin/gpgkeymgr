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
#include <algorithm>
#include <vector>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <libintl.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <gpgme.h>

#define arraylength(a) ( sizeof ( a ) / sizeof ( *a ) )


using namespace std;

const char* program_name="Schlüsselwärter";
const char* program_version="0.1.8";
const char* textpath="/usr/share/locale";

bool ask_user(string question);
string shortenuid(string longuid);
int searchvector(vector<string> str, string key);
int readvector(string file, vector<string>& vector);
string replace_string(string input, const string &search, const string &replace);
int copyfile(string dir, string filename, string destination);
int backup();
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key);
void print_key(gpgme_key_t key);
void help();

bool quiet = false; // For quiet-mode
bool yes = false; // For 'yes-mode'
bool dry = false; // For dry-mode

int main(int argc, char *argv[]) {
   int count = 0; // count number of key's deleted

   /* i18n */
   setlocale( LC_ALL, "" );
   bindtextdomain( "schluesselwaerter", "/usr/share/locale" );
   textdomain( "schluesselwaerter" );

   /* First: get arguments */
   bool revoked = false;
   bool expired = false;
   bool novalid = false;	int max_valid = 0;
   bool notrust = false;	int max_trust = 0;
   bool altern = false;
   bool dobackup = false;
   bool poslist = false;	vector<string> list;
   for (int i=1; i<argc; i++) {
      if ( strlen( argv[i] ) != 2 ) {
          help();
          return 1;
          }
      char c = argv[i][1];
      switch (c)
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
               if ( max_trust != 0 )
                  i++;
            }
            break;
         case 'o': altern = true; break;
         case 'q': quiet = true; break;
         case 'y': yes = true; break;
         case 'd': dry = true; break;
         case 'b': dobackup=true; backup(); break;
         case 'l':
            if ( i+1 < argc ) {
               poslist=true;
               if ( readvector(argv[i+1], list) )
                  return 2;
               i++;
               }
            else {
               help();
               return 1;
               }
            break;
         case 'h': help(); return 0;
   }
   }
   if ( !revoked && !expired && !novalid && !notrust && !poslist ) {
      if ( dobackup )
         return 0;
      else {
         help();
         return 1;
         }
      }

   if (!yes)
   {
   /* Generate security-question */
   string mode;
   if (altern)
      mode = gettext(" or ");
   else
      mode = gettext(" and ");
   string question = gettext("Do you really want to delete all keys which are ");
   if ( revoked )
      question += gettext("revoked")        + mode;
   if ( expired )
      question += gettext("expired")        + mode;
   if ( novalid )
      question += gettext("unvalid")        + mode;
   if ( notrust )
      question += gettext("untrusted")      + mode;
   if ( poslist )
      question += gettext("listed in file") + mode;
   question = question.substr(0, question.length()-mode.length()); // remove last 'and'
   question += gettext("###");	// for languages which need also something at the end
   if ( question.substr(question.length()-3, question.length()) == "###")
      question = question.substr(0, question.length()-3);
   question += "?";

   if ( !ask_user(question) ) {
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
   if (!quiet)
      printf(gettext("GPG-Version=%s\n"), p);

   /* check for OpenPGP support */
   err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
   if (err != GPG_ERR_NO_ERROR)       return 11;
   p = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
   if (!quiet)
      printf(gettext("Protocol name: %s\n"), p);

   /* get engine information */
   err = gpgme_get_engine_info(&enginfo);
   if (err != GPG_ERR_NO_ERROR)       return 12;
   if (!quiet)
      printf(gettext("file=%s, home=%s\n\n"), enginfo->file_name, enginfo->home_dir);

   /* create our own context */
   err = gpgme_new(&ctx);
   if (err != GPG_ERR_NO_ERROR)       return 13;

   /* set protocol to use in our context */
   err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
   if (err != GPG_ERR_NO_ERROR)       return 14;

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
         if ( altern ) { // any given criteria induce deletion
            if ( revoked && key->revoked ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key); }
            else if ( expired && key->expired ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key); }
            else if ( novalid && key->uids->validity <= max_valid ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key); }
            else if ( notrust && key->owner_trust <= max_trust  ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key); }
            else if ( poslist && searchvector(list, shortenuid(key->subkeys->keyid))  ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key); }
         }
         else { // all given criteria together induce deletion
            if (  (!revoked || ( revoked && key->revoked ) ) &&
                  (!expired || ( expired && key->expired ) ) &&
                  (!novalid || ( novalid && key->uids->validity <= max_valid ) ) &&
                  (!notrust || ( notrust && key->owner_trust <= max_trust ) ) &&
                  (!poslist || ( poslist && searchvector(list, shortenuid(key->subkeys->keyid)) ) )
               ) {
                     if (!quiet) print_key(key);
                     if (!dry) fail = remove_key(ctx, key);
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
      cerr << gettext("can not list keys: ") << gpgme_strerror (err) << endl;
      return 10;
   }
   printf(gettext("Deleted %i key(s).\n"), count);
} // end 'main'


/*
Ask the user something, expecting [y/n] as answer
*/
bool ask_user(string question)
{
   cout << question << " [y/n] ";
   char c;
   cin >> c;
   if (c == 'y')
      return true;
   if (c == 'n')
      return false;
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
      cout << " " << gettext("revoked");
   if (key->expired)
      cout << " " << gettext("expired");
   printf (" [%i|", key->uids->validity);
   printf ("%i]", key->owner_trust);
   putchar ('\n');
}


/*
Delete key 'key' from pubring via context 'ctx'
*/ 
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key)
{
   gpgme_error_t err = gpgme_new (&ctx);
   err = gpgme_op_delete (ctx, key, 0 );
   if (gpg_err_code (err) == GPG_ERR_CONFLICT ) {
      cout << "\t=> " <<  gettext("Skipping secret key") << endl;
      return 1;
   }
   else if ( gpg_err_code (err) == GPG_ERR_NO_ERROR ) {
      if (!quiet)  cout << "\t=> " << gettext("deleted key") << endl;
      return 0;
   }
   else {
      cerr << "\t=> " << gettext("unknown Error occurred") << endl;
      return 2;
   }
}


/*
Replace 'search' with 'replace' ind 'input'
*/
string replace_string(string input, const string &search, const string &replace)
{
   string::size_type pos = input.find(search, 0);
   int searchlength  = search.length();
   int replacelength = replace.length();

   while (string::npos != pos) {
      input.replace(pos, searchlength, replace);
      pos = input.find(search, pos + replacelength);
   }
   return input;
}


/*
Returns the short-UID
*/
string shortenuid(string longuid)
{
   if ( longuid.size() == 16 )
      return longuid.substr(8, 16);
   else if ( longuid.size() == 8 )
      return longuid;
   else {
      cerr << gettext("UID in wrong format, skipping");
      return "";
   }
}


/*
Search if an value is included in the string list
We use binary search as search algorithm
*/
int searchvector(vector<string> str, string key)
{
   int low, high, mid;
   low  = 0;
   high = str.size();
   
   while (low <= high) {
      mid = (low + high) / 2;
      if (key < str[mid])
         high = mid - 1;
      else if (key > str[mid])
         low = mid + 1;
      else
         return 1;  // found
   }
   return 0; // not found
}


/*
Read vector from file
*/
int readvector(string file, vector<string>& vector)
{
   ifstream ifs( file.c_str() );

   // check if the file is open
   if (! ifs) {
      cerr << gettext("Failed to open ") << file << endl;
      return 1;
   }

   int line_counter = 1;
   string s;
   while (getline(ifs, s)) {
      line_counter++;
      s = shortenuid(s);
      if ( s != "" )
         vector.push_back(s);
   }

   ifs.close();
   sort(vector.begin(), vector.end());
   return 0;
}


/*
Will copy a <home>/dir/filename to destination/filename 
equivalent to `cp ~/$dir/$filename $destination/filename` on unix
destination must already exist
*/
int copyfile(string dir, string filename, string destination)
{
   string full_filename;
   string full_destination;
   struct stat inFileInfo, outFileInfo, pathFileInfo;
   int    instat, outstat;

   // Get home-Directory
   struct passwd *pw    = getpwuid(getuid());
   const string homedir = pw->pw_dir;

   // Put filenames together
   full_filename    =  homedir + dir + filename;
   destination      =  replace_string(destination, "~", homedir);
   full_destination =  destination;
   if ( full_destination.substr(full_destination.length(), 0) != "/" )
      full_destination += "/";
   full_destination += filename;

   instat = stat(full_filename.c_str(), &inFileInfo); // Test if source-file exists
   if (instat != 0) {
      cerr << gettext("failed to open file: ") << full_filename << endl;
      return 1;
   }

   // Now, test path, to which should be written
   int pathstat = stat(destination.c_str(), &pathFileInfo);
   if ( pathstat != 0 ) {	// path Does not exist.
      int success;
      if (!yes)
         if ( !ask_user(gettext("Directory does not exist. Create?")) )
            return 1;
      #ifdef __MSDOS__
         success = mkdir(destination.c_str());
      #else  /* Unix */
         success = mkdir(destination.c_str(), 0777);
      #endif

      if (success) {
         cerr << gettext("Can't create directory.\n");
         return 1;
      }
   }
   else {
      int filetyp = pathFileInfo.st_mode & S_IFMT;
      if ( filetyp != S_IFDIR ) {	// path isn't a directory
         cerr << gettext("no directory") << endl;
         return 1;
      }
   }

   // Test if file already exists
   outstat = stat(full_destination.c_str(), &outFileInfo);
   if ( outstat == 0 )
      if (!yes)
         if ( !ask_user(gettext("File ") + full_destination + gettext(" already exists, overwrite?")) )
            return 1;

   // Copy file in binary mode
   ifstream ifs(full_filename.c_str(), ios::binary);
   ofstream ofs(full_destination.c_str(), ios::binary);
   ofs << ifs.rdbuf();
} // end 'copyfile'


/*
Backup keyring-files to a directory given by the user
*/
int backup()
{
   string destination = "";
   cout << gettext("Where should I put the backup? (Directory must exist) ");
   cin  >> destination;
   if ( destination == "" )
      destination="/backup/";
   if ( copyfile("/.gnupg/", "pubring.gpg", destination) )
      return 1;
   if ( copyfile("/.gnupg/", "pubring.kbx", destination) )
      return 1;
   cout << gettext("Successfully backuped pubring.gpg and pubring.kbx") << endl;
   return 0;
}


/*
Print out help-Text
*/
void help()
{
   cout << program_name << endl;
   cout << "\t" << gettext("Version: ") << program_version << endl;
   cout << gettext("Note: this is still an experimental version. Before use, please backup your ~/.gnupg directory.\n") << endl;
   cout << gettext("Use: ");
   cout << "schluesselwaerter [-o] [-qyb] TEST [MORE TESTS…]\n";

   cout << "\t-b\t"     << gettext("Backup public keyring")             << endl;
   cout << "\t-o\t"     << gettext("remove key already if one given criteria is maching") << endl;
   cout << "\t-q\t"     << gettext("don't print out so much")           << endl;
   cout << "\t-y\t"     << gettext("Answer all questions with yes")     << endl;
   cout << "\t-d\t"     << gettext("Don't really do anything")          << endl;
   cout                 << gettext("TESTs: ")                           << endl;
   cout << "\t-r\t"     << gettext("remove revoked keys")               << endl;
   cout << "\t-e\t"     << gettext("remove expired keys")               << endl;
   cout << "\t-l "      << gettext("file")
        << "\t"         << gettext("remove keys listed in file (uids)") << endl;
   cout << "\t-v [N]\t" << gettext("remove not-valid keys")             << endl;
   cout << "\t-t [N]\t" << gettext("remove not-trusted keys")           << endl;
   cout << "\t\t\t"     << gettext("with N you can increase the maximum level")
                                                                        << endl;
}

