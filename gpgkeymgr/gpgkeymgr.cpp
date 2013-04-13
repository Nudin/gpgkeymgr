/*
	gpgkeymgr
	  A program to clean up an manage your keyring
	  Copyright: Michael F. Schönitzer; 2011
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

#define arraylength(a) ( sizeof ( a ) / sizeof ( *a ) ) // get length of array
#define _(Text) gettext(Text) // _ as short version of gettext

using namespace std;

const char* program_name="gpgkeymgr";
#ifdef VERS
   const char* program_version = VERS;
#else
   const char* program_version = _("Developement Version");
#endif
#ifdef LOCAL
  const char* textpath="locale";
#else
  const char* textpath="/usr/share/locale";
#endif

// definitions of functions, implementations see below
bool ask_user(string question);
string shortenuid(string longuid);
int searchvector(vector<string> str, string key);
int readvector(string file, vector<string>& vector);
string replace_string(string input, const string &search, const string &replace);
int copyfile(string dir, string filename, string destination, bool yes);
int backup(bool yes, string destination);
int remove_key(gpgme_ctx_t ctx, gpgme_key_t key, bool quiet);
void print_key(gpgme_key_t key);
void help();


int main(int argc, char *argv[]) {
   int count = 0; // count number of key's deleted

   /* i18n */
   setlocale( LC_ALL, "" );
   bindtextdomain( program_name, textpath );
   textdomain( program_name );

   /* First: get arguments */
   bool revoked  = false;
   bool expired  = false;
   bool novalid  = false;	int max_valid = 0;
   bool notrust  = false;	int max_trust = 0;
   bool altern   = false;
   bool dobackup = false;	string destination = "";
   bool poslist  = false;	vector<string> list;
   bool statistics = false; // Print out statistics
   bool onlystatistics = false; 
   bool quiet    = false;  // For quiet-mode
   bool dry      = false;  // For dry-mode
   bool yes      = false;  // For 'yes-mode'

   opterr = 0;
   char c;
   int tmp;
   while ((c = getopt (argc, argv, "rev:t:oqydsb:l:h")) != -1) {
      switch (c)
         {
         case 'r':
            revoked = true;
            break;
         case 'e':
            expired = true;
            break;
         case 'v':
            novalid = true;
            if ( sscanf(optarg, "%d", &tmp) )
               max_valid = tmp;
            else
               optind--;
            break;
         case 't':
            notrust = true;
            if ( sscanf(optarg, "%d", &tmp) )
               max_trust = tmp;
            else
               optind--;
            break;
         case 'o':
            altern = true;
            break;
         case 'q':
            quiet = true;
            break;
         case 'y':
            yes = true;
            break;
         case 'd':
            dry = true;
            break;
         case 's':
            statistics = true;
            break;
         case 'b':
            dobackup=true;
            if(optarg[0] == '-')
               optind--;
            else
               destination = optarg;
            break;
         case 'l':
            poslist=true;
            if ( readvector(optarg, list) )
               return 2;
            break;
         case 'h':
            help();
            return 0;
            break;
         case '?':
            if (optopt == 'v')	// Option t and v can also be called without N
               novalid = true;
            else if (optopt == 't')
               notrust = true;
            else if (optopt == 'b')
               dobackup=true;
            else {
               help();
               return 1;
            }
            break;
         default:
             help();
             return 1;
         } } // end swich & loop

   if ( dobackup ) {
      if ( backup(yes, destination) )
         return 3;
   }
   if ( !revoked && !expired && !novalid && !notrust && !poslist ) {
      if ( dobackup )
         return 0;
      else if ( statistics )
         onlystatistics=true;
      else { // none option has been given
         help();
         return 1;
      }
   }

   if (!yes && !onlystatistics )
   {
   /* Generate security-question */
   string mode;
   if (altern)
      mode = _(" or ");
   else
      mode = _(" and ");
   string question = _("Do you really want to delete all keys which are ");
   if ( revoked )
      question += _("revoked")        + mode;
   if ( expired )
      question += _("expired")        + mode;
   if ( novalid )
      question += _("unvalid")        + mode;
   if ( notrust )
      question += _("untrusted")      + mode;
   if ( poslist )
      question += _("listed in file") + mode;
   // remove last 'and':
   question = question.substr(0, question.length()-mode.length());
   // for languages which need also something at the end of the questions:
   question += _("###");
   if ( question.substr(question.length()-3, question.length()) == "###")
      question = question.substr(0, question.length()-3);
   question += "?";

   if ( !ask_user(question) ) {
      cout << _("By") << endl;
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

         /* Test if to remove key */
         if ( !onlystatistics && altern ) { // any given criteria induce deletion
            if ( revoked && key->revoked ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key, quiet); }
            else if ( expired && key->expired ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key, quiet); }
            else if ( novalid && key->uids->validity <= max_valid ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key, quiet); }
            else if ( notrust && key->owner_trust <= max_trust  ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key, quiet); }
            else if ( poslist && 
                        searchvector(list, shortenuid(key->subkeys->keyid))  ) {
               if (!quiet) print_key(key);
               if (!dry) fail = remove_key(ctx, key, quiet); }
         }
         else if( !onlystatistics ) { // all given criteria together induce deletion
            if ( (!revoked || ( revoked && key->revoked )) &&
                 (!expired || ( expired && key->expired )) &&
                 (!novalid || ( novalid && key->uids->validity <= max_valid )) &&
                 (!notrust || ( notrust && key->owner_trust <= max_trust ))    &&
                 (!poslist || ( poslist &&
                          searchvector(list, shortenuid(key->subkeys->keyid))) )
               ) {
                     if (!quiet) print_key(key);
                     if (!dry) fail = remove_key(ctx, key, quiet);
                 }
         }

         gpgme_key_release (key);
         if ( !fail )
            count++;
      } // end while
      gpgme_release (ctx);
      
      if(statistics) {
         // Print out table
         cout << _("Statistics:") << endl;
         cout << "\e[31m" << _("Left-to-Right: Trust") << "\e[0m" << endl;
         cout << "\e[32m" << _("Up-To-Down: Validity") << "\e[0m" << endl;
         cout << "\e[1m\e[31m" << setw(5) << "#";
         cout << setw(5) << "0" << setw(5) << "1" << setw(5) << "2";
         cout << setw(5) << "3" << setw(5) << "4" << setw(5) << "5";
         cout << setw(7) << _("Sum") << "\e[0m" << endl;
         for (int i = 0; i < 6; i++ )
         {
            cout << "\e[1m\e[32m" << setw(5) << i << "\e[0m" << setw(5) << numberofkeys[i][0] << setw(5) << numberofkeys[i][1];
            cout << setw(5) << numberofkeys[i][2] << setw(5) << numberofkeys[i][3];
            cout << setw(5) << numberofkeys[i][4] << setw(5) << numberofkeys[i][5];
            int sum = 0;
            for ( int j = 0; j<6; j++)
               sum += numberofkeys[i][j];
            cout << setw(7) << "\e[1m" << sum << "\e[0m" << endl;
         }
         cout << "\e[1m\e[32m" << setw(5) << _("Sum") << "\e[0m\e[1m";
         int totalsum = 0;
         for ( int j = 0; j<6; j++)
         {
            int sum = 0;
            for ( int i = 0; i<6; i++)
               sum += numberofkeys[i][j];
            cout << setw(5) << sum;
            totalsum += sum;
         }
         cout << setw(5) << totalsum << "\e[0m" << endl;
         cout << endl;
         cout << _("Number of revoked keys: ") << revokedkeys << endl;
         cout << _("Number of expired keys: ") << expiredkeys << endl;
         cout << _("Number keys: ") << totalsum << endl;
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
      cerr << _("UID in wrong format, skipping");
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
      cerr << _("Failed to open ") << file << endl;
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
int copyfile(string dir, string filename, string destination, bool yes)
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

   // Test if source-file exists
   instat = stat(full_filename.c_str(), &inFileInfo);
   if (instat != 0) {
      cerr << _("failed to open file: ") << full_filename << endl;
      return 1;
   }

   // Now, test path, to which should be written
   int pathstat = stat(destination.c_str(), &pathFileInfo);
   if ( pathstat != 0 ) {	// path Does not exist.
      int success;
      if (!yes)
         if ( !ask_user(_("Directory does not exist. Create?")) )
            return 1;
      #ifdef __MSDOS__
         success = mkdir(destination.c_str());
      #else  /* Unix */
         success = mkdir(destination.c_str(), 0777);
      #endif

      if (success) {
         cerr << _("Can't create directory.\n");
         return 1;
      }
   }
   else {
      int filetyp = pathFileInfo.st_mode & S_IFMT;
      if ( filetyp != S_IFDIR ) {	// path isn't a directory
         cerr << _("no directory") << endl;
         return 1;
      }
   }

   // Test if file already exists
   outstat = stat(full_destination.c_str(), &outFileInfo);
   if ( outstat == 0 )
      if (!yes) {
         string question  =  _("File ") + full_destination;
                question +=  _(" already exists, overwrite?");
         if ( !ask_user(question) )
            return 1;
      }

   // Copy file in binary mode
   ifstream ifs(full_filename.c_str(), ios::binary);
   ofstream ofs(full_destination.c_str(), ios::binary);
   ofs << ifs.rdbuf();
   return 0;
} // end 'copyfile'



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



/*
Print out help-Text
*/
void help()
{
   cout << program_name << endl;
   cout << "\t" << _("Version: ") << program_version << endl;
   cout << _("Note: this is still an experimental version. "
                "Before use, please backup your ~/.gnupg directory.\n") << endl;
   cout << _("Use: ");
   cout << program_name <<  " [-o] [-qysb] TEST [MORE TESTS…]\n";

   cout << "\t-b [dir]\t" << _("Backup public keyring")                 << endl;
   cout << "\t-o\t"       << _("remove key already "
                                   "if one given criteria is maching")  << endl;
   cout << "\t-q\t"       << _("don't print out so much")               << endl;
   cout << "\t-y\t"       << _("Answer all questions with yes")         << endl;
   cout << "\t-d\t"       << _("Don't really do anything")              << endl;
   cout << "\t-s\t"       << _("Print statistics")                      << endl;
   cout << "\t-h\t"       << _("Print this help and exit")              << endl;
   cout                   << _("TESTs: ")                               << endl;
   cout << "\t-r\t"       << _("remove revoked keys")                   << endl;
   cout << "\t-e\t"       << _("remove expired keys")                   << endl;
   cout << "\t-l "        << _("file")
        << "\t"           << _("remove keys listed in file (uids)")     << endl;
   cout << "\t-v [N]\t"   << _("remove not-valid keys")                 << endl;
   cout << "\t-t [N]\t"   << _("remove not-trusted keys")               << endl;
   cout << "\t\t\t"       << _("with N you can increase the maximum level")
                                                                        << endl;
}

