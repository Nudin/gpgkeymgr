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

#include "copyfile.hpp"

#include <iostream>
#include <fstream>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libintl.h>

#include "stringutil.hpp"
#include "userinteraction.hpp"

using namespace std;
#define _(Text) gettext(Text) // _ as short version of gettext


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
