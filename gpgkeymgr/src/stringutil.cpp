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
#include <libintl.h>

#include "stringutil.hpp"

using namespace std;

#define _(Text) gettext(Text) // _ as short version of gettext

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

