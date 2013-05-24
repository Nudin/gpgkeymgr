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
#include <fstream>
#include <algorithm>
#include <libintl.h>

#include "vectorutil.hpp"
#include "stringutil.hpp"

using namespace std;

#define _(Text) gettext(Text) // _ as short version of gettext


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
