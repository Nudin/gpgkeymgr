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

#include "userinteraction.hpp"
#include "globalconsts.hpp"

#include <iostream>
#include <iomanip>
#include <libintl.h>
#define _(Text) gettext(Text) // _ as short version of gettext

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
Print out a statistics overview
*/
void printstatistics(int revokedkeys, int expiredkeys, int numberofkeys[6][6]) {
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
   cout << "\t-x "        << _("file")
        << "\t"           << _("do not remove keys listed in file (uids)")     << endl;
   cout << "\t-v [N]\t"   << _("remove not-valid keys")                 << endl;
   cout << "\t-t [N]\t"   << _("remove not-trusted keys")               << endl;
   cout << "\t\t\t"       << _("with N you can increase the maximum level")
                                                                        << endl;
}
