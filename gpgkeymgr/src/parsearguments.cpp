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
#include <stdio.h>

#include "vectorutil.hpp"
#include "parsearguments.hpp"

void help();

using namespace std;

int parsearguments(int argc, char *argv[], auditor& keyauditor,
				 bool& dobackup, string& destination, bool& statistics, bool& onlystatistics,
				 bool& quiet, bool& dry, bool& yes ) {
   bool revoked  = false;
   bool expired  = false;
   bool novalid  = false;	int max_valid = 0;
   bool notrust  = false;	int max_trust = 0;
   bool altern   = false;
   bool poslist  = false;	vector<string> list;
   
   dobackup = false;	destination = "";
   statistics = false; // Print out statistics
   onlystatistics = false; 
   quiet    = false;  // For quiet-mode
   dry      = false;  // For dry-mode
   yes      = false;  // For 'yes-mode'

   // Test if at least one argument has been given
   if ( argc == 1 ) {
      help();
      return 1;
   }

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
            return -1;
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

   if ( !revoked && !expired && !novalid && !notrust && !poslist && statistics )
         onlystatistics=true;

   keyauditor.setvalues(altern, revoked, expired, novalid,
					max_valid, notrust, max_trust, poslist,
				 	list);
   return 0;
}
