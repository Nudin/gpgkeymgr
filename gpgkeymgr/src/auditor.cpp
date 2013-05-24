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
#include <stdio.h>
#include <stdlib.h>

#include "auditor.hpp"
#include "vectorutil.hpp"
#include "stringutil.hpp"

#define _(Text) gettext(Text) // _ as short version of gettext

using namespace std;


auditor::auditor()
: auditor_revoked(false), auditor_expired(false), auditor_novalid(false), 
  auditor_max_valid(0), auditor_notrust(false), auditor_max_trust(0),
  auditor_altern(false), auditor_poslist(false)
  {}

void auditor::setvalues (bool altern, bool revoked, bool expired, bool novalid,
					int max_valid, bool notrust, int max_trust, bool poslist,
				 	vector<string> list) {
   auditor_revoked   = revoked;
   auditor_expired   = expired;
   auditor_novalid   = novalid;
   auditor_max_valid = max_valid;
   auditor_notrust   = notrust;
   auditor_max_trust = max_trust;
   auditor_altern    = altern;
   auditor_poslist   = poslist;
   auditor_list      = list;
}


bool auditor::test(bool revoked, bool expired, int validity, int owner_trust, string keyid) {
         /* Test if to remove key */
         if ( auditor_altern ) { // any given criteria induce deletion
            if ( auditor_revoked && revoked ) 
               return true;
            else if ( auditor_expired && expired ) 
               return true;
            else if ( auditor_novalid && validity <= auditor_max_valid ) 
               return true;
            else if ( auditor_notrust && owner_trust <= auditor_max_trust  ) 
               return true;
            else if ( auditor_poslist && 
                        searchvector(auditor_list, shortenuid(keyid))  ) 
               return true;
         }
         else { // all given criteria together induce deletion
            if ( (!auditor_revoked || ( auditor_revoked && revoked )) &&
                 (!auditor_expired || ( auditor_expired && expired )) &&
                 (!auditor_novalid || ( auditor_novalid && validity <= auditor_max_valid )) &&
                 (!auditor_notrust || ( auditor_notrust && owner_trust <= auditor_max_trust ))    &&
                 (!auditor_poslist || ( auditor_poslist &&
                          searchvector(auditor_list, shortenuid(keyid))) )
               ) {
                 return true;
                 }
         }
         return false;
}


string auditor::generatequestion() {
   /* Generate security-question */
   string mode;
   if (auditor_altern)
      mode = _(" or ");
   else
      mode = _(" and ");
   string question = _("Do you really want to delete all keys which are ");
   if ( auditor_revoked )
      question += _("revoked")        + mode;
   if ( auditor_expired )
      question += _("expired")        + mode;
   if ( auditor_novalid )
      question += _("unvalid") + string(" (≤") + NumberToString(auditor_max_valid) + ")" + mode;
   if ( auditor_notrust )
      question += _("untrusted") + string(" (≤") + NumberToString(auditor_max_trust) + ")" + mode;
   if ( auditor_poslist )
      question += _("listed in file") + mode;
   // remove last 'and':
   question = question.substr(0, question.length()-mode.length());
   // for languages which need also something at the end of the questions:
   question += _("###");
   if ( question.substr(question.length()-3, question.length()) == "###")
      question = question.substr(0, question.length()-3);
   question += "?";
   return question;
}
