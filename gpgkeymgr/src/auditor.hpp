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

#include <vector>
#include <string>
using namespace std;

#ifndef _auditor_hpp_
#define _auditor_hpp_

class auditor{
  
  public:
    auditor();
    void setvalues(bool, bool, bool, bool, int, bool, int, bool, vector<string>, bool, vector<string>);
    bool test(bool, bool, int, int, string);
    string generatequestion();
    
  private:
    bool auditor_revoked;	// delete keys that are revoked
    bool auditor_expired;	// delete keys that are expired
    bool auditor_novalid;	int auditor_max_valid;	// delete keys that are not valid (engough)
    bool auditor_notrust;	int auditor_max_trust;	// delete keys that are not trusted (engough)
    bool auditor_altern;	// treat arguments as alternative
    bool auditor_poslist;	vector<string> auditor_list_pos;	// List of keys to delete
    bool auditor_neglist;	vector<string> auditor_list_neg;	// List of keys NOT to delete
};


#endif
