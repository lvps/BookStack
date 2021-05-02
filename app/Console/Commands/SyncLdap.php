<?php

namespace BookStack\Console\Commands;

use Auth;
use Hash;
use Str;
use Log;
use BookStack\Auth\Access\ExternalAuthService;
use BookStack\Auth\Access\Ldap;
use Illuminate\Console\Command;
use BookStack\Auth\Access\LdapService;
use BookStack\Auth\Role;
use BookStack\Auth\User;
use BookStack\Auth\Access\Guards\LdapSessionGuard;


class SyncLdap extends Command
{
    /**
     * Used to sync users with LDAP server on a per request basis
     *
     * Use case:
     * SSO logins need user account to exist/roles synced prior to login
     *
     * .env setting examples:
     * LDAP_SYNC_USER_FILTER=(&(memberOf=CN=app-bookstack,OU=groups,OU=Access,DC=example.com))
     *  the origin to sync
     * LDAP_SYNC_USER_RECURSIVE_GROUPS=true
     *  if there's nested groups, pull those in too
     * LDAP_SYNC_EXCLUDE_EMAIL="admin@example.com,testaccount@example.com"
     *  comma seperated list of strings
     *  allow for email exclusions to be defined to skip adding the accounts
     *  uses string matching, so can also block wildcards (ie: "-disabled")
     */

    public $users = array();
    public $users_checked = array();
    public $cn_checked = array(); // list of groups that have already been fetched
    public $groups = array();
    public $sync_user_filter;
    public $sync_user_recursive_groups;
    public $sync_user_exclude_email;
    public $id_attribute;
    public $LDAP;
    public $ldap;


    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'bookstack:syncldap {filter? : Optional LDAP filter for initial group pull}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Batch syncs LDAP users and groups';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();

        $config = config('services.ldap');
        $this->id_attribute = strtolower($config['id_attribute']);
        $this->sync_user_filter = $config['sync_user_filter'];
        $this->sync_user_recursive_groups = $config['sync_user_recursive_groups'];
        $this->sync_user_exclude_email = $config['sync_user_exclude_email'];
        $this->LDAP = new Ldap();
        $this->ldap = new LdapService($this->LDAP);
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        if ($this->argument('filter')) {
            $this->sync_user_filter = $this->argument('filter');
        }

        Log::info("[syncldap] starting...");
        if (config('auth.method') !== 'ldap' && !config('auth.ldap_provision')) {
            dd("Must be using ldap for auth method or provisioning");
        }

        Log::info("[syncldap] retrieving users");
        // get all users with the LDAP_SYNC_USER_FILTER
        //   [Use that to limit specific group/dn users to be auto-added]
        $data = $this->ldap->getAllUsers();
        $groups = $this->ldap->getAllGroups();

        // if there's a nested group/cn found in the users returned, recurse those as well
        //   [recursion enabled/disabled with LDAP_SYNC_USER_RECURSIVE_GROUPS]
        $this->checkDnForUserRecursive($data);

        Log::info("[syncldap] retrieved " . count($this->users) . " in " . count($this->cn_checked) . " groups");
        $usercount = 1;

        // check if there's any strings to exclude from emails
        if ($this->sync_user_exclude_email) {
            $email_excludes = explode(',', $this->sync_user_exclude_email);
        } else {
            $email_excludes = false;
        }

        $found_ids = [];
        $dnToUser = [];
        // run thru the returned list of all user records
        foreach ($this->users as $userdata) {
            // did we find an id_attribute?
            if (isset($userdata[$this->id_attribute][0])) {
                $user_id = $userdata[$this->id_attribute][0];

                Log::info("[syncldap] fetching user details for " . $user_id . " (" . $usercount . "/" . count($this->users) . ")");

                $found_ids[$user_id] = true;

                // fetch the user details and check if they exist
                $ldapUserDetails = $this->ldap->getUserDetails($user_id);

                $exclude = false;
                if(!isset($ldapUserDetails['email'])) {
					 $exclude = true;
				}

                // check if email in excludes array
                if(is_array($email_excludes)) {
                    foreach($email_excludes as $exclude_string) {
                        if(strpos($ldapUserDetails["email"], trim($exclude_string)) !== false) {
                            $exclude = true;
                        }
                    }
                }

                if(!$exclude) {
                    $user = User::where('email', '=', $ldapUserDetails["email"])->first();
                    if ($user === null) {
                        // user doesn't exist
                        $user = new User();

                        $user->name = $ldapUserDetails['name'];
                        $user->email = $ldapUserDetails['email'];
                        $user->password = Hash::make(Str::random(32));
                        $user->email_confirmed = true;
                        $user->external_auth_id = $user_id;

                        $user->refreshSlug();
                        $user->save();
                        $dnToUser[$ldapUserDetails['dn']] = $user;
                    } else {
                        // user exists but this is the first time they're being paired to LDAP
                        //   so set the external_auth_id
                        $changed = false;
                        if(is_null($user->external_auth_id)) {
							$user->external_auth_id = $user_id;
							$changed = true;
                        }
                        if($user->name != $ldapUserDetails['name']) {
							$user->name = $ldapUserDetails['name'];
							$changed = true;
						}
						if(!$user->email_confirmed) {
							$user->email_confirmed = true;
							$changed = true;
						}
							//$user->email = $ldapUserDetails['email'];
						if($changed) {
							$user->refreshSlug();
                            $user->save();
                        }
                        $dnToUser[$ldapUserDetails['dn']] = $user;
                    }
                    // sync the user groups to bookstack groups
                    Log::info("[syncldap] done syncing " . $user_id . " (" . $usercount . "/" . count($this->users) . ")");

                    //$this->ldap->syncGroups($user, $user_id);
                } else {
                    Log::info("[syncldap] user in exclude list " . $user_id . "  (" . $usercount . "/" . count($this->users) . ")");
                }


                $usercount++;
            }
        }

        $this->parseGroups($groups, $dnToUser);

        // Avoid catastrophic deletion of every user
        if(count($found_ids) > 0) {
			$users = User::whereNotNull('external_auth_id')->get();
			foreach($users as $user) {
				if(strlen($user->external_auth_id) <= 0) {
					continue;
				}

				if(!isset($found_ids[$user->external_auth_id])) {
					// TODO: what happens to owned books?
					// Soft delete
					$deleted_id = substr(sha1($user->external_auth_id), 0, 10) . time();
					$user->name = "Deleted $deleted_id";
					$user->refreshSlug();
					$user->save();

					// Hard delete
// 					$user->delete();
				}
			}
        }
    }

    private function checkDnForUserRecursive($data)
    {
        // passes in the results of LdapService->getAllUsers (uses LDAP_SYNC_USER_FILTER)
        // needs to recurse and check for all nested groups
        //  nested recursion can be enabled/disabled with LDAP_SYNC_USER_RECURSIVE_GROUPS
        for ($i = 0; $i < count($data); $i++) {
            if (isset($data[$i][$this->id_attribute][0])) {
                $userdata = $data[$i][$this->id_attribute][0];
                if (!in_array($userdata, $this->users_checked)) {
                    $this->users_checked[] = $userdata;
                    $this->users[] = $data[$i];
                }
            } elseif ((isset($data[$i]["dn"]) && $this->sync_user_recursive_groups)) {
                // found a nested group record [dn => cn=GROUP ] for recursion
                $new_dn = $data[$i]["dn"];
                foreach ($this->LDAP->explodeDn($new_dn, 0) as $attribute) {
                    // pop out the cn record for the group name
                    $pieces = explode("=", $attribute);
                    if (strtolower($pieces[0]) == 'cn') {
                        // was the group already checked?
                        if (!in_array($pieces[1], $this->cn_checked)) {
                            $filter = "(memberOf=" . $new_dn . ")";
                            $this->cn_checked[] = $pieces[1];
                            $newdata = $this->ldap->getAllUsers($filter);
                            $this->checkDnForUserRecursive($newdata);
                        }
                    }
                }
            }
        }
    }

    private function parseGroups($data, $dnToUser)
    {
		$dnToUuid = [];
        for($i = 0; $i < count($data); $i++) {
            if(isset($data[$i]['nsuniqueid'][0]) && isset($data[$i]['cn'][0])) {
                $cn = $data[$i]['cn'][0];
                //$name = str_replace(' ', '-', trim(strtolower($cn)));
                $external_id = $data[$i]['nsuniqueid'][0];
                $description = "$cn group from SSO";
                if(isset($data[$i]['member'])) {
					foreach($data[$i]['member'] as $member) {
						$dnToUuid[$member][] = $external_id;
					}
                }

				$role = Role::where('external_auth_id', '=', $external_id)->first();

				if($role === null) {
					// user doesn't exist
					$role = new Role();

					$role->display_name = $cn;
					$role->description = $description;
					$role->external_auth_id = $external_id;

					$role->save();
				} else {
					// user exists but this is the first time they're being paired to LDAP
					//   so set the external_auth_id
					$changed = false;
					if($role->display_name != $cn) {
						$role->display_name = $cn;
						$changed = true;
					}
					if($role->description != $description) {
						$role->description = $description;
						$changed = true;
					}
					if($changed) {
						$role->save();
					}
				}
			}
		}

		foreach($dnToUuid as $dn => $uuids) {
			$user = $dnToUser[$dn] ?? null;
			if($user) {
				$this->ldap->syncWithGroups($user, $uuids);
				$count = count($uuids);
				Log::info("[syncldap] added $count roles to $user->external_auth_id (unless syncWithGroups failed)");
			}
		}
	}
}
