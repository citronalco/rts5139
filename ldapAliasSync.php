<?php
/*
 * LDAP Alias Sync: Syncronize users' identities (name, email, organization, reply-to, bcc, signature)
 * by querying an LDAP server's aliasses.
 *
 * Based on the 'IdentiTeam' Plugin by André Rodier <andre.rodier@gmail.com>
 * Author: Lukas Mika <lukas.mika@web.de>
 * Licence: GPLv3. (See copying)
 */
class ldapAliasSync extends rcube_plugin {
// ---------- Global variables
	// Internal variables
	public  $task = 'login';
	private $initialised;
	private $app;
	private $rc_user;

	// Config variables
	private $config    = array();
	private $cfg_ldap  = array();
	private $cfg_mail  = array();
	private $cfg_user  = array();
	private $cfg_alias = array();

	// Plugin variables
	private $ldap_con;

// ---------- Main functions
	// Plugin initialization
	function init() {
		try {
			write_log('ldapAliasSync', 'Initialising');

			// Load general roundcube config settings
			$this->load_config('config.inc.php');
			$this->app = rcmail::get_instance();

			// Load plugin config settings
			$this->config = $this->app->config->get('ldapAliasSync');

			$this->cfg_ldap	  = check_ldap_config($this->config['ldap']);
			$this->cfg_mail	  = check_mail_config($this->config['mail']);
			$this->cfg_user	  = check_user_config($this->config['user_search']);
			$this->cfg_alias  = check_alias_config($this->config['alias_search']);
			$this->cfg_update = check_update_config($this->config['update']);

			$this->ldap_con  = initialize_ldap($this->cfg_ldap);

			if ( is_resource($this->ldap_con) ) {
				// register hook
				$this->add_hook('login_after', array($this, 'login_after'));
				$this->initialised = true;
			}
		} catch ( Exception $exc ) {
			write_log('ldapAliasSync', 'Failed to initialise: '.$exc->getMessage());
		}

		if ( $this->initialised ) {
			write_log('ldapAliasSync', 'Initialised');
		}
	}

	/**
	 * login_after
	 * 
	 * See http://trac.roundcube.net/wiki/Plugin_Hooks
	 * Arguments:
	 * - URL parameters (e.g. task, action, etc.)
	 * Return values:
	 * - task
	 * - action 
	 * - more URL parameters
	 */
	function login_after($args) {
		private $login = array();

		try {
			$this->rc_user = rcmail::get_instance()->user;
			$login = get_login_info($this->rc_user->get_username('mail'), $this->cfg_mail);

			$identities = fetch_identities($login);
			sync_identities_db($identities);
		} catch ( Exception $exc ) {
			write_log('ldapAliasSync', 'Runtime error: '.$exc->getMessage());
		}

		return $args;
	}			

	function fetch_identities($login) {
		private users   = array();
		private user    = array();
		private aliases = array();
		private alias   = array();
		private identities = array();

		$users = get_ldap_identities($this->ldap_con, $login, $this->cfg_user);

		if ( $identities['count'] = 0 ) {
			throw new Exception(sprintf("User '%s' not found.", $login['login']));
		}

		foreach ( $users as $user ) {
			array_push($identities, $user);
			$aliases = get_ldap_identities($this->ldap_con, $login, $this->cfg_alias, $user['dn']);
			foreach ( $aliases as $alias ) {
				array_push($identities, $alias);
			}
		}

		return $identities;
	}

	function get_ldap_identities($con, $login, $config, $dn = '') {
		private $base_dn = $config['base_dn'];
		private $filter  = $config['filter'];
		private $fields  = array();
		private $bound   = false;
		private $result;
		private $entries = array();

		// Prepare LDAP query base DN
		$base_dn = str_replace('%login', $login['login'], $base_dn);
		$base_dn = str_replace('%local', $login['local'], $base_dn);
		$base_dn = str_replace('%domain', $login['domain'], $base_dn);
		$base_dn = str_replace('%email', $login['email'], $base_dn);
		$base_dn = str_replace('%dn', $dn, $base_dn);
		$base_dn = str_replace('%%', '%', $base_dn);

		// Prepare LDAP query filter
		$filter = str_replace('%login', $login['login'], $filter);
		$filter = str_replace('%local', $login['local'], $filter);
		$filter = str_replace('%domain', $login['domain'], $filter);
		$filter = str_replace('%email', $login['email'], $filter);
		$filter = str_replace('%dn', $dn, $filter);
		$filter = str_replace('%%', '%', $filter);

		// Prepare LDAP query attributes
		( $config['attr_mail'] ) : array_push($fields, $config['attr_mail']);
		( $config['attr_local'] ) : array_push($fields, $config['attr_local']);
		( $config['attr_dom'] ) : array_push($fields, $config['attr_dom']);
		( $config['attr_name'] ) : array_push($fields, $config['attr_name']);
		( $config['attr_org'] ) : array_push($fields, $config['attr_org']);
		( $config['attr_reply'] ) : array_push($fields, $config['attr_reply']);
		( $config['attr_bcc'] ) : array_push($fields, $config['attr_bcc']);
		( $config['attr_sig'] ) : array_push($fields, $config['attr_sig']);
		( $config['mail_by'] == 'memberof' ) : array_push($fields, 'memberof');

		// Bind to server
		if ( $config['bind_dn'] ){
			$bound = ldap_bind($con, $config['bind_dn'], $config['bind_pw']);
		} else {
			$bound = ldap_bind($con);
                }

		if ( ! $bound ) {
			throw new Exception(sprintf("Bind to server '%s' failed. Con: (%s), Error: (%s)", $this->cfg_ldap['server'], $con, ldap_errno($con)));
		}

		$result = ldap_search($con, $base_dn, $filter, $fields, 0, 0, 0, $config['deref']);

		if ( $result ) {
			$entries = ldap_get_entries($con, $result);
		}

		ldap_close($con);

		foreach ( $entries as $entry ) {
			$ids = get_ids_from_obj($entry, $config);
			foreach ( $ids as $id ) {
				array_push($identities, $id);
			}
		}

		return $identities;
	}

	function get_ids_from_obj($ldap_id, $config) {
		private $identity = array();
		private $identities = array();
		private $entries = array();
		private $entry = array();
		private $local;
		private $domain;
		private $break = true;

		// Get attributes
		$identity['dn'] = $ldap_id['dn'];

		if ( $config['attr_name'] ) {
			$ldap_temp = $ldap_id[$config['attr_name']];
			$identity['name'] = $ldap_temp[0];
		}

		if ( $config['attr_org'] ) {
			$ldap_temp = $ldap_id[$config['attr_org']];
			$identity['organization'] = $ldap_temp[0];
		}

		if ( $config['attr_reply'] ) {
			$ldap_temp = $ldap_id[$config['attr_reply']];
			$identity['reply-to'] = $ldap_temp[0];
		}

		if ( $config['attr_bcc'] ) {
			$ldap_temp = $ldap_id[$config['attr_bcc']];
			$identity['bcc'] = $ldap_temp[0];
		}

		if ( $config['attr_sig'] ) {
			$ldap_temp = $ldap_id[$config['attr_sig']];
			$identity['signature'] = $ldap_temp[0];
		}

		if ( preg_match('/^\s*<[a-zA-Z]+/', $identity['signature']) ) {
			$identity['html_signature'] = 1;
		} else {
			$identity['html_signature'] = 0;
		}

		// Get e-mail address
		switch $config['mail_by'] {
			case 'attribute':
				$ldap_temp = $ldap_id[$config['attr_mail']];
				foreach ( $ldap_temp as $attr ) {
					if ( strstr($attr, '@') {
						$domain = explode('@', $attr)[1];
						if ( $domain && ! in_array( $domain, $config['ignore_domains']) ) {
							$identity['email'] = $attr;
						}
					}
				}
				break;
			case 'dn':
				$ldap_temp = $ldap_id[$config['attr_local']];
				$local = $ldap_temp[0];
				( $config['non_domain_attr'] == 'skip' ) : $break = false ? $break = true;
				$domain = get_domain_name($ldap_id['dn'], $config['attr_dom'], $break);
				if ( $local && $domain && ! in_array($domain, $config['ignore_domains']) ) {
					$identity['email'] = $local.'@'.$domain;
					array_push($identities, $identity);
				}
				break;
			case 'memberof':
				$ldap_temp = $ldap_id[$config['attr_local']];
				$local = $ldap_temp[0];
				( $config['non_domain_attr'] == 'skip' ) : $break = false ? $break = true;
				$ldap_temp = $ldap_id['memberof'];
				foreach ( $ldap_temp as $memberof ) {
					$domain = get_domain_name($memberof, $config['attr_dom', $break);
					if ( $local && $domain && ! in_array($domain, $config['ignore_domains']) ) {
						$identity['email'] = $local.'@'.$domain;
						array_push($identities, $identity);
					}
				}
				break;
			case 'static':
				$ldap_temp = $ldap_id[$config['attr_local']];
				$local = $ldap_temp[0];
				if ( $local && $config['domain_static'] && ! in_array($config['domain_static'], $config['ignore_domains']) ) {
					$identity['email'] = $local.'@'.$config['domain_static'];
					array_push($identities, $identity);
				}
				break;
		}
		return $identities;
	}

	function sync_identities_db($identities) {
		private $db_identities;
		private $db_identity;
		private $identity;
		private $key;
		private $value;
		private $in_db;
		private $in_ldap;

		if ( count($identities) > 0 && $db_identities = $this->rc_user->list_identities() ) {

			# Check which identities not yet contained in the database
			foreach ( $identities as $identity ) {
				$in_db = false;

				foreach ( $db_identities as $db_identity ) {
					# email is our only comparison parameter
					if( $db_identity['email'] == $identity['email'] ) {
						if ( $this->cfg_update['update_existing'] ) {
							if ( ! $this->cfg_update['update_empty_fields']) {
								foreach ($identity as $key => $value) {
									if ( empty($identity[$key]) ) {
										unset($identity[$key]);
									}
								}
							}
							$this->rc_user->update_identity ( $db_identity['identity_id'], $identity );
						}
						$in_db = true;
						break;
					}
				}

				if( !$in_db ) {
					$this->rc_user->insert_identity( $identity );
				}
			}

			# Check which identities are available in database but nut in LDAP and delete those
			foreach ( $db_identities as $db_identity ) {
				$in_ldap = false;

				foreach ( $identities as $identity ) {
					# email is our only comparison parameter
					if( $db_identity['email'] == $identity['email'] ) {
						$in_ldap = true;
						break;
					}
				}
                            
				# If this identity does not exist in LDAP, delete it from database
				if( !$in_ldap ) {
					$this->rc_user->delete_identity($db_identity['identity_id']);
				}
			}
		}
	}

// ---------- Helper functions
	function initialize_ldap($config) {
		private $uri;
		private $con;

		$uri = $config['scheme'].'://'.$config['server'].':'.$config['port'];

		$con = ldap_connect($uri);
		if ( is_resource($con) ) {
			ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
			return $con;
		} else {
			throw new Exception(sprintf("Connection to the server failed: (Error=%s)", ldap_errno($con));
		}
	}

	function get_login_info($info, $config) {
		private $login = array();

		$login['login'] = $info;

		if ( strstr($info, '@') ) {
			$login_parts = explode('@', $info);

			$login['local'] = array_shift($login_parts);
			$login['domain'] = array_shift($login_parts);

			if ( $config['replace_domain'] && $config['search_domain'] ) {
				$login['domain'] = $config['search_domain'];
			}
		} else {
			$login['local'] = $login;

			if ( $config['search_domain'] ) {
				$login['domain'] = $config['search_domain'];
			}
		}

		if ( $config['dovecot_separator'] && strstr($login['local'], $config['dovecot_separator']) ) {
			$login['local'] = array_shift(explode($config['dovecot_separator'], $login['local']));
		}

		if ( $login['local'] && $login['domain'] ) {
			$login['email'] = $login['local']."@".$login['domain'];
		}

		return $login;
	}

	function get_domain_name( $dn, $attr, $break = true ) {
    		$found = false;
		$domain = '';

		$dn_parts = explode(',', $dn);

		foreach( $dn_parts as $dn_part ) {
			$objs = explode('=', $dn_part);
			if ($objs[0] == $attr) {
				$found = true;
				if ( strlen( $domain ) == 0 ) {
					$domain = $objs[1];
				} else {
					$domain .= ".".$objs[1];
				}
			} elseif ( $found == true && $break == true ) {
				break;
			}
		}
		return $domain;
	}

// ---------- Configuration functions
	function check_ldap_config($config) {
		$SCHEMES = array('ldap', 'ldaps', 'ldapi');

		// Set default values for empty config parameters
		(! $config['scheme']) : $config['scheme'] = 'ldap';
		(! $config['server']) : $config['server'] = 'localhost';
		(! $config['port']) : $config['port'] = '389';
		(! $config['bind_dn']) : $config['bind_dn'] = '';
		(! $config['bind_pw']) : $config['bind_pw'] = '';

		// Check parameters with fixed value set
		(! in_array($config['scheme'], $SCHEMES)) : throw new Exception('[ldap] scheme "'.$config['scheme'].'" is invalid');

		return $config;
	}

	function check_mail_config($config) {
		// Set default values for empty config parameters
		(! $config['search_domain']) : $config['search_domain'] = '';
		(! $config['replace_domain']) : $config['replace_domain'] = false;
		(! $config['dovecot_separator']) : $config['dovecot_separator'] = '';

		// Check parameter combinations
		($config['replace_domain'] && ! $config['search_domain']) : throw new Exception('[mail] search_domain must not be initial, if replace_domain is set to "true"!');

		return $config;
	}

	function check_user_config($config) {
		$DEREFS   = array($LDAP_DEREF_NEVER, $LDAP_DEREF_FINDING, $LDAP_DEREF_SEARCHING, $LDAP_DEREF_ALWAYS);
		$MAIL_BYS = array('attribute', 'dn', 'memberof', 'static');
		$NDATTRS  = array('break', 'skip');

		// Set default values for empty config parameters
		(! $config['base_dn']) : $config['base_dn'] = '';
		(! $config['filter']) : $config['filter'] = '(objectClass=*)';
		(! $config['deref']) : $config['deref'] = 'never';
		(! $config['mail_by']) : $config['mail_by'] = 'attribute';
		(! $config['attr_mail']) : $config['attr_mail'] = 'mail' ? $config['attr_mail'] = strtolower($config['attr_mail']);
		(! $config['attr_local']) : $config['attr_local'] = '' ? $config['attr_local'] = strtolower($config['attr_local']);
		(! $config['attr_dom']) : $config['attr_dom'] = '' ? $config['attr_dom'] = strtolower($config['attr_dom']);
		(! $config['domain_static']) : $config['domain_static'] = '';
		(! $config['ignore_domains']) : $config['ignore_domains'] = array();
		(! $config['non_domain_attr']) : $config['non_domain_attr'] = 'break';
		(! $config['attr_name']) : $config['attr_name'] = '' ? $config['attr_name'] = strtolower($config['attr_name']);
		(! $config['attr_org']) : $config['attr_org'] = '' ? $config['attr_org'] = strtolower($config['attr_org']);
		(! $config['attr_reply']) : $config['attr_reply'] = '' ? $config['attr_reply'] = strtolower($config['attr_reply']);
		(! $config['attr_bcc']) : $config['attr_bcc'] = '' ? $config['attr_bcc'] = strtolower($config['attr_bcc']);
		(! $config['attr_sig']) : $config['attr_sig'] = '' ? $config['attr_sig'] = strtolower($config['attr_sig']);

		// Override values
		switch $config['deref'] {
			case 'never':
				$config['deref'] = $LDAP_DEREF_NEVER;
				break;
			case 'search':
				$config['deref'] = $LDAP_DEREF_SEARCHING;
				break;
			case 'find':
				$config['deref'] = $LDAP_DEREF_FINDING;
				break;
			case 'always':
				$config['deref'] = $LDAP_DEREF_ALWAYS;
				break;
		}

		// Check on empty parameters
		(! $config['base_dn']) : throw new Exception('[user_search] base_dn must not be initial!');

		// Check parameters with fixed value set
		(! in_array($config['deref'], $DEREFS)) : throw new Exception('[user_search] deref "'.$config['deref'].'" is invalid');
		(! in_array($config['mail_by'], $MAIL_BYS)) : throw new Exception('[user_search] mail_by "'.$config['mail_by'].'" is invalid');
		(! in_array($config['non_domain_attr'], $NDATTRS)) : throw new Exception('[user_search] non_domain_attr "'.$config['non_domain_attr'].'" is invalid');

		// Check parameter combinations
		($config['mail_by'] == 'attribute' && ! $config['attr_mail']) : throw new Exception('[user_search] attr_mail must not be initial, if mail_by is set to "attribute"!');
		($config['mail_by'] == 'dn' && ! $config['attr_local']) : throw new Exception('[user_search] attr_local must not be initial, if mail_by is set to "dn"!');
		($config['mail_by'] == 'dn' && ! $config['attr_dom']) : throw new Exception('[user_search] attr_dom must not be initial, if mail_by is set to "dn"!');
		($config['mail_by'] == 'memberof' && ! $config['attr_local']) : throw new Exception('[user_search] attr_local must not be initial, if mail_by is set to "memberof"!');
		($config['mail_by'] == 'memberof' && ! $config['attr_dom']) : throw new Exception('[user_search] attr_dom must not be initial, if mail_by is set to "memberof"!');
		($config['mail_by'] == 'static' && ! $config['attr_local']) : throw new Exception('[user_search] attr_local must not be initial, if mail_by is set to "static"!');
		($config['mail_by'] == 'static' && ! $config['domain_static']) : throw new Exception('[user_search] domain_static must not be initial, if mail_by is set to "static"!');

		return $config;
	}

	function check_alias_config($config) {
		$DEREFS   = array('never', 'find', 'search', 'always');
		$MAIL_BYS = array('attribute', 'dn', 'memberof', 'static');
		$NDATTRS  = array('break', 'skip');

		// Set default values for empty config parameters
		(! $config['base_dn']) : $config['base_dn'] = '';
		(! $config['filter']) : $config['filter'] = '(objectClass=*)';
		(! $config['deref']) : $config['deref'] = 'never';
		(! $config['mail_by']) : $config['mail_by'] = 'attribute';
		(! $config['attr_mail']) : $config['attr_mail'] = 'mail' ? $config['attr_mail'] = strtolower($config['attr_mail']);
		(! $config['attr_local']) : $config['attr_local'] = '' ? $config['attr_local'] = strtolower($config['attr_local']);
		(! $config['attr_dom']) : $config['attr_dom'] = '' ? $config['attr_dom'] = strtolower($config['attr_dom']);
		(! $config['domain_static']) : $config['domain_static'] = '';
		(! $config['ignore_domains']) : $config['ignore_domains'] = array();
		(! $config['non_domain_attr']) : $config['non_domain_attr'] = 'break';
		(! $config['attr_name']) : $config['attr_name'] = '' ? $config['attr_name'] = strtolower($config['attr_name']);
		(! $config['attr_org']) : $config['attr_org'] = '' ? $config['attr_org'] = strtolower($config['attr_org']);
		(! $config['attr_reply']) : $config['attr_reply'] = '' ? $config['attr_reply'] = strtolower($config['attr_reply']);
		(! $config['attr_bcc']) : $config['attr_bcc'] = '' ? $config['attr_bcc'] = strtolower($config['attr_bcc']);
		(! $config['attr_sig']) : $config['attr_sig'] = '' ? $config['attr_sig'] = strtolower($config['attr_sig']);

		// Override values
		switch $config['deref'] {
			case 'never':
				$config['deref'] = $LDAP_DEREF_NEVER;
				break;
			case 'search':
				$config['deref'] = $LDAP_DEREF_SEARCHING;
				break;
			case 'find':
				$config['deref'] = $LDAP_DEREF_FINDING;
				break;
			case 'always':
				$config['deref'] = $LDAP_DEREF_ALWAYS;
				break;
		}

		// Check on empty parameters
		(! $config['base_dn']) : throw new Exception('[alias_search] base_dn must not be initial!');

		// Check parameters with fixed value set
		(! in_array($config['deref'], $DEREFS)) : throw new Exception('[alias_search] deref "'.$config['deref'].'" is invalid');
		(! in_array($config['mail_by'], $MAIL_BYS)) : throw new Exception('[alias_search] mail_by "'.$config['mail_by'].'" is invalid');
		(! in_array($config['non_domain_attr'], $NDATTRS)) : throw new Exception('[alias_search] non_domain_attr "'.$config['non_domain_attr'].'" is invalid');

		// Check parameter combinations
		($config['mail_by'] == 'attribute' && ! $config['attr_mail']) : throw new Exception('[alias_search] attr_mail must not be initial, if mail_by is set to "attribute"!');
		($config['mail_by'] == 'dn' && ! $config['attr_local']) : throw new Exception('[alias_search] attr_local must not be initial, if mail_by is set to "dn"!');
		($config['mail_by'] == 'dn' && ! $config['attr_dom']) : throw new Exception('[alias_search] attr_dom must not be initial, if mail_by is set to "dn"!');
		($config['mail_by'] == 'memberof' && ! $config['attr_local']) : throw new Exception('[alias_search] attr_local must not be initial, if mail_by is set to "memberof"!');
		($config['mail_by'] == 'memberof' && ! $config['attr_dom']) : throw new Exception('[alias_search] attr_dom must not be initial, if mail_by is set to "memberof"!');
		($config['mail_by'] == 'static' && ! $config['attr_local']) : throw new Exception('[alias_search] attr_local must not be initial, if mail_by is set to "static"!');
		($config['mail_by'] == 'static' && ! $config['domain_static']) : throw new Exception('[alias_search] domain_static must not be initial, if mail_by is set to "static"!');

		return $config;
	}

	function check_update_config($config) {
		// Set default values for empty parameters
		(! $config['update_existing']) : $config['update_existing'] = false;
		(! $config['update_empty_fields']) : $config['update_existing'] = false;

		return $config;
	}
}
?>
