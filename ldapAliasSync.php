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
    public $task = 'login';

    // Internal variables
    private $initialised;
    private $app;
    private $config;
    private $rc_user;

    // mail parameters
    private $mail = array();
    private $search_domain;
    private $replace_domain;
    private $find_domain;
    private $separator;

    // LDAP parameters
    private $ldap;
    private $server;
    private $bind_dn;
    private $bind_pw;
    private $base_dn;
    private $filter;
    private $attr_mail;
    private $attr_name;
    private $attr_org;
    private $attr_reply;
    private $attr_bcc;
    private $attr_sig;
    private $fields;

    function init() {
        try {
            write_log('ldapAliasSync', 'Initialising');
            
            # Load default config, and merge with users' settings
            $this->load_config('config.inc.php');

            $this->app = rcmail::get_instance();
            $this->config = $this->app->config->get('ldapAliasSync');

            # Load plugin config at once
            $this->cfg_ldap 		= check_ldap_config($this->config['ldap']);
            $this->cfg_mail 		= check_mail_config($this->config['mail']);
            $this->cfg_user_search 	= check_user_config($this->config['user_search']);
            $this->cfg_alias_search 	= check_alias_config($this->config['alias_search']);
            

            # Load LDAP configs
            $this->server       = $this->ldap['server'];
            $this->bind_dn      = $this->ldap['bind_dn'];
            $this->bind_pw      = $this->ldap['bind_pw'];
            $this->base_dn      = $this->ldap['base_dn'];
            $this->filter       = $this->ldap['filter'];
            $this->attr_mail    = $this->ldap['attr_mail'];
            $this->attr_name    = $this->ldap['attr_name'];
            $this->attr_org     = $this->ldap['attr_org'];
            $this->attr_reply   = $this->ldap['attr_reply'];
            $this->attr_bcc     = $this->ldap['attr_bcc'];
            $this->attr_sig     = $this->ldap['attr_sig'];

            # Special features for attrs set above
            $this->attr_mail_ignore = $this->ldap['attr_mail_ignore'];

            # Convert all attribute names to lower case
            $this->attr_mail  = strtolower($this->attr_mail);
            $this->attr_name  = strtolower($this->attr_name);
            $this->attr_org   = strtolower($this->attr_org);
            $this->attr_reply = strtolower($this->attr_reply);
            $this->attr_bcc   = strtolower($this->attr_bcc);
            $this->attr_sig   = strtolower($this->attr_sig);

            $this->fields = array($this->attr_mail, $this->attr_name, $this->attr_org, $this->attr_reply,
                $this->attr_bcc, $this->attr_sig);

            # Load mail configs
            $this->search_domain  = $this->mail['search_domain'];
            $this->replace_domain = $this->mail['replace_domain'];
            $this->find_domain    = $this->mail['find_domain'];
            $this->separator      = $this->mail['dovecot_seperator'];

            # LDAP Connection
            $this->conn = ldap_connect($this->server);

            if ( is_resource($this->conn) ) {
                ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);

                # Bind to LDAP (with account or anonymously)
                if ( $this->bind_dn ){
                    $bound = ldap_bind($this->conn, $this->bind_dn, $this->bind_pw);
                } else {
                    $bound = ldap_bind($this->conn);
                }

                if ( $bound ) {
                    # register hook
                    $this->add_hook('login_after', array($this, 'login_after'));
                    $this->initialised = true;
                } else {
                    $log = sprintf("Bind to server '%s' failed. Con: (%s), Error: (%s)",
                        $this->server,
                        $this->conn,
                        ldap_errno($this->conn));
                    write_log('ldapAliasSync', $log);
                }
            } else {
                $log = sprintf("Connection to the server failed: (Error=%s)", ldap_errno($this->conn));
                write_log('ldapAliasSync', $log);
            }
        } catch ( Exception $exc ) {
            write_log('ldapAliasSync', 'Failed to initialise: '.$exc->getMessage());
        }

        if ( $this->initialised ) {
            write_log('ldapAliasSync', 'Initialised');
        }
    }
    
    function check_ldap_config($config) {
    	$SCHEMES = array('ldap', 'ldaps', 'ldapi');
   	
   	# Set default values for empty config parameters
    	(! $config['scheme']) : $config['scheme'] = 'ldap';
    	(! $config['server']) : $config['server'] = 'localhost';
    	(! $config['bind_dn']) : $config['bind_dn'] = '';
    	(! $config['bind_pw']) : $config['bind_pw'] = '';
    	
    	# Check parameters with fixed value set
    	(! in_array($config['scheme'], $SCHEMES)) : throw new Exception('[ldap] scheme "'.$config['scheme'].'" is invalid');

    	return $config;
    }
    
    function check_mail_config($config) {
    	# Set default values for empty config parameters
    	(! $config['search_domain']) : $config['search_domain'] = '';
    	(! $config['replace_domain']) : $config['replace_domain'] = false;
    	(! $config['dovecot_separator']) : $config['dovecot_separator'] = '';
    	
    	# Check parameter combinations
    	($config['replace_domain'] && ! $config['search_domain']) : throw new Exception('[mail] search_domain must not be initial, if replace_domain is set to "true"!');

    	return $config;
    }
    
    function check_user_config($config) {
    	$SCOPES   = array('base', 'one', 'sub');
    	$DEREFS   = array('never', 'find', 'search', 'always');
    	$MAIL_BYS = array('attribute', 'dn', 'memberof', 'static');
    	$NDATTRS  = array('break', 'skip');
    	
    	# Set default values for empty config parameters
    	(! $config['base_dn']) : $config['base_dn'] = '';
    	(! $config['filter']) : $config['filter'] = '(objectClass=*)';
    	(! $config['scope']) : $config['scope'] = 'base';
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
    	
    	# Check on empty parameters
    	(! $config['base_dn']) : throw new Exception('[user_search] base_dn must not be initial!');

    	# Check parameters with fixed value set
    	(! in_array($config['scope'], $SCOPES)) : throw new Exception('[user_search] scope "'.$config['scope'].'" is invalid');
    	(! in_array($config['deref'], $DEREFS)) : throw new Exception('[user_search] deref "'.$config['deref'].'" is invalid');
    	(! in_array($config['mail_by'], $MAIL_BYS)) : throw new Exception('[user_search] mail_by "'.$config['mail_by'].'" is invalid');
    	(! in_array($config['non_domain_attr'], $NDATTRS)) : throw new Exception('[user_search] non_domain_attr "'.$config['non_domain_attr'].'" is invalid');

    	# Check parameter combinations
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
    	$SCOPES   = array('base', 'one', 'sub');
    	$DEREFS   = array('never', 'find', 'search', 'always');
    	$MAIL_BYS = array('attribute', 'dn', 'memberof', 'static');
    	$NDATTRS  = array('break', 'skip');
    	
    	# Set default values for empty config parameters
    	(! $config['base_dn']) : $config['base_dn'] = '';
    	(! $config['filter']) : $config['filter'] = '(objectClass=*)';
    	(! $config['scope']) : $config['scope'] = 'base';
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
    	
    	# Check on empty parameters
    	(! $config['base_dn']) : throw new Exception('[alias_search] base_dn must not be initial!');

    	# Check parameters with fixed value set
    	(! in_array($config['scope'], $SCOPES)) : throw new Exception('[alias_search] scope "'.$config['scope'].'" is invalid');
    	(! in_array($config['deref'], $DEREFS)) : throw new Exception('[alias_search] deref "'.$config['deref'].'" is invalid');
    	(! in_array($config['mail_by'], $MAIL_BYS)) : throw new Exception('[alias_search] mail_by "'.$config['mail_by'].'" is invalid');
    	(! in_array($config['non_domain_attr'], $NDATTRS)) : throw new Exception('[alias_search] non_domain_attr "'.$config['non_domain_attr'].'" is invalid');

    	# Check parameter combinations
    	($config['mail_by'] == 'attribute' && ! $config['attr_mail']) : throw new Exception('[alias_search] attr_mail must not be initial, if mail_by is set to "attribute"!');
    	($config['mail_by'] == 'dn' && ! $config['attr_local']) : throw new Exception('[alias_search] attr_local must not be initial, if mail_by is set to "dn"!');
    	($config['mail_by'] == 'dn' && ! $config['attr_dom']) : throw new Exception('[alias_search] attr_dom must not be initial, if mail_by is set to "dn"!');
    	($config['mail_by'] == 'memberof' && ! $config['attr_local']) : throw new Exception('[alias_search] attr_local must not be initial, if mail_by is set to "memberof"!');
    	($config['mail_by'] == 'memberof' && ! $config['attr_dom']) : throw new Exception('[alias_search] attr_dom must not be initial, if mail_by is set to "memberof"!');
    	($config['mail_by'] == 'static' && ! $config['attr_local']) : throw new Exception('[alias_search] attr_local must not be initial, if mail_by is set to "static"!');
    	($config['mail_by'] == 'static' && ! $config['domain_static']) : throw new Exception('[alias_search] domain_static must not be initial, if mail_by is set to "static"!');
    	
    	return $config;
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
        $this->rc_user = rcmail::get_instance()->user;
        $login = $this->rc_user->get_username('mail');

        try {
            # Get the local part and the domain part of login
            if ( strstr($login, '@') ) {
                $login_parts = explode('@', $login);
                $local_part  = array_shift($login_parts);
                $domain_part = array_shift($login_parts);

                if ( $this->replace_domain && $this->search_domain ) {
                    $domain_part = $this->search_domain;
                }
            } else {
                $local_part = $login;
                if ( $this->search_domain ) {
                    $domain_part = $this->search_domain;
                }
            }

            # Check if dovecot master user is used.
            if ( strstr($login, $this->separator) ) {
                $log = sprintf("Removed dovecot impersonate separator (%s) in the login name", $this->separator);
                write_log('ldapAliasSync', $log);

                $local_part = array_shift(explode($this->separator, $local_part));
            }

            # Set the search email address
            if ( $domain_part ) {
                $login_email = "$local_part@$domain_part";
            } else {
                $domain_part = '';
                $login_email = '';
            }

            $filter = $this->filter;

            # Replace place holders in the LDAP base DN with login data
            $ldap_basedn = str_replace('%login', $login, $base_dn);
            $ldap_basedn = str_replace('%local', $local_part, $ldap_basedn);
            $ldap_basedn = str_replace('%domain', $domain_part, $ldap_basedn);
            $ldap_basedn = str_replace('%email', $login_email, $ldap_basedn);

            # Replace place holders in the LDAP filter with login data
            $ldap_filter = str_replace('%login', $login, $filter);
            $ldap_filter = str_replace('%local', $local_part, $ldap_filter);
            $ldap_filter = str_replace('%domain', $domain_part, $ldap_filter);
            $ldap_filter = str_replace('%email', $login_email, $ldap_filter);

            # Search for LDAP data
            $result = ldap_search($this->conn, $ldap_basedn, $ldap_filter, $this->fields);

            if ( $result ) {
                $info = ldap_get_entries($this->conn, $result);

                if ( $info['count'] >= 1 ) {
                    $log = sprintf("Found the user '%s' in the database", $login);
                    write_log('ldapAliasSync', $log);

                    $identities = array();

                    # Collect the identity information
                    for($i=0; $i<$info['count']; $i++) {
                        write_log('ldapAliasSync', $i);
                        $email = null;
                        $name = null;
                        $organization = null;
                        $reply = null;
                        $bcc = null;
                        $signature = null;

                        $ldapID = $info["$i"];
                        $ldap_temp = $ldapID[$this->attr_mail];
                        $email = $ldap_temp[0];
                        if ( $this->attr_name ) {
                            $ldap_temp = $ldapID[$this->attr_name];
                            $name = $ldap_temp[0];
                        }
                        if ( $this->attr_org ) {
                            $ldap_temp = $ldapID[$this->attr_org];
                            $organisation = $ldap_temp[0];
                        }
                        if ( $this->attr_reply ) {
                            $ldap_temp = $ldapID[$this->attr_reply];
                            $reply = $ldap_temp[0];
                        }
                        if ( $this->attr_bcc ) {
                            $ldap_temp = $ldapID[$this->attr_bcc];
                            $bcc = $ldap_temp[0];
                        }
                        if ( $this->attr_sig ) {
                            $ldap_temp = $ldapID[$this->attr_sig];
                            $signature = $ldap_temp[0];
                        }

                        $ldap_temp = $ldapID[$this->attr_mail];
                        for($mi = 0; $mi < $ldap_temp['count']; $mi++) {
                            $email = $ldap_temp[$mi];
                            # If we only found the local part and have a find domain, append it
                            if ( $email && !strstr($email, '@') && $this->find_domain ) $email = "$email@$this->find_domain";

                            # Only collect the identities with valid email addresses
                            if ( strstr($email, '@') ) {
                                # Verify that domain part is not ignored
                                $domain = explode('@', $email)[1];
                                if ( is_array($this->attr_mail_ignore) and in_array($domain, $this->attr_mail_ignore) ) continue;

                                if ( !$name )         $name         = '';
                                if ( !$organisation ) $organisation = '';
                                if ( !$reply )        $reply        = '';
                                if ( !$bcc )          $bcc          = '';
                                if ( !$signature )    $signature    = '';

                                # If the signature starts with an HTML tag, we mark the signature as HTML
                                if ( preg_match('/^\s*<[a-zA-Z]+/', $signature) ) {
                                    $isHtml = 1;
                                } else {
                                    $isHtml = 0;
                                }

                                $identity = array(
                                    'email'          => $email,
                                    'name'           => $name,
                                    'organization'   => $organisation,
                                    'reply-to'       => $reply,
                                    'bcc'            => $bcc,
                                    'signature'      => $signature,
                                    'html_signature' => $isHtml,
                                );

                                array_push($identities, $identity);
                            } else {
                                $log = sprintf("Domain missing in email address '%s'", $email);
                                write_log('ldapAliasSync', $log);
                            }
                        }
                    }

                    if ( count($identities) > 0 && $db_identities = $this->rc_user->list_identities() ) {
                        # Check which identities not yet contained in the database
                        foreach ( $identities as $identity ) {
                            $in_db = false;

                            foreach ( $db_identities as $db_identity ) {
                                # email is our only comparison parameter
                                if( $db_identity['email'] == $identity['email'] ) {
                                    if (isset($this -> config['update_identity']) && $this -> config['update_identity']) {
                                        if (!isset($this -> config['update_only_nonempty_fields']) || $this -> config['update_only_nonempty_fields']) {
                                            foreach ($identity as $key => $value) {
                                                if (empty($identity[$key])) unset($identity[$key]);
                                            }
                                        }
                                        $this->rc_user->update_identity ( $db_identity['identity_id'], $identity );
                                        $log = "Updated identity: ".$identity['email'];
                                    }
                                    write_log('ldapAliasSync', $log);
                                    $in_db = true;
                                    break;
                                }
                            }
                            if( !$in_db ) {
                                $this->rc_user->insert_identity( $identity );
                                $log = "Added identity: ".$identity['email'];
                                write_log('ldapAliasSync', $log);
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
                                $log = sprintf("Removed identity: ", $del_id);
                                write_log('ldapAliasSync', $log);
                            }
                        }
                    }
                } else {
                    $log = sprintf("User '%s' not found (pass 2). Filter: %s", $login, $ldap_filter);
                    write_log('ldapAliasSync', $log);
                }
            } else {
                $log = sprintf("User '%s' not found (pass 1). Filter: %s", $login, $ldap_filter);
                write_log('ldapAliasSync', $log);
            }

            ldap_close($this->conn);
        } catch(Exception $e) {
            echo 'Caught exception: ',  $e->getMessage(), "\n";
	}
        return $args;
    }
}
?>
