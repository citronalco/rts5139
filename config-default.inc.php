<?php
/*
 * Default configuration settings for ldapAliasSync roundcube plugin
 * Copy this file in config.inc.php, and override the values you need.
*/

$rcmail_config['ldapAliasSync'] = array(
    // Mail parameters
    'mail' => array(
        # Domain to use for LDAP searches (optional)
        # If no login name is given (or 'replace_domain' is true),
        # the domain part for the LDAP filter is set to this value
        # Default: none
        #'search_domain'     => '',
        
        # Replace domain part for LDAP searches (optional)
        # This parameter can be used in order to override the login domain part with
        # the value maintained in 'search_domain'
        # Possible values: true, false
        # Default: false
        #'replace_domain'    => false,
        
        # Dovecot master user seperator (optional)
        # If you use the dovecot impersonation feature, this seperator will be used
        # in order to determine the actual login name.
        # Set it to the same character if using this feature, otherwise you can also
        # leave it empty.
        # Default: none
        #'dovecot_seperator' => '',
    ),

    // LDAP parameters
    'ldap' => array(
        # LDAP server address (required)
        'server'     => 'ldap://localhost',
        
        # LDAP Bind DN (requried, if no anonymous read rights are set for the accounts)
        'bind_dn'    => 'cn=mail,ou=services,dc=example,dc=com',
        
        # Bind password (required, if the bind DN needs to authenticate)
        'bind_pw'    => 'secret',
    ),
    
    # 'user_search' holds all config variables for the user search
    'user_search' => array(
        # LDAP search base (required)
        # - Use '%login' as a place holder for the login name
        # - Use '%local' as a place holder for the login name local part
        # - Use '%domain' as a place holder for the login name domain part (/'search_domain', if not given or replaced)
        # - Use '%email' as a place holder for the email address ('%local'@'%domain')
        'base_dn'    => 'uid=%local,ou=users,dc=example,dc=com',
        
        # LDAP search filter (optional)
        # This open filter possibility is the heart of the LDAP search.
        # - Use '%login' as a place holder for the login name
        # - Use '%local' as a place holder for the login name local part
        # - Use '%domain' as a place holder for the login name domain part (/'search_domain', if not given or replaced)
        # - Use '%email' as a place holder for the email address ('%local'@'%domain')
        # Default: '(objectClass=*)'
        #'filter'     => '(objectClass=*)',
        
        # LDAP search scope (optional)
        # Either search the base DN itself, a level below the base DN or the whole subtree
        # Possible values: 'base', 'one', 'sub'
        # Default: 'base'
        #'scope'      => 'base',
        
        # LDAP alias derefencing (optional)
        # Possible values: never, search, find, always
        # Default: 'never'
        #'deref'      => 'never',
        
        # How to find the e-mail addresses (required)
        # Possible values are:
        # - 'attribute' - e-mail address will be taken from the entry's 'attr_mail' attribute
        # - 'dn'        - e-mail address local part will be taken from the entry's 'attr_local';
        #                 e-mail address domain part will be taken from the DN's 'attr_dom' attributes
        # - 'memberof'  - e-mail address local part will be taken form the entry's 'attr_local';
        #                 e-mail address domain part will be taken from the memberOf attributes' 'attr_dom' attributes
        # - 'static'    - e-mail address local part will be taken form the entry's 'attr_local';
        #                 e-mail address domain part will be copied from 'domain_static'
        'mail_by'    => 'attribute',
        
        # LDAP e-mail attribute (required, if 'mail_by' is 'attribute')
        'attr_mail'  => 'mail',
        
        # LDAP e-mail local part attribute (required, if 'mail_by' is 'dn', 'memberof' or 'static')
        #'attr_local' => 'uid',
        
        # LDAP e-mail domain part attribute (required, if 'mail_by' is 'dn' or 'memberof')
        #'attr_dom'   => 'dc'
        
        # Static domain to append to local parts (required, if 'mail_by' is 'static')
        #'domain_static'  => 'example.com',

        # Users with one of the following domains will be ignored (optional)
        # Default: none
        #'ignore_domains' => array(),
        
        # How to handle non-domain attributes in a DN (optional)
        # Set to true, if you want to break up the search (e.g. uid=u1,dc=mail,dc=de,ou=dom,dc=example,dc=com --> mail.de)
        # Set to false, if you want to skip non-domain attributes (e.g. uid=u1,dc=mail,dc=de,ou=dom,dc=example,dc=com --> mail.de.example.com)
        # Possible values: true, false
        # Default: true
        #'break_dom'     => true,

        ### The following attributes can be fetched from LDAP in order to provide additional identity information
        
        # LDAP name attribute (optional)
        # Default: none
        #'attr_name'  => '',
        
        # LDAP organization attribute (optional)
        # Default: none
        #'attr_org'   => '',
        
        # LDAP reply-to attribute (optional)
        # Default: none
        #'attr_reply' => '',
        
        # LDAP bcc (blind carbon copy) attribute (optional)
        # Default: none
        #'attr_bcc'   => '',
        
        # LDAP signature attribute (optional)
        # Default: none
        #'attr_sig'   => '',
    ),
    
    # 'alias_search' holds all config variables for the alias search
    'user_search' => array(
        # LDAP search base (required)
        # - Use '%login' as a place holder for the login name
        # - Use '%local' as a place holder for the login name local part
        # - Use '%domain' as a place holder for the login name domain part (/'search_domain', if not given or replaced)
        # - Use '%email' as a place holder for the email address ('%local'@'%domain')
        # - Use '%dn' as a place holder for the DN returned by the user search
        'base_dn'    => 'ou=aliases,dc=example,dc=com',
        
        # LDAP search filter (optional)
        # This open filter possibility is the heart of the LDAP search.
        # - Use '%login' as a place holder for the login name
        # - Use '%local' as a place holder for the login name local part
        # - Use '%domain' as a place holder for the login name domain part (/'search_domain', if not given or replaced)
        # - Use '%email' as a place holder for the email address ('%local'@'%domain')
        # - Use '%dn' as a place holder for the DN returned by the user search
        # Default: '(objectClass=*)'
        #'filter'     => '(objectClass=*)',
        
        # LDAP search scope (optional)
        # Either search the base DN itself, a level below the base DN or the whole subtree
        # Possible values: 'base', 'one', 'sub'
        # Default: 'base'
        #'scope'      => 'base',
        
        # LDAP alias derefencing (optional)
        # Possible values: never, search, find, always
        # Default: 'never'
        #'deref'      => 'never',
        
        # How to find the e-mail addresses (required)
        # Possible values are:
        # - 'attribute' - e-mail address will be taken from the entry's 'attr_mail' attribute
        # - 'dn'        - e-mail address local part will be taken from the entry's 'attr_local';
        #                 e-mail address domain part will be taken from the DN's 'attr_dom' attributes
        # - 'memberof'  - e-mail address local part will be taken form the entry's 'attr_local';
        #                 e-mail address domain part will be taken from the memberOf attributes' 'attr_dom' attributes
        # - 'static'    - e-mail address local part will be taken form the entry's 'attr_local';
        #                 e-mail address domain part will be copied from 'domain_static'
        'mail_by'    => 'attribute',
        
        # LDAP e-mail attribute (required, if 'mail_by' is 'attribute')
        'attr_mail'  => 'mail',
        
        # LDAP e-mail local part attribute (required, if 'mail_by' is 'dn', 'memberof' or 'static')
        #'attr_local' => 'uid',
        
        # LDAP e-mail domain part attribute (required, if 'mail_by' is 'dn' or 'memberof')
        #'attr_dom'   => 'dc'
        
        # Static domain to append to local parts (required, if 'mail_by' is 'static')
        #'domain_static'  => 'example.com',

        # Users with one of the following domains will be ignored (optional)
        # Default: none
        #'ignore_domains' => array(),

        # How to handle non-domain attributes in a DN (optional)
        # Set to true, if you want to break up the search (e.g. uid=u1,dc=mail,dc=de,ou=dom,dc=example,dc=com --> mail.de)
        # Set to false, if you want to skip non-domain attributes (e.g. uid=u1,dc=mail,dc=de,ou=dom,dc=example,dc=com --> mail.de.example.com)
        # Possible values: true, false
        # Default: true
        #'break_dom'     => true,

        ### The following attributes can be fetched from LDAP in order to provide additional identity information
        
        # LDAP name attribute (optional)
        # Default: none
        #'attr_name'  => '',
        
        # LDAP organization attribute (optional)
        # Default: none
        #'attr_org'   => '',
        
        # LDAP reply-to attribute (optional)
        # Default: none
        #'attr_reply' => '',
        
        # LDAP bcc (blind carbon copy) attribute (optional)
        # Default: none
        #'attr_bcc'   => '',
        
        # LDAP signature attribute (optional)
        # Default: none
        #'attr_sig'   => '',
    ),

    # Update identity (optional)
    # Set to true, if you want update an existing identity with the same e-mail address in the database
    # Possible values: true, false
    # Default: false
    #'update_identity' => false,

    # Update only nonempty fields of the identity (optional)
    # Set to false if you want to also update empty fields of the identity.
    # Possible values: true, false
    # Default: true
    #'update_only_nonempty_fields' => true
);
?>
