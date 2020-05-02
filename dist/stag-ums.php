<?php
/**
 * Name:            Stag UMS (Part of StagPHP Core Library)
 * Description:     Contains final executable functions
 *                  of the StagPHP User Management System.
 *
 * @package:        StagPHP Library File
 */

/** Stag UMS base Functions */
require_once 'functions.php';

/** User Session Management Main Class */
class stag_ums extends stag_ums_base {
    /** DB Type */
    private $db_type;

    /** DB Table Name */
    private $table_name;

    /** DB Salt Field Name */
    private $db_salt = 'su_login_salt';

    /** DB IP Field Name */
    private $db_ip = 'su_ip';

    /** DB Browser ID Field Name */
    private $browser_id = 'su_browser_id';
}