<?php
/**
 * Name:            Stag UMS (Part of StagPHP Core Library)
 * Description:     Contains StagPHP User Management System.
 *                  It relies on Stag JDB
 *
 * @package:        StagPHP Library File
 * @version:        V 1.0.0
 */

/** Stag UMS base Functions */
require_once 'functions.php';

/** User Session Management Main Class */
class stag_ums extends stag_ums_base {
  /** DB Configuration */
  private $db_table_name;
  private $db_login_salt_field  = 'su_login_salt';
  private $db_ip_field          = 'su_ip';
  private $db_browser_id_field  = 'browser_id';

  /** Main constructor function */
  function __construct($db_table_name){
    /** Call parent Constructor */
    parent::__construct();

    /** Setting up table name */
    if(isset($db_table_name)) $this->db_table_name = $db_table_name;
  }

  /** Login function
   * 
   * It create New Session on successful
   * login. Also updates session data
   * including browser stamp, to prevent
   * simultaneous access */
  function create_session($data){
    // Return error if username and password is not valid
    if(!isset($data['username']) || !isset($data['password'])) return array(
      'status'      => false,
      'description' => 'User does not exits!'
    );
    
    $username = $data['username'];
    $password = $data['password'];

    if(isset($data['remember']) && $data['remember']) $remember_me = TRUE;
    else $remember_me = FALSE;

    // Creating user DB Object
    $user_db = new CYZ_JDB(STAG_CONTAINER_DIR.'/jdb/');

    // Initialize DB with table name specified
    $user_db->db_init($this->db_table_name);

    // get all user data
    $users_data = $user_db->get_table($this->db_table_name);

    // Loop through user data
    foreach($users_data as $key => $user_data){
      if($username == $user_data['su_username']){
        /** Encrypt password hash */
        $password = md5($password);

        /** Compare password hash
        * return false if password hash comparison fails */
        if($password != $user_data['su_password']) return array(
          'status'      => false,
          'description' => 'Password does not match!'
        );

        // Destroy Old Session
        if(isset($user_data['session_id'])){
          session_id($user_data['session_id']);
          session_start();
          session_destroy();
        }

        /** Create new super user session and
         * set Double Encrypted Password */
        $session_id = parent::create_session($username, md5($password), $remember);

        /**
         * Update DB with session salt
         * and browser ID */
        $user_db->update_row(
          $this->db_table_name,
          $key,
          array(
            'su_username'               => $user_data['su_username'],
            'su_password'               => $user_data['su_password'],
            'session_id'                => $session_id,
            $this->db_login_salt_field  => parent::get_cookie_salt(),
            $this->db_ip_field          => parent::get_user_ip(),
            $this->db_browser_id_field  => parent::get_user_agent(),
          )
        );

        return array(
          'status'      => TRUE,
          'description' => 'User successfully logged in!'
        );
      }
    }

    // Return Error
    return array(
      'status'      => false,
      'description' => 'User does not exits!'
    );
  }

  /** Verify Session
   * 
   * Used for auto login. This function
   * verifies active sessions of the logged-in
   * users. In case of any error on verification
   * or invalid session, it deletes session data
   * and logout the users */
  function verify_session(){
    $verification_result = parent::verify_php_session();

    /** Auto Login Case 1
     * 
     * If PHP session not found. Verify user based
     * on session cookie. This is only possible when
     * users checks remember me option. */
    if('SESSION NOT FOUND' == $verification_result['status']){
      $cookie_data = parent::get_cookie();

      // If cookie is not set or does not exits return false 
      if(!isset($cookie_data) || !is_array($cookie_data)) return FALSE;

      // Creating user DB Object
      $user_db = new CYZ_JDB(STAG_CONTAINER_DIR.'/jdb/');

      // Initialize DB with table name specified
      $user_db->db_init($this->db_table_name);

      // get all user data
      $users_data = $user_db->get_table($this->db_table_name);

      /** Return if user data not found */
      if(empty($users_data)) return false;

      // Verify Cookie
      $validation = parent::verify_cookie_session($cookie_data, $users_data);

      // In case cookie is forged or not valid
      if('VALID' == $validation['status']) return FALSE;

      /** Retrieve user id from cookie */
      $user_id = cyz_base64_decode($cookie_data[0]);

      // Retrieve user password from cookie
      $password = $cookie_data[1];

      // Extend remember me duration
      if('30DAYS' == $cookie_data[5]) $remember = true;
      else $remember = false;

      // Create new super user session
      parent::create_session($user_id, $password, $remember);

      /** Update DB with session salt */
      $user_db->update_column_data(
        $this->db_table_name,
        $validation['key'],
        $this->db_login_salt_field,
        parent::get_cookie_salt()
      );

      return TRUE;
    }

    /** Auto Login Case 2
     * 
     * If PHP session is found. Verify user based
     * PHP session, check browser id for extra protection */
    else if('VALID' == $verification_result['status']){
      $user_id = $verification_result['user_id'];

      // Creating user DB Object
      $user_db = new CYZ_JDB(STAG_CONTAINER_DIR.'/jdb/');

      // Initialize DB with table name specified
      $user_db->db_init($this->db_table_name);

      // get all user data
      $users_data = $user_db->get_table($this->db_table_name);

      /** Return if user data not found */
      if(empty($users_data)) return false;

      /** Loop through user data */
      foreach($users_data as $key => $user_data){
        /** Get user with user ID */
        if(isset($user_data["su_username"]) && $user_id == $user_data["su_username"]){
          if(parent::get_user_agent() != $user_data['su_browser_id']) return FALSE;
        }
      }

      return TRUE;
    }

    return FALSE;
  }

  function logout($slug = null){
    // Something went wrong
    if(!defined('SU_ID')) define('SU_ID', null);

    // Delete Session
    parent::delete_session();

    // redirect
    if(isset($slug)) header("Location: ".get_home_url().$slug);
    else header("Location: ".get_home_url());
    exit;
  }
}