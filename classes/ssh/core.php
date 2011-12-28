<?php
/**
 * SSH Library includes the ability to connect to a host and verify its key, login with a username/password or a ssh key.
 * Currently capable of SCP, directory navigation, and directory listing
 * 
 * 
 * @package    Jexmex/SSH
 * @author     Jexmex <sparks.craig@gmail.com>
 * @copyright  (c) 2011 Jexmex
 * @license    MIT
 */
class SSH_Core
{
    /**/
    protected $_connected = False;
    
    protected $_conn_link;
    
    protected $_config = array(
            'host' => 'localhost',
            'host_fingerprint' => NULL,
            'port' => 22,
            'user' => NULL,
            'authentication_method' => 'PASS',
            'password' => NULL,
            'pub_key' => NULL,
            'private_key' => NULL,
            'passphrase' => NULL,
            'auto_connect' => True,
        );
    
    /**
     * The constructor method that initiates the class
     * 
     * Pass a configuration array with the following values
     * 
     * array (
     *      'host' => 'THE.HOST.TO.CONNECT.TO', //IP or Hostname
     *      'host_fingerprint' => 'HOSTFINGERPRINT', //The fingerprint of the host to authenticate with.  If this is NULL no check will be done (but this is not recommened)
     *      'port' => '22', //The port to use to connect
     *      'user' => 'myuser', //The user to connect with
     *      'authentication_method' => 'KEY', //The authentication method, either KEY or PASS
     *      'password' => NULL, //The password to use or NULL if using key authentication
     *      'pub_key' => '/location/to/pub/ssh/key', //The location of the servers/users public ssh key. NULL if using password
     *      'private_key' => '/location/to/private/ssh/key', //The location of the servers/users private ssh key. NULL if using password
     *      'passphrase' => 'thisismypassphrase', //The passphrase for the ssh key, if there is not one, set to NULL
     *      'auto_connect' => True, //Should the server be auto-connected to during class initialization (defaults to True)
     * )
     * 
     * @param $config array Array of configuration items
     */
    public function __construct(array $config)
    {
        $this->_config = $config + $this->_config;
        
        //This ensures the fingerprint is formatted the same as the way ssh2_fingerprint returns it
        $this->_config['host_fingerprint'] = strtoupper(str_replace(':','',$this->_config['host_fingerprint']));
        
        if($this->_config['auto_connect'] == True)
        {
            $this->connect();
        }
    }
    
    /**
     * Connect to host
     * 
     * Connects to the host.  Throws exception if the host is unable to be connected to.  Will automatically
     * verify the host fingerprint, if one was provided, and throw an exception if the fingerprint is not
     * verified.
     * 
     */
    public function connect()
    {
        //Attempt to connect to host
        $link = ssh2_connect($this->_config['host'],$this->_config['port']);
        
        //If host connection fails, throw exception
        if(!$link)
        {
            throw Kohana_Exception("Unable to connect to :host on port :port",array(":host" => $host,":port" => $port));
        }
        else
        {
            //Assign the connection link to the class property
            $this->_conn_link = $link;
            
            //If host fingerprint is not NULL, attempt to verify fingerprint
            if($this->_config['host_fingerprint'] !== NULL)
            {
                $verify = $this->verify_host_fingerprint();
                
                //If the fingerprint is not verified, throw exception
                if(!$verify)
                {
                    throw new Kohana_Exception("Unable to verify host fingerprint");
                }
            }
        }
        
        //Attempt to login user
        if($this->_config['authentication_method'] == 'KEY')
        {
            $this->login_key();
        }
        else
        {
            $this->login_password();
        }
    }
    
    /**
     * Connection check
     * 
     * This method is suppose to check to see if the host is still connected to, but at this time,
     * I am unaware of a way to do this with SSH2 functions.
     * 
     * @ignore This is currently unused and should be ignored
     */
    public function check_connection()
    {
        /* AS OF THIS TIME, I DO NOT THINK ITS POSSIBLE TO CHECK THE CONNECTION*/
    }
    
    /**
     * Verify host fingerprint
     * 
     * Verifies the host fingerprint.
     * 
     * @return True on success, False on failure
     */
    protected function verify_host_fingerprint()
    {
        //Get the hosts fingerprint
        $fingerprint = ssh2_fingerprint($this->_conn_link);

        //Check the returned fingerprint, to the one expected
        if($this->_config['host_fingerprint'] === $fingerprint)
        {
            return True;
        }
        else
        {
            return False;
        }
    }
    
    /**
     * Login using a key
     * 
     * This will attempt to login using the provided user and a hash key.
     * 
     * @return bool True on success, False on failure 
     */
    public function login_key()
    {
        //TODO: add location for pub/private key files
        return ssh2_auth_pubkey_file($this->_conn_link,$this->_config['pub_key'],$this->_config['private_key'],$this->_config['passphrase']);
    }
    
    /**
     * Login using password
     * 
     * Attempts to login using the provided user and a password
     * 
     * @return bool True on success, False on failure
     */
    public function login_password()
    {
        return ssh2_auth_password($this->_conn_link,$this->_config['user'],$this->_config['password']);
    }
    
    /**
     * Sends a file to the remote server using scp
     * 
     * Attempts to send a file via SCP to the remote server currently connected to
     * 
     * @param $local_path string The path to the file to send
     * @param $remote_path string The path to the remote location to save the file
     */
    public function send_file($local_path,$remote_path,$create_mode = 0644)
    {
        //First verify the local file exists
        if(!file_exists($local_path))
        {
            throw new Kohana_Exception("File does not exist locally.");
        }
        
        //Attempt to send the file
        $send = @ssh2_scp_send($this->_conn_link,$local_path,$remote_path,$create_mode);
        
        //If send fails, throw exception
        if($send == False)
        {
            throw new Kohana_Exception("Unable to save file remotely");
        }
        else
        {
            return True;
        }
    }
    
    /**
     * Requests a file from the remote server using SCP
     * 
     * Attempts to request and save a file from the currently connected to server using SCP.
     * 
     * @param $local_path string The path to save the file to on local server
     * @param $remote_path string The path to the remote file that is being requested
     */
     
    public function request_file($local_path,$remote_path)
    {
        $get = @ssh2_scp_receive($this->_conn_link,$remote_path,$local_path);
		
        //If receive fails, throw exception
        if($get == False)
        {
            throw new Kohana_Exception("Unable to save file from remote");
        }
        else
        {
            return True;
        }
    }
    
    /**
     * Moves a file on the remote server
     * 
     * Attempts move a file on the connected server
	 * 
	 * @param $old_path string Path to original file location
	 * @param $new_path string Path to move file to
     */
    public function move_remote_file($old_path,$new_path)
    {
        $mv = @ssh2_exec($this->_conn_link,"mv $old_path $new_path");
		
        if($mv == False)
        {
            throw new Kohana_Exception("Unable to move file on remote server");
        }
        else
        {
            return True;
        }
    }
    
    /**
     * Copies a file on the remote server
     * 
     * Attempts to copy of a file on the connected server
	 * 
	 * @param $path string Path to original file location
	 * @param $copy_to string Path to copy file to
     */
    public function copy_remote_file($path,$copy_to)
    {
        $cp = @ssh2_exec($this->_conn_link,"cp $path $copy_to");
		
        if($cp == False)
        {
            throw new Kohana_Exception("Unable to copy file on remote server");
        }
        else
        {
            return True;
        }
    }
	
	/**
	 * Disconnects from the connected server
	 */
    public function disconnect()
    {    	
        @ssh2_exec($this->_conn_link, 'echo "EXITING" && exit;');
		
        $this->_conn_link = NULL;
    }
    
	/**
	 * Deconstructor called when class instance is destroyed
	 */
    public function __destruct()
    {
        $this->disconnect();
    }
}