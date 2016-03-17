<?php
/**************************************************************************\
  
 \****************************************************************************/
class Kl_AresUser
{
    // private variables
    private $_companyId; // login user company id
    //private $_userSeqNo; // login user seq no in user table(app_users)
    private $_userName;  // login user id
    private $_dBConn;    // database connection handle

    /**
     * constructor of class AresUser
     *
     * @param string $company_id
     * @param string $user_name
     */
    function __construct($company_id,$user_name) {
        global $g_db_sql;
        $this->_dBConn    = $g_db_sql;
        $this->_companyId = strtoupper($company_id);
        $this->_userName  = strtoupper($user_name);
        //$this->_dBConn->debug = true;
    }

 
    public function  KL_check_user($username_no_sz)
    {
    	$sql = <<<eof
    		select kl_check_user( :company_id, :username_sz )
			  from dual 
eof;
    	//$this->_dBConn->debug =1;
    	return $this->_dBConn->GetOne($sql,array('company_id'=>$this->_companyId,
    			'username_sz'=>$username_no_sz));
    }
}// end class KL_ARESUser()
