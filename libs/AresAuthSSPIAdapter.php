<?php
/**
 *	Integration Authentication with Microsoft Windows Active Directory 
 *  Create By: Dennis
 *  Create Date: 2009-04-02 13:10
 * 
 *  $HeadURL: https://192.168.0.101/svn/ehr/trunk/eHR/libs/AresAuthSSPIAdapter.php $
 *  $Id: AresAuthSSPIAdapter.php 1536 2009-05-06 05:39:40Z dennis $
 *  $LastChangedDate: 2009-05-06 13:39:40 +0800 (周三, 06 五月 2009) $ 
 *  $LastChangedBy: dennis $
 *  $LastChangedRevision: 1536 $  
 \****************************************************************************/
require_once 'AresIAuthAdapter.php';
require_once 'AresAuthResult.php';

class AresAuthSSPIAdapter implements AresIAuthAdapter {
	
	private $_dBConn;
	private $_credit;
	private $_account;
	private $_domain;
	private $_companyId;
	private $_userName;
	private $_passwd;
	
	/**
	 * Constructor of class AresAuthSSPIAdapter
	 *
	 * @param ADODB_oci8 $db_conn
	 * @param string $remote_user
	 */
	public function __construct(ADODB_oci8 $db_conn,$remote_user)
	{
		$this->_dBConn = $db_conn;
		$this->_credit = $remote_user;
	}// end class constructor
	
	protected function _getAuthorityName()
	{
		if (!empty($this->_credit))
		{
			$cred = explode('\\',$this->_credit);
			if (count($cred) == 1) array_unshift($cred, 'no domain info - perhaps SSPIOmitDomain is On');
			list($this->_domain, $this->_account) = $cred;
		}// end if
	}// end _getAuthorityName()
	
	
	public function authenticate()
	{
		$this->_getAuthorityName();
		$code  = AresAuthResult::FAILURE;
		$messages[0] = '';
		$messages[1] = '';
		if (!$this->_account) {
            $code = AresAuthResult::FAILURE_IDENTITY_NOT_FOUND;
            $messages[0] = 'A username is required';
            return new AresAuthResult($code, '', $messages);
        }
		if (!$this->_domain) {
            $code = AresAuthResult::FAILURE_DOMAIN_IS_NULL;
            $messages[0] = 'No domain info - perhaps SSPIOmitDomain is On';
            return new AresAuthResult($code, '', $messages);
        }
        //$email = $this->_account.'@'.$this->_domain.'.com';
        
        $this->_getRealUserName(strtolower($this->_account));
        $identity = $this->_userName;
		if (!$identity) {
            $code = AresAuthResult::FAILURE_IDENTITY_NOT_FOUND;
            $messages[0] = 'User name was not found.(-- NT Account not found in HCP user table )';
            return new AresAuthResult($code, '', $messages);
        }// end if
        $code = AresAuthResult::SUCCESS;
		return new AresAuthResult($code,$identity,$messages);
	}// end authenticate()
	
	private function _getRealUserName($email)
	{
		$user_info = $this->_getUserInfo($email);
		$this->_userName  = $user_info['USERNAME'];
		$this->_companyId = $user_info['COMPANY_ID'];
		$this->_passwd    = $user_info['PASSWD'];
	}// end _getRealUserName
	
	private function _getUserInfo($email)
	{
		$sql = <<<eof
			select username_no_sz    as username,
				   username_password as passwd,
			       seg_segment_no    as company_id
			  from app_users
			 where lower(substr(email, 0, instr(email, '@') - 1)) = :email
eof;
		//$this->_dBConn->debug = true;
		$this->_dBConn->SetFetchMode(ADODB_FETCH_ASSOC);
		return $this->_dBConn->GetRow($sql,array('email'=>strtolower($email)));
	}// end _getUserInfo()
	
	public function getUserName()
	{
		return $this->_userName;
	}
	
	public function getCompanyId()
	{
		return $this->_companyId;
	}
	
	public function getPasswd()
	{
		return $this->_passwd;
	}
}// end class AresSSO
