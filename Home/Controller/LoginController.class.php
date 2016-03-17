<?php 
namespace Home\Controller;
use Think\Controller;

include_once (DOCROOT.'/conf/config.inc.php');
$cookieDomain = dirname ( dirname ( $_SERVER ['PHP_SELF'] ) );
$home_url = $GLOBALS['config']['curr_home'] . '/index.php';

$authtype = isset($_GET['authtype']) && !empty($_GET['authtype']) ?
$_GET['authtype'] : 'default';

$companyid = '';
$username  = '';
$passwd    = '';
switch ($authtype) {
	
	case 'default':
		if (isset($_POST['companyno']) &&
		isset($_POST['username'])  &&
		isset($_POST['password']))
		{
			$username  = htmlentities ($_POST['username'], ENT_QUOTES, 'UTF-8' );
			$companyid = $_POST['companyno'];
			$passwd    = $_POST['password'];
		}
		break;
		
	case 'sspi':
		if (isset($_GET['remote_user'])    &&
		!empty($_GET['remote_user'])   &&
		isset($_GET['sessid'])         &&
		!empty($_GET['sessid']))
		{
			require_once 'AresAuth.php';
			require_once 'AresAuthSSPIAdapter.php';
			$sspi_auth = new AresAuthSSPIAdapter($g_db_sql,$_GET['remote_user']);
			$auth = AresAuth::getInstance();
			$result = $auth->authenticate($sspi_auth);
			if($result->isValid())
			{
				$username  = $auth->getIdentity();
				$companyid = $sspi_auth->getCompanyId();
				$passwd    = $sspi_auth->getPasswd();
			}
		}
		
	case 'eip':
		if (isset($_GET['companyno']) &&
		isset($_GET['username'])  &&
		isset($_GET['password']))
		{
			$username  = htmlentities(base64_decode($_GET['username']),ENT_QUOTES,'UTF-8');
			$companyid = base64_decode($_GET['companyno']);
			$passwd    = base64_decode($_GET['password']);
		}
		break;
	default:break;
}

if (!empty($companyid) && !empty($username) && !empty($passwd))
{
	$langcode  = isset($_POST['lang']) && !empty($_POST['lang']) ?
	$_POST['lang']:$GLOBALS['config']['default_lang'];
	require_once 'AresUser.class.php';
	echo $companyid ;
	echo $username;
	require_once 'KL_AresUser.class.php';
	$KLUser = new KL_AresUser($companyid,$username);
	$username= $KLUser->KL_check_user($username);
	echo $companyid ;
	echo $username;
	
	$User = new AresUser($companyid,$username);
	$home_url .= '?lang=' .$langcode. '&companyno=' .$companyid;
	$home_url .= '&loginerror=';
	
	if ($User->IsUserExits ()) {
		
		if ($User->isPasswordValid($passwd)) {
			
			$mss_perm = $User->CheckPermission ('MDN');
			if ($User->CheckPermission ('ESN') or '1' == $mss_perm ) {
				setCookie ('companyid',$companyid, time () + 3600 * 24 * 365, $cookieDomain );
				setCookie ('language', $langcode, time () + 3600 * 24 * 365, $cookieDomain );
				setCookie ('username', $username, time () + 3600 * 24 * 365, $cookieDomain );
				$_SESSION ['user']['language'] = $langcode;
				// get user profile
				$result = $User->GetUserInfo ();
				$_SESSION ['user']['company_id']  = $companyid; 
				$_SESSION ['user']['user_seq_no'] = $result ['USER_SEQ_NO'];
				$_SESSION ['user']['emp_seq_no']  = $result ['USER_EMP_SEQ_NO']; 
				$_SESSION ['user']['emp_id']      = $result ['USER_EMP_ID']; 
				$_SESSION ['user']['emp_name']    = $result ['USER_EMP_NAME']; 
				$_SESSION ['user']['user_name']   = $username; 
				$_SESSION ['user']['sex']         = $result ['SEX'];
				$_SESSION ['user']['dept_seqno']  = $result ['DEPT_SEQNO']; 
				$_SESSION ['user']['dept_id']     = $result ['DEPT_ID'];
				$_SESSION ['user']['dept_name']   = $result ['DEPT_NAME']; 
				
				$_SESSION ['user']['title_id']    = $result ['TITLE_ID']; 
				$_SESSION ['user']['title_name']  = $result ['TITLE_NAME']; 
				$_SESSION ['user']['title_level'] = $result ['TITLE_LEVEL'];
				$_SESSION ['user']['join_date']   = $result ['JOIN_DATE']; 
				
				$_SESSION ['user']['is_manager1'] = $User->IsManager($result ['USER_EMP_SEQ_NO']); 
				
				$_SESSION ['user']['is_manager']  = $mss_perm;
				unset($result);
				
				$_SESSION['user']['not_first_login'] = $User->isFirstLogin($passwd);
				
				$User->AddLoginList($_SESSION ['user']['user_seq_no'],'eHR');
				if(strtoupper($User->getDefaultHome()) == 'MD' ){
					header ('Location:'.$GLOBALS['config']['mgr_home'].'/redirect.php');
				}else {
					header ('Location:'.$GLOBALS['config']['ess_home'].'/redirect.php');
				}// end if
				exit();
			} else {
				header('Location: '.$home_url.urlencode('未授权.'));
				exit();
			}// end if
		} else {
			header('Location: '.$home_url.urlencode('Password error.'));
			exit();
		}
		
	} else {
		header('Location: '.$home_url.urlencode('The user name does not exist.'));
		exit();
	}
}else{
	header('Location: '.$home_url.'?loginerror='.urlencode('Attack error.'));
	exit();
}

?>