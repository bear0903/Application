<?php 

require_once (DOCROOT . '/conf/config.inc.php');

if(isset($_GET['Controller']) &&
		 $_GET['Controller'] == 'logout' &&
		 isset($_SESSION['user']['company_id']) &&
		 isset($_SESSION['user']['user_name'])
		){
			require_once 'AresUser.class.php';
			$User = new AresUser($_SESSION['user'], ['company_id'],
								 $_SESSION['user'], ['user_name']);
			$User->UpdateLogouttime('test');
		}

if (session_id() != ''){
	session_unset();
	session('[destroy]');
}

if (isset($_SERVER['REMOTE_USER']) && !empty($_SERVER['REMOTE_USER'])){
	header('Location: ./Application/Home/LoginController.class.php????????');
	exit;
}


if (	isset($_GET['password'])  && !empty($_GET['password'])  &&
		isset($_GET['companyno']) && !empty($_GET['companyno']))
{
	header('Location: ./Application/Home/LoginController.class.php????????');
	exit;
}

$g_tpl->assign ($GLOBALS['config']['dir_array']);

$g_tpl->assign('DEFAULT_THEME', $GLOBALS['config']['sys_param']['default_theme']);
include_once($GLOBALS['config']['inc_dir'].'/IndexModel.class.php');
$g_parser->ParseMultiLang ('ESN0000', $GLOBALS['config']['default_lang']);
$g_tpl->display('index.html');


?>