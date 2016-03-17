<?php 
namespace Think\Model;
use Think\Model;

$language = isset($_POST['lang']) ?
			$_POST['lang'] :
			(isset($_GET['lang']) ?
			$_GET['lang'] : 	
			$GLOBALS['config']['default_lang']);

$sql1 = <<<eof
		select language_code,language_name
			from ehr_multilang_list
eof;
$g_parser->ParseSelect ('language_list',$sql1,'s_lang_code',$language);

$companyid = isset($_POST['companyno']) ?
				$_POST['companyno'] :
				(isset($_GET['companyno']) ?
				$_GET['companyno']	:
				(isset($_COOKIE['companyid']) ?
				$_COOKIE['companyid'] : ''		
						));

$sql2 = <<<eof
		select dept_seq_no as company_id,
			   dept_name   as company_name,
			from  ehr_department_v
				where dept_type='company'
				order_by dept_id
eof;

$g_parser->ParseSelect ('company_list',$sql2,'s_company_id',$company);

$g_tpl->assign('company',getLogoUrl);


?>