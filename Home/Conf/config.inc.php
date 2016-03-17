<?php
/****************************************************************************\
 *  Copyright (C) 2004 Ares China Inc.
 *  Created By Dennis Lan, Lan Jiangtao
 *  Description:
 *     System configuration file for ESS & MSS
 *  Change Log:
 *  2013-02-27 Oracle Version Last Version, tag to verions 3.2.3433
 *  $Id: config.inc.php 3857 2014-11-03 03:44:55Z dennis $
 *  $LastChangedDate: 2014-11-03 11:44:55 +0800 (周一, 03 十一月 2014) $
 *  $LastChangedBy: dennis $
 *  $LastChangedRevision: 3857 $
 ****************************************************************************/
if (!defined ('DOCROOT'))die( 'Attack Error.');

define('DS','/');
define('PS',PATH_SEPARATOR);
$db_config_file = DOCROOT.DS.'conf'.DS.'define.ini.php';
// Apache Load Balance
// Store Session to Database via ADODB Session Class
// Add by Dennis 2009-05-15
if (file_exists($db_config_file))
{
	include_once $db_config_file;
	if (isset($GLOBALS['config']['sess_handler']) &&
	    'db' == $GLOBALS['config']['sess_handler'])
	{
		include_once DOCROOT.DS.'libs/adodb/session/adodb-session2.php';
		ini_set('session.save_handler','user');
		$driver   = $GLOBALS['config']['database']['adapter'];
		$host     = $GLOBALS['config']['database']['host'];
		$user     = $GLOBALS['config']['database']['username'];
		$password = $GLOBALS['config']['database']['password'];
		$database = $GLOBALS['config']['database']['dbname'];
		$options['table'] = 'ehr_sessions';
		ADOdb_Session::config($driver, $host, $user, $password, $database,$options);
		unset($GLOBALS['config']['database']);
	}
}

/**
 * Cust session expired seconds
 * add by dennis 2013/12/03
 * @param number $expire seconds
 * 
 */
function start_session($expire = 0)
{
    if ($expire == 0) {
        $expire = ini_get('session.gc_maxlifetime');
    } else {
        ini_set('session.gc_maxlifetime', $expire);
    }

    if (empty($_COOKIE['PHPSESSID'])) {
        session_set_cookie_params($expire);
        session_start();
    } else {
        session_start();
        setcookie('PHPSESSID', session_id(), time() + $expire);
    }
}
//session_cache_limiter('nocache'); //清空表单
//session_cache_limiter('private'); //不清空表单，只在session生效期间
//session_cache_limiter('public');  //不清空表单，如同没使用session一般
//header("Cache-control: private");
//$GLOBALS['config']['sess_expired'];
if (!isset($_SESSION)) session_start(); //start_session(3600);

// modify by dennis 20091231 for fixed workflow mail approved
// last update 2011-08-11 15:00 for get least patch no

function getSCID() {
    $svnid = '$Rev: 3857 $';
    $scid = substr($svnid, 6);
    return intval(substr($scid, 0, strlen($scid) - 2));
}


define ('ESS_APP_VERSION', '3.2.'.getSCID());
define ('MSS_APP_VERSION', '3.2.'.getSCID());
// set Time Zone for PHP5
date_default_timezone_set('Asia/Shanghai');

// !!! warning: please set to false in product ENV
$config['debug'] = true;

if ($config['debug']) {
	ini_set('error_reporting', E_ALL);
	ini_set('display_errors', 1);
} else {
	ini_set('error_reporting', E_ALL);
	ini_set('display_errors', 0);
} // end if

$config['css_dir']    = DOCROOT.DS.'css';
$config['img_dir']    = DOCROOT.DS.'img';
$config['lib_dir']    = DOCROOT.DS.'libs';
$config['js_dir']     = DOCROOT.DS.'js';
$config['pic_dir']    = DOCROOT.DS.'upload'.DS.'emphoto';
$config['ctl_dir']    = DOCROOT.DS.'controls';
$config['upload_dir'] = DOCROOT.DS.'upload';
// add by dennis 20091109
$config['tmp_dir']    = DOCROOT.DS.'tmp'.DS.'cache';
$config['calendar']   = $config['lib_dir'].DS.'library'.DS.'JsCalendar';
$config['mailer']     = $config['lib_dir'].DS.'phpMailer';
$config['mail_method']= 'mail';
// define module home
$config['ess_home']   = DOCROOT.DS.'ess'; // Employee Self-Service module home
$config['mgr_home']   = DOCROOT.DS.'mgr'; // Manager Desktop module home

// eHR System support lanague List
$config['support_lang_list'] = array ('zh-cn' => 'ZHS',
									  'zh-tw' => 'ZHT',
									  'en-us' => 'US',
									  'en-gb' => 'ZHS',
									  'zh-cn,zh-tw;q=0.5' => 'ZHS',
									  'zh-tw,zh-cn;q=0.5' => 'ZHT');

set_include_path(get_include_path().'.'.PS.$config['lib_dir'].PS.$config['lib_dir'].DS.'library');
//echo get_include_path();
// constants

if (!defined('ADODB_DIR')) define('ADODB_DIR', $config['lib_dir'].DS.'adodb');
// only this, !!! don't forget the last back slash !!! because smarty class use this constant
define('SMARTY_DIR', $config['lib_dir'].DS. 'smarty'.DS.'libs'.DS);

require_once 'functions.php';			// public functions
require_once 'db_config.inc.php'; 		// Database Configuration File
require_once 'AresSmarty.class.php'; 	// Smarty Template Engine
require_once 'AresDB.inc.php'; 			// AdoDB
require_once 'AresParser.class.php'; 	// Page Compiler Class
require_once 'AresSys.class.php';		// eHR System Setting class add by dennis 2012-03-05

// get default user os primary language
// added by dennis 2008-03-21
$user_lang = get_language ();
$config['default_lang'] = strtoupper(isset($_GET['lang']) && !empty($_GET['lang']) ? $_GET['lang'] :
						  (isset($_SESSION['user']['language']) ?
						   $_SESSION['user']['language'] :
						   $config['support_lang_list'][$user_lang]));

$dir = (DOCROOT == '..') ? dirname($_SERVER['PHP_SELF']) : dirname(dirname($_SERVER['PHP_SELF']));
$module_name = strtolower(substr($dir, strlen($dir) - 3, strlen($dir)));
$config['curr_home'] = $config[$module_name.'_home'];
$config['tpl_dir']   = $config['curr_home'].DS.'templates';
$config['inc_dir']   = $config['curr_home'].DS.'includes';

// 设定 user 文件上传的路径(不再从HCP参数中抓取) add by dennis 2011-11-22
$config['upl_dir']	 = DOCROOT.DS.'upload/userfile'; 

//$config['index_page'] = $config['curr_home'].'/redirect.php';
// set query cache dir for ADODB CacheSelect
//$config['tmp_dir'] = $config['curr_home'].'/temp';

$config['dir_array'] = array ('IMG_DIR' => $config['img_dir'],
							  'PIC_DIR' => $config['pic_dir'],
							  'CSS_DIR' => $config['css_dir'],
							  'JS_DIR'  => $config['js_dir'],
							  'INC_DIR' => $config['inc_dir'],
							  'CAL_DIR' => $config['calendar']);


// needed cache application id array | 2006-02-24 10:39:55 add by dennis
$config['cache_left_time'] = 3600; // seconds 1 hour
$config['cache_app_list']  = array ('ESN0000','ESN0000_1','MDN0000','MDN0000_1'); // defautl cache app list

// ESS mss 共用程式清单
$config['pub_app'] = array( //'ESND004'=>'MDNE103',  remark by dennis 20090909 ESS中加自定义程式
						   'MDNA101'=>'ESNA001',
						   'MDNA102'=>'ESNA002',
						   'MDNA103'=>'ESNA003',
						   'MDNA104'=>'ESNA004',
						   'MDNA105'=>'ESNA005',
						   'MDNA106'=>'ESNA006',
						   'MDNA107'=>'ESNA007',
						   'MDNA108'=>'ESNA008',
						   'MDNA109'=>'ESNA009',
						   'MDNA110'=>'ESNA010',
						   'MDNA111'=>'ESNA011',
                           'MDNA112'=>'ESNA018',
                           'MDNA901'=>'ESNA902',
						   'MDNA201'=>'ESNB001',
						   'MDNA202'=>'ESNB002',
						   'MDNA203'=>'ESNB003',
						   'MDNA204'=>'ESNB004',
						   'MDNA205'=>'ESNB005',
						   'MDNA206'=>'ESNB006',
						   'MDNA301'=>'ESNC001',
						   'MDNA302'=>'ESNC002',
						   'MDNA303'=>'ESNC003',
						   'MDNA304'=>'ESNC006',
						   'MDNA305'=>'ESNC005',
						   'MDNA306'=>'ESSC203',
						   'MDNA401'=>'ESND003',
						   'MDNA402'=>'ESND004',
						   'MDNA403'=>'ESND006',
						   'MDNH102'=>'ESNH001',
						   'MDNH103'=>'ESNH002',
						   'MDNC101'=>'ESNB007',
						   'ESNH003'=>'MDNH104',
						   'ESNH004'=>'MDNH105',
						   'ESNH006'=>'MDNH107',
						   'ESNH007'=>'MDNH108',
						   'ESNH008'=>'MDNH109'
						);

// 需要双重认证程式清单(薪资相关程式需要双重认证)
$config['double_auth_list'] = array ('salary_adjust_his',  		// 薪资调整记录
									 'salary_ss_his_new', 		// 社保/保险查询
									 'salary_personal_tax',		// 缴税记录
									 'salary_slip',				// 薪资条
									 'bonus',					// 奖金
									 'salary_adjust_his_detail',// 调薪历史明细
									 'salary_slip_detail',		// 薪资明细
									 'ESNC001',
                                     'ESNC002',
                                     'ESNC003',
									 'ESNC004','ESNC005','MDNA301',
									 'MDNA302','MDNA303','MDNA304',
									 'MDNA305','salary_slip_new','ESNC006'); // add by dennis 2011-08-02 MSS 薪資查詢加入到此

// 邮件中签核时 link 到相应的签核 table 不需要做安全检查
// EHR_ROOT/mgr/redirect.php 中的 security_check 不检查
$config['none_auth_list'] = array('leave_approve',				// 请假签核
								  'overtime_approve',			// 加班签核
								  'trans_approve',				// 异动签核
								  'nocard_approve',				// 忘记刷卡签核
								  'resign_approve',				// 离职签核
								  'cancel_leave_approve',		// 销假签核
								  'view_flowchart',				// 查看流程图
								  'findpasswd');				// 找回密码

// MD 程式 mapping table
$config['md_app_map'] = array('MDNA'=>'mystaff',				// 我的部属
							  'MDNA001'=>'staffinfo',			// 人员信息
							  'MDNA002'=>'deptsummary', 		// 部门信息
							  'MDNC'=>'pa', 					// 绩效考核
							  'MDNC' => 'pa_report',    		// 默认页 add by Terry
							  'MDNC106'=>'pa_report',			// 绩考报表
							  'MDNC108'=>'staffabc',			// Staff ABC (未成之功能 only demo) by dennis 2011-08-02
							  'MDNC901'=>'pa_bottom5_confirm',	// Bottom5 List Confirm 确认
							  'MDNC902'=>'pa_bottom5_list',		// 绩效改善通知单
							  //'MDNE'=>'training',				// 教育训练  marked by Terry 2011-8-29
							  'MDNE'=>'MDNE101',			    // 默认页 add by Terry
							  'MDNE201'=>'train_subject',		// 课程
							  'MDNE202'=>'train_student_lov',	// 训练成绩查询
							  'MDNE203'=>'train_agency_lov',	// 训练成绩查询
							  'MDNE204'=>'train_teacher_lov',	// 训练成绩查询
							  'MDNE205'=>'train_subject_lov',	// 课程lov
							  'MDNE206'=>'train_class_lov',		// 课程班别lov
							  'MDNF'=>'org_chart_view', 				// 组织图
							  'MDNF101'=>'org_chart_list',		// 组织图历史
							  'MDNF102'=>'org_chart_upload',	// 组织图上传
							  'MDNF103'=>'org_chart_view',		// 当前用的组织图
							  'MDNG'=>'emp_adv_search',			// 进阶查询 , modify by Terry , set default page
							  'MDNG101'=>'emp_adv_search',    	// 员工查询
							  'MDNG102'=>'job_vacancy_adv_search',			// 职缺查询
							  'MDNG103'=>'competency_adv_search',   		// 胜任力查询
							  'MDNG104'=>'license_adv_search',  			// 证照查询
							  'MDNG201'=>'advsearch_compecense_period_lov', // 预算周期
							  'MDNG202'=>'advsearch_grade_lov',  			// 职等 LOV
							  'MDNG203'=>'advsearch_dept_lov',  			// 部门 LOV
							  'MDNG204'=>'advsearch_edu_lov',  				// 学历 LOV
							  'MDNG205'=>'advsearch_school_lov',  			// 学校 LOV
							  'MDNG206'=>'advsearch_major_lov',  			// 科系 LOV
							  'MDNG207'=>'advsearch_factory_lov',  			// 厂区 LOV
							  'MDNG208'=>'advsearch_speciality_lov',		// 专长 LOV
							  'MDNG209'=>'advsearch_nationality_lov',		// 地区 LOV
							  'MDNG210'=>'advsearch_title_lov',  			// 职务 LOV
							  'MDNG211'=>'advsearch_license_lov',  			// 证照名 LOV
							  'MDNG212'=>'advsearch_license_dept_lov',		// 发证机构 LOV
							  'MDNG213'=>'advsearch_yyyymm_lov',			// 职缺查询中的预算年度 LOV
							  'MDNH'=>'home',   							// 首页
							  'MDNH101'=>'home',							// 首页
							  'MDNH104'=>'leave_approve',					// 请假签核
							  'MDNH105'=>'overtime_approve',				// 加班签核
							  'MDNH106'=>'trans_approve',					// 人事异动签核
							  'MDNH107'=>'nocard_approve',					// 忘刷签核
							  'MDNH108'=>'resign_approve',					// 离职留停签核
							  'MDNH109'=>'cancel_leave_approve',			// 销假签核
							  'MDNS'=>'systemsetting_default_home',  	    // 系统设置  , modify by Terry , set default page
							  //'MDNS105'=>'systemsetting_default_layout',	// 默认布局  mv 2 ess by dennis 2011-11-24
							  'MDNS101'=>'systemsetting_password',		    // 密码更改   mv 2 ess by dennis 2011-11-24
							  //'MDNS102'=>'systemsetting_receiver_group',	// 收件人群组
							  //'MDNS103'=>'systemsetting_log',				// 系统日志   mv 2 ess by dennis 2011-11-24
							  'MDNS104'=>'systemsetting_default_home',		// 默认首页
							  'MDNT'   =>'emp_overtime_gather',				// 考勤汇总
							  'MDNT001'=>'emp_leave_gather', 				// 请假资料汇总 add by Terry
							  'MDNT002'=>'emp_overtime_gather',				// 加班资料汇总 add by Terry
);
// ESS 程式 mapping table
$config['ess_app_map'] = array('ESNH'=>'home', 								// 预设显示首页
							   'ESNH000'=>'home', 							// 首页
							   'ESNH801'=>'data_import',					// 批量导入结果查询
							   'ESNA'=>'pim',								// 个人出勤汇总
							   'ESNA000'=>'pim', 							// 出勤汇总
							   'ESNA007'=>'emp_schedule',					// 排程
							   'ESNA012'=>'emp_leave_apply',				// 请假申请
							   'ESNA013'=>'emp_leave_apply_search',			// 请假申请查询
							   'ESNA014'=>'emp_overtime_apply',				// 加班申请
							   'ESNA015'=>'emp_overtime_apply_search',		// 加班申请查询
							   'ESNA017'=>'edit_personal_info',				// 编辑个人资料
							   'ESNA018'=>'pim', 							// 出勤汇总
 							   'ESNA019'=>'hr_check_data', 					// HR审核人个资料修改
							   'ESNA020'=>'vacation_left',					// 可休假查询
							   'ESNA021'=>'emp_trans_apply',				// 人事异动申请added by gracie
                               'ESNA022'=>'emp_trans_apply_search',			// 人事异动申请查询 added by gracie
                               'ESNA023'=>'emp_nocard_apply',				// 忘刷申请added by gracie
                               'ESNA024'=>'emp_nocard_apply_search',		// 忘刷申请查询 added by gracie
							   'ESNA025'=>'emp_resign_apply',				// 离职留停申请added by gracie
                               'ESNA026'=>'emp_resign_apply_search',		// 离职留停申请查询 added by gracie
							   'ESNA027'=>'emp_cancel_leave_apply',			// 销假申请
                               'ESNA028'=>'emp_cancel_leave_apply_search',	// 销假申请查询
                               'ESNA030'=>'emp_spec_leave',                 // 员工特别假查询 issuno:8824
                               'ESNA901'=>'resaon_for_leaving',				// 离职原因调查
							   'ESNB'=>'job_desc',							// JD 点Tab时预设显示的面页
							   'ESNB001'=>'job_desc',						// JD
							   'ESNB002'=>'year_objective',					// 年度目标
							   'ESNB004'=>'job_require', 					// 工作职能
							   'ESNB007'=>'pa_period_list',					// 绩效考核自评单查询 by 考核期间
							   'ESNB008'=>'pa_score_result',				// 绩效考核查询 by 考核期间
							   'ESNB010'=>'pa_successor_plan',				// 接班人维护
							   'ESNB020'=>'pa_goal_list',                   // 期初考核查询
							   'ESNC'=>'salary_home',						// 薪资模块验证
							   'ESNC000'=>'salary_home',					// 我的薪资
							   'ESNC001'=>$config['double_auth_list'][0],	// 调薪历史
							   'ESNC002'=>$config['double_auth_list'][1],	// 社保/保险查询
							   'ESNC003'=>$config['double_auth_list'][2],	// 缴税记录
							   'ESNC004'=>$config['double_auth_list'][3],	// 薪资条
							   'ESNC005'=>$config['double_auth_list'][4],	// 奖金
							   'ESNC006'=>$config['double_auth_list'][17],   // 电子薪资条
							   'ESND'=>'my_career',							// 我的成长
							   'ESND000'=>'my_career', 						// 我的成长
							   'ESND005'=>'train_requir_online',			// 训练需求在线填写
							   'ESND010'=>'register_online',				// 训练在线申请
							   'ESND011'=>'train_enter_for_query',
							   'ESNE'=>'wf_assistant', 						// 助理桌面
							   'ESNE000'=>'wf_assistant', 					// 助理桌面
							   'ESNE001'=>'assistant_overtime_batch_apply', // 助理批量加班
							   'ESNE002'=>'assistant_leave_batch_apply',	// 助理批量请假
							   'ESNE003'=>'assistant_overtime_apply_search',// 助理批量加班查询
							   'ESNE004'=>'assistant_leave_apply_search',	// 助理批量请假查询
							   'ESNE007'=>'emp_overtime_apply_import',		// 助理批量加班导入
							   //'ESNE008'=>'emp_leave_apply_import',      	// 助理批量請假导入
							   'ESNE008'=>'assis_leave_apply_import',      	// 助理批量請假导入(new) add by Dennis 2014/05/28
							   'ESNE020'=>'assistant_overtime_batch_del',	// 助理批量删除加班申请
							   'ESNE021'=>'assistant_leave_batch_del',   	// 助理批量删除请假申请
							   /* add by Dennis 2014/05/30 */
							   'ESNE023'=>'assis_ot_excel_imp_result',      // 助理加班 Excle 导入结果，注：之前是自定义查询 modify by Dennis 2014/05/30
							   'ESNE022'=>'assis_ot_excel_imp_detail',      // 助理加班 Excel 导入结果明细
							   'ESNE024'=>'assis_leave_excel_imp_result',   // 助理请假 Excle 导入结果    add by Dennis 2014/05/30
							   'ESNE025'=>'assis_leave_excel_imp_detail',   // 助理请假 Excel 导入结果明细 add by Dennis 2014/05/30
							   /* end add by Dennis 2014/05/30 */
							   'ESNF'=>'wf_admin', 							// 流程管理员
							   'ESNF000'=>'wf_admin',						// 流程管理员
							   'ESNF101'=>'overtime_apply_rule',			// 请假规则说明设定
							   'ESNF102'=>'leave_apply_rule',   			// 加班规则说明设定
							   'ESNF001'=>'admin_leave_apply_search',		// 管理员批量请假查询
							   'ESNF002'=>'admin_overtime_apply_search',	// 管理员批量加班查询
							   'ESNF003'=>'admin_cancel_leave_apply_search',// 管理员销假查询
							   'ESNF004'=>'admin_user_define_wf',			// 管理员自定义流程查询
                               'ESNF005'=>'admin_trans_apply_search',		// 管理员人事異動流程管理
							   'ESNF006'=>'admin_nocard_apply_search',		// 管理员忘刷流程管理
                               'ESNF007'=>'admin_resign_apply_search',		// 管理员離職/留停流程管理
                               /* 身份证阅读器功能已经独立成一个产品 by Dennis 2014/05/22
							   'ESNP'=>'card_read',							// 身份证读卡  add by Terry
							   'ESNP001'=>'card_read',						// 读卡 从 mgr 移到这边　by dennis 2011-11-24
							   'ESNP002'=>'card_add_information_web',		// 补资料 从 mgr 移到这边 by dennis 2011-11-24
							   'ESNP006'=>'card_edit_information',			// 编辑员工资料从 mgr 移到这边 by dennis 2011-11-24
                               */
                               'ESNR'=>'user_def_rpt_home',					// 自订查询报表首页(New)
							   'ESNR001'=>'user_def_rpt_wiz', 				// 使用者自定义报表精灵
							   'ESNR002'=>'user_def_rpt_edit', 				// 编辑使用者自定义报表
							   'ESNR003'=>'user_def_rpt_list', 				// 我的自订报表
							   'ESNS'=>'systemsetting_password',			// 修改密码
							   'ESNS004'=>'systemsetting_default_layout',	// 设置默认布局 , add by Terry
							   'ESNS301'=>'user_excel_data_import',			// Excel 导入设定
							   'ESNS001'=>'systemsetting_password',			// 修改密码
							   'ESNS003'=>'systemsetting_log',  			// 登录日志
							   'ESNS203'=>'umd_program_list',  				// 用户自定程序查询
							   'ESNS204'=>'umd_guide1',       				// 用户自定程序向导
							   'ESNS205'=>'umd_muti_lang',  				// 多国语言查询
							   'ESNS201'=>'umd_menu_create',  				// 新建菜单
							   'ESNS202'=>'umd_menu_list',  				// 菜单查询
							   'ESNS206'=>'agent_setting',					// 代理人设置
							   'ESNS401'=>'idcard_param_setting',			// 身份证读卡器参数
							   'ESNW'=>'wf_user_define',  					// 使用者自定义流程
							   'ESNW001'=>'wf_user_define',  				// 使用者自定义流程
							   /* 身份证阅读器功能已经独立成一个产品 by Dennis 2014/05/22
							   'ESNG001'=>'idcard_check',					// 录用前检查身份证
							   'ESNQ'=>'fab_idcard_input',					// 录入员工的 识别证序列号
							   'ESNQ001'=>'fab_idcard_input',				// 录入员工的 识别证序列号
							   'ESNQ002'=>'fab_emp_list',					// 查詢待列印識別證的員工清單
							   */
							   'ESNJ001'=>'dorm_emp_check',					// 查房－员工比对 add by dennis 2013/08/13 for 瑞
							   'ESNJ002'=>'dorm_sanitation_check',			// 卫生检查							
);

// 共用多语的程式,如 ESNH 共用 ESNH000 的多语
$config['pub_lang_map'] = array('ESNH'=>'MDNH',
								'news'=>'MDNH',
								'ESNH000'=>'MDNH',
								'home'=>'MDNH',
								'ESNA'=>'ESNA018',
								'ESNA000'=>'ESNA018',
								'ESNA112'=>'ESNA012',
								'ESNA028'=>'ESNA013',
								'employee_lov'=>'ESNA012',
								'ESNB'=>'ESNB001',
								'ESNC000'=>'ESNC',
								'ESND000'=>'ESND',
								'ESNE'=>'ESNA013',
								'ESNE000'=>'ESNA013',
								'ESNF'=>'ESNA013',
								'ESNF000'=>'ESNA013',
								'ESNE001'=>'ESNA014',
								'ESNE002'=>'ESNA012',
								'ESNE003'=>'ESNA015',
								'ESNE020'=>'ESNA015',
								'ESNE004'=>'ESNA013',
								'ESNE021'=>'ESNA013',
								'ESNF001'=>'ESNA013',
								'ESNF002'=>'ESNA015',
                                'ESNF005'=>'ESNA022',
								'ESNF006'=>'ESNA024',
                                'ESNF007'=>'ESNA026',
                                'ESNF003'=>'ESNA013',
								'emp_lov'=>'ESNE201',
								'ESNS003'=>'MDNS103', // add by dennis 2011-09-23
								'emp_full_lov'=>'ESNE201',
								'user_excel_upload'=>'ESNE007',
								'ESNS301'=>'ESNE007',
								'pa_bottom5_list'=>'MDNC901',
								'salary_auth_page'=>'ESNC',
								'salary_slip_detail'=>'ESNC004',
								'salary_adjust_his_detail'=>'ESNC004',
								'job_desc'=>'ESNB001',
								'view_flowchart'=>'ESNA013',
								'assistant_leave_apply_search'=>'ESNA013',
								'assistant_overtime_apply_search'=>'ESNA015',
								'admin_leave_apply_search'=>'ESNA013',
								'admin_overtime_apply_search'=>'ESNA015',
                                'admin_trans_apply_search'=>'ESNA022',
								'admin_nocard_apply_search'=>'ESNA024',
                                'admin_resign_apply_search'=>'ESNA026',
                                'admin_cancel_leave_apply_search'=>'ESNA013',
								'leave_approve'=>'ESNA013',
								'overtime_approve'=>'ESNA013',
								'trans_approve'=>'ESNA013',
                                'nocard_approve'=>'ESNA013',
								'resign_approve'=>'ESNA013',
                                'cancel_leave_approve'=>'ESNA013',
								'pa_form'=>'ESNB007',
								'pa_goal_setting'=>'ESNB007',		// add by dennis  2013/09/30
								'pa_goal_setting_view'=>'ESNB007',	// add by dennis  2013/09/30
								'pa_goal_edit'=>'ESNB007',			// add by dennis  2013/09/30
								'pa_summary_rpt'=>'ESNB008',
								'pa_emp_list'=>'ESNB008',
								'pa_report'=>'ESNB008',
								'pa_score_detail_list'=>'ESNB008',
								'pa_statistics_rpt'=>'ESNB008',
								'pa_add_successor'=>'ESNB010',
								'salary_personal_tax'=>'ESNC003',
								'pa_improve_form_print'=>'MDNC902',
								'pa_improve'=>'MDNC902',
								'findpasswd'=>'ESN0000',
								'staffabc_detail'=>'MDNC108',
								'ESNZ001'=>'ESNA014',
								'umd_guide1'=>'ESNS204',
								'umd_guide2'=>'ESNS204',
								'umd_guide3'=>'ESNS204',
								'umd_guide4'=>'ESNS204',
								'umd_guide5'=>'ESNS204',
								'umd_guide6'=>'ESNS204',
								'ESNS202'=>'ESNS201',
								'ESNS203'=>'ESNS204',
								'ESNS001'=>'MDNS101','ESNS'=>'MDNS101',
								'kpi_receiver_lov'=>'MDND101',
								'alert_email_set_lov'=>'MDNS102',
								'user_define_wf_approve'=>'ESNW001',
								'wf_user_define'=>'ESNW001',
								'wf_user_define_form'=>'ESNW001',
								'user_define_wf_approve'=>'ESNW001',
								'ESNW'=>'ESNW001',
								'user_define_wf'=>'ESNW001',
								'systemsetting_password' => 'MDNS101',
								'emp_adv_search' => 'MDNG101',
								'pim' => 'ESNA018',
								'wf_assistant' =>'ESNA013',
								'wf_admin' => 'ESNA013',
								'org_chart_list' => 'MDNF101',
);
/**
 *
 * 系统参数配置
 *
 * @var array
 */
$config['sys_param'] = array(
	'salary_timeout'=>1000*3600,
	'default_theme'=>'redmond'
);

$sys = new AresSys();
// check workflow install add by dennis 2010-09-08
$config['is_wf_installed'] = $sys->isWorkflowInstalled();
// add by dennis 20091104
// 自定义 workflow 程式定义
$config['ud_wf_app'] = $sys->getAppsListByType('workflow');
// add by dennis 20091229
$config['no_multi_lang_app'] = $sys->getAppsListByType('query');

// include public library file
$g_tpl = new AresSmarty($config['curr_home']);
$g_parser = new AresParser();

/**
 * PHP Security Filter
 * @param array $array
 * @return string
 * add by Dennis 2013/08/14
 */
function cleanArray($array)
{
	foreach($array as $key=>$value)
	{
		if(is_array($value))
		{
			$array[$key] = cleanArray($value);
		}
		else
		{
			$array[$key] = htmlspecialchars($value);
		}
	}
	return $array;
}
//$_POST = cleanArray($_POST); // remark by dennis 2013/11/01 当密码是特殊字符时不能登录,move to redirect.php
$_GET = cleanArray($_GET);

// 自定义查询程式数字栏位，小数位位数配置,预设4位，如果此处有设定的以设定为准
$config['num_fmt'] = array(
        'ESNA006'=>array('HM_COUNTS'=>0,'HM_AMOUNT'=>2),
        'ESNA009'=>array('HA_DAYS'=>4,'HA_HOUR'=>2),
        'ESNA010'=>array('HO_HOURT'=>2),
        'ESNA011'=>array('HY_SUM_YEARS'=>2,'HY_ONLY_YEAR_DAYS'=>4),
);

// add by dennis 20091229
// 客制程式 Config
$cust_config_file = DOCROOT.DS.'conf'.DS.'cust_config.inc.php';
if(file_exists($cust_config_file))
{
    // customize application configuration file
    require_once $cust_config_file;
}

