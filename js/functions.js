/*
 * 共用 JS
 *  $HeadURL: https://192.168.0.101/svn/ehr/trunk/eHR/js/functions.js $
 *  $Id: functions.js 3846 2014-09-29 01:13:19Z dennis $
 *  $LastChangedDate: 2014-09-29 09:13:19 +0800 (周一, 29 九月 2014) $
 *  $LastChangedBy: dennis $
 *  $LastChangedRevision: 3846 $
 ****************************************************************************/
/**
 * reset form value
 * 注意: 请使用 <input type="button"/>,不要使用 type="reset"
 * 否则不能清除 submit 之后的 form
 * @param  form_id string
 * @return void
 * @author Dennis 20090809
 */
function clear_form(form_id) {
	$('#' + form_id).find(':input').each(function () {
		switch (this.type) {
			case 'password':
			case 'select-multiple':
			case 'select-one':
			case 'text':
			case 'textarea':
			case 'hidden':
				$(this).val("");
				break;
			case 'checkbox':
			case 'radio':
				this.checked = false;
			default:break;
		} // end switch
	});
} // end clear_form()

/**
 * open url in new windows
 * @param url
 * @param winid
 * @param w
 * @param h
 * @param left
 * @param top
 * @returns {Boolean}
 */
function openw(url, winid, w, h, left, top) {
	if (left == undefined)
		left = 220;
	if (top == undefined)
		top = 200;
	var w = window.open(
			url + '&openW=Y&rand=' + Math.random(),
			winid,
			'height='
			 + h
			 + ', width='
			 + w
			 + ',left='
			+left + ',top='
			+top + ',toolbar=no, menubar=no, scrollbars=yes, resizable=yes,location=no,status=no');
	if (window.focus) {
		w.focus();
	}
	return false;
} // end openw()

/**
 * Show Lov Window
 * @param url
 * @param txt_id
 * @param txt_no
 * @param txt_name
 * @param w
 * @param h
 * @param left
 * @param top
 * @return void
 */
function showLov(url, txt_id, txt_no, txt_name, w, h, left, top) {
	if (left == undefined)
		left = 220;
	if (top == undefined)
		top = 200;
	if (w == undefined)
		w = 400;
	if (h == undefined)
		h = 440;
	//var rs=showModalDialog(url,'about','dialogWidth=' + w + 'px;dialogHeight=' + h + 'px;dialogLeft=' + left + 'px;dialogTop=' + top + 'x;toolbar=no;menubar=no;scrollbars=no');
	// remark by dennis 20090708 showModalDialog 无第二个参数
	var rs = showModalDialog(url, 'dialogWidth=' + w + 'px;dialogHeight=' + h + 'px;dialogLeft=' + left + 'px;dialogTop=' + top + 'x;toolbar=no;menubar=no;scrollbars=no');
	//showDlg(url,'List of Values',w,h);
	try {
		txt_id.value = rs.id;
	} catch (e) {
		// no define txt_id or txt_no or txt_name
	}
	try {
		txt_no.value = rs.no;
	} catch (e) {
		// no define txt_id or txt_no or txt_name
	}
	try {
		txt_name.value = rs.name;
	} catch (e) {
		// no define txt_id or txt_no or txt_name
	}
}



/**
 * Popup a windows to display detail information
 * @param no
 * @return void
 */
function attachClickEvent() {
	$('a').each(function () {
		if ($(this).attr('type') == 'popup') {
			$(this).click(function () {
				var p_title = $.trim($(this).text());
				p_title =  p_title && p_title != '' ? $(this).text() : "流程图";
				showDlg($(this).attr('href'),p_title,700,600);
				return false;
			});
		}
	});
} // end attachClickEvent

/**
 * Show JqueryUI Dialog
 * 
 * @param url
 * @param dlg_title
 * @param w
 * @param h
 * @returns {Boolean}
 * @author Dennis 2013/09/06
 */
function showDlg(url,dlg_title,w,h){
	var dialog = top.$('<div style="display:none"></div>').appendTo('body');
	// load remote content
	dialog.load(
		url, {}, // omit this param object to issue a GET request instead a POST request, otherwise you may provide post parameters within the object
		function (responseText, textStatus, XMLHttpRequest) {
		dialog.dialog({
			// add a close listener to prevent adding multiple divs to the document
			title : dlg_title,
			width : w,
			height : h,
			modal : true,
			close : function (event, ui) {
				// remove div with all data and events
				dialog.remove();
			}
		});
	});
	//prevent the browser to follow the link
	return false;
}
/**
 * check all checkbox
 * @param oForm
 * @param bCheck
 */
function CheckAll(oForm, bCheck) {
	/*
	var _elements = oForm.elements;
	for (var i = 0; i < _elements.length; i++) {
		if (_elements[i].type == "checkbox" && _elements[i].value != "") {
			_elements[i].checked = bCheck;
		} // end if
	} // end for loop
	*/
	$("input:checkbox").each(function (){
		if ($(this).val() != '') this.checked = bCheck;
	});
} // end CheckAll()

/**
 * 检查是否有选中的记录
 */
function isChecked(oForm) {
	var _elements = oForm.elements;
	for (var i = 0; i < _elements.length; i++) {
		if (_elements[i].type == "checkbox" && _elements[i].value != ""
			 && _elements[i].checked) {
			return true;
		}
	} // end for loop
	return false;
} // end isChecked()

/**
 * 分页翻页时用到此 Function
 * 所有的分页页共用此 function
 * @last update by Dennis 2011-09-26
 */
function gotopage(url) {
	$('form:first').attr('action', url);
	//$('form:first').submit();
	$('#submit').click();
}

/**
 * * parameter1: form name; * return boolean : no error return true else return
 * false * html add required=Y or area_number=Y area_min=20 area_max=60 title='' *
 * Example: if(!checkUserInputData('form1')) return false;
 */
function checkUserInputData(formID) {
	var theFormId = '#'.formID;
	var passed = true;
	// check required input
	$(theFormId).find('[@required*=Y]').each(function () {
		if ($(this).attr('disabled') == false) {
			if ($(this).val().replace(/ /g, '') == '') {
				alert($(this).attr('title'));
				$(this).focus();
				passed = false;
				return false;
			}
			if ($(this).attr('type') == 'radio') {
				var radioName = $(this).attr('name');
				var radiochecked = false;
				$("input[name='" + radioName + "']").each(function (index) {
					if (this.checked) {
						radiochecked = true;
						return;
					} // end if
				});
				/*
				 * remark by dennis 2008-12-16 var n=
				 * document.all[radioName].length; var radiochecked = false;
				 * for(var i=0;i<n;i++){
				 * if(document.all[radioName][i].checked){ radiochecked = true;
				 * break; } }
				 */
				if (radiochecked == false) {
					alert($(this).attr('title'));
					$(this).focus();
					passed = false;
					return false;
				}
			}
		}
	});
	if (passed == false)
		return passed;
	
	// check area number value
	$(theFormId).find('[@check_range*=Y]').each(function () {
		// alert($(this).attr('area_max'));
		if ($(this).attr('disabled') == false) {
			var max = eval($(this).attr('max_num'));
			var min = eval($(this).attr('min_num'));
			var thisValue = $(this).val();
			try {
				eval(1 + thisValue);
				thisValue = eval(thisValue);
				if (thisValue < min || thisValue > max) {
					alert($(this).attr('title'));
					$(this).focus();
					passed = false;
					return false;
				}
			} catch (e) {
				alert($(this).attr('title'));
				$(this).focus();
				passed = false;
				return false;
			}
		}
	});
	if (passed == false)
		return passed;
	
	// check is number value
	$(theFormId).find('[@is_number*=Y]').each(function () {
		if ($(this).attr('disabled') == false) {
			var thisValue = $(this).val();
			try {
				eval(1 + thisValue);
			} catch (e) {
				alert($(this).attr('title'));
				$(this).focus();
				passed = false;
				return false;
			}
		}
	});
	if (passed == false)
		return passed;
	return passed;
}

/**
 * 四舍五入格式化数字
 * @param number expr       将要格式化的数字
 * @param number decplaces  保留几位小数
 * @return number
 * @author Dennis 2009-03-23
 */
function number_format(expr, decplaces) {
	// raise incoming value by power of 10 times the
	// number of decimal places; round to an integer; convert to string
	var str = '' + Math.round(eval(expr) * Math.pow(10, decplaces));
	// pad small value strings with zeros to the left of rounded number
	while (str.length <= decplaces) {
		str = '0' + str;
	}
	// establish location of decimal point
	var decpoint = str.length - decplaces;
	// assemble final result from: (a) the string up to the position of
	// the decimal point; (b) the decimal point; and (c) the balance
	// of the string. Return finished product.
	
	return str.substring(0, decpoint) + '.'
	 + str.substring(decpoint, str.length);
}

/*
选中/取消选中 指定table中的所有checkbox
parameter: tabid  ---table id
bCheck ---- true 选中，false 取消选中
 */
function gf_CheckAllRows(tabid, bCheck) {
	var tab = document.getElementById(tabid);
	var rows = tab.rows.length;
	for (var i = 0; i < rows; i++) {
		//alert(tab.rows[i].cells[0].childNodes[0].type)
		if (tab.rows[i].cells[0].childNodes[0].type == 'checkbox') {
			tab.rows[i].cells[0].childNodes[0].checked = bCheck;
		} //end if
	} // end for loop
} // end CheckAll()


/*  删除一笔
 *  create by boll
 */
function gf_doDelete(url) {
	var confirm = window.confirm("确认删除?");
	if (confirm)
		location.href = url;
}
// emp_lov.html/emp_import.html 共用 functions add by dennis 2013-03-27
	/**
	 * Check employee exists the selected list according the primary ke (psn_id)
	 */
	 function isRowExists(tabobj,kval){
		var rows = tabobj.find('tr:gt(0)'); 
		var r = 0;
		rows.each(function(index) {
	         if (kval == $(':first-child', this).children('input:nth-child(2)').val()) r=1;
	    });
		return r;
	}
	/**
	* add some trs to table
	* @param tabObj object the target table object
	* @param rows   array  data of row
	* @author Dennis
	*/
	function addRowsToTable(tabObj,rows)
	{
	    var rcnt = rows.length;
	    var j = 0;
	    var emp_list_html = '';
	    for (var i=0; i<rcnt; i++) 
	    {
	        if(isRowExists(tabObj,rows[i]['emp_seqno']) == 0)
	        {
	        	emp_list_html += '<tr>';
	        	emp_list_html += '<td><input type="checkbox" name = "emp_seqno_chk[]" />';
	        	emp_list_html += '<input type="hidden" name = "emp_seqno[]" value="'+rows[i]['emp_seqno']+'"/></td>';
	        	emp_list_html += '<td>'+rows[i]['dept_id'];
	        	emp_list_html += '<input type="hidden" name = "dept_seqno[]" value="'+rows[i]['dept_seqno']+'"/>';
	        	emp_list_html += '<input type="hidden" name = "dept_id[]" value="'+rows[i]['dept_id']+'"/></td>';
	        	emp_list_html += '<td>'+rows[i]['dept_name'];
	        	emp_list_html += '<input type="hidden" name = "dept_name[]" value="'+rows[i]['dept_name']+'"/></td>';
	        	emp_list_html += '<td>'+rows[i]['emp_id'];
	        	emp_list_html += '<input type="hidden" name = "emp_id[]" value="'+rows[i]['emp_id']+'"/></td>';
	        	emp_list_html += '<td>'+rows[i]['emp_name'];
	        	emp_list_html += '<input type="hidden" name = "emp_name[]" value="'+rows[i]['emp_name']+'"/></td>';
	        	emp_list_html += '<td>'+rows[i]['overtimetype'];
	        	emp_list_html += '<input type="hidden" name = "overtimetype[]" value="'+rows[i]['overtimetype']+'"/></td>';
	        	emp_list_html += '<td>'+rows[i]['overtimetype_name'];
	        	emp_list_html += '<input type="hidden" name = "overtimetype_name[]" value="'+rows[i]['overtimetype_name']+'"/></td>';
	        	//emp_list_html += '<td><img class="delete_row_img" src="<!--{$IMG_DIR}-->/close.gif" border="0" alt="Delete"/></td>';
				emp_list_html += '</tr>';
	        	j++;
	        }// end if
	    }// end for loop
	    tabObj.find('tr:last').after(emp_list_html);
	    return j;
	}// end addRowsToTable()
// end emp_lov.html/emp_import.html 共用 functions