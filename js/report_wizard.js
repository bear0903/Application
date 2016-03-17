/**
 * User Defined Report Core Javascript
 * @author Dennis
 * 
 */
	//Global Variables
	var wizCnt			= 4;	// Wizard Step count
	var lastDsName		= '';	// 当前选中的数据来源 (view name)
	var colsList		= [];	// 记录当前选中 view 里的栏位
	var currWhereHtml	= '';	// 当前的条件，点“确定”按钮时记录下来整个 table html,下次再打开时直接显示
	var currWhereVals	= []; 	// 预设查询条件栏位的实际 value, 因为currWhere 中无法记录user 输入的值
	var colAttrVals		= [];	// 记录每个栏位属性设定值
	var lastLi			= '';	// Last Clicked Column on the Column Attributes Setting UI
	var colGroup		= [];	// store the single row layout column group setting 
	
	var noDisColList	= ['PSN_ID',
	                	   'SEG_SEGMENT_NO'];	// 不要显示column name, 通常是 pk, fk 不要显示
	var datasourceList	= [];	// data source list (所选取的数据来源清单)
	var dsLabel			= [];	// data source 中文名称 for display
	var dsTableId		= 'datasource_list';	// where the datasource list  add table container id
	 
	// 所有栏位属性
	var colAttrKeys		= [ 'attr_data_type',
							'attr_col_title',
							'ui_type',
							'chked_val',
							'tgt_url',
							'query_allow',
							'range_allow',
							'groupby_allow',
							'groupby_type',
							'date_fmt',
							'num_format',
							'col_width',
							'txt_align',
							'dec_num',
							'unsign_fmt',
							'uf_font_color',
							'uf_bg_color',
							'is_list_cond',
							'list_data_source',
							'formual_val',
							'sort_allow',
							'sort_type',
							'sort_seq',
							'col_label_cn',
							'col_label_tw',
							'col_label_en'];
	
	// Record the object which used twice on this page 
	var $dis_col_list 	   = '';
	var $dis_col_list1 	   = '';
	var $dis_col_list2 	   = '';
	var $dis_col_list3 	   = '';
	var $cond_col_list	   = '';
	var $sort_col_list	   = '';
	var $stts_col_list     = '';
	var $def_col_list	   = '';
	var $attr_dis_col_list = '';
	var $wiz_step		   = '';
	var $ui_col_list       = '';
	var $ui_group_col_list = '';
	var $default_where_dis = '';
	var $col_grp_acc	   = '';
	var $allow_col_group   = '';
	var $step2_tab_sub     = '';
	// end of reuse object define
	
	/**
	* 初始化所有界面和事件
	*/
	$(function(){
		init();
		// edit report setting
		if (typeof(_initEditRpt) == 'function')
		{
			_initEditRpt();
		}
	});
	
	/**
	* Init User Defined Report Wizard UI
	*/
	function init()
	{
		_initGlbObj();
		_defaultHide();
		_initButtons();
		_initTabs();
		_initValidation();
		_bindEvent();
	}
	/**
	 * Init global object for reuse to improve performance
	 */
	function _initGlbObj()
	{
		$dis_col_list 	   = $('#dis_col_list');
		$dis_col_list1 	   = $('#dis_col_list1');
		$dis_col_list2 	   = $('#dis_col_list2');
		$dis_col_list3 	   = $('#dis_col_list3');
		$cond_col_list 	   = $('#cond_col_list');
		$sort_col_list 	   = $('#sort_col_list');
		$stts_col_list 	   = $('#stts_col_list');
		$def_col_list	   = $('#def_col_list');
		$attr_dis_col_list = $('#attr_dis_col_list');
		$wiz_step		   = $('#wiz_step');
		$ui_col_list       = $('#ui_col_list');
		$ui_group_col_list = $('#ui_group_col_list');
		$default_where_dis = $('#default_where_dis');
		$col_grp_acc	   = $('#col_grp_acc');
		$allow_col_group   = $('#allow_col_group');
		$step2_tab_sub	   = $('#step2_tab_sub');
	}
	
	/**
	* 把事件 Binding 到相关物件上
	*/
	function _bindEvent()
	{
		// choose report layout style
		$('img').click(function(){_setRadioChk($(this).attr('id'));});
		$('input[name=layout_type]:radio').click(function(){
			_setRadioChk($(this).attr('id'));
		});
		
		//open_help_pulldownlist
		$('#open_help_pulldownlist').click(function(){
			_initDialog('dialog_help_pulldownlist');
			$('#dialog_help_pulldownlist').dialog('open');
			return false;
		});
		
		//open_add_groupcols
		$('#open_add_groupcols').click(function(){
			if (_checkDisColsBeforeOpen()){
				_initDialog('dialog_add_colsgroup');
				$('#dialog_add_colsgroup').dialog('open');
				return false;
			}
		});
		// 如果允许分页, enable 每页笔数和分布 toolbar 位置
		$('#allow_paging').change(function(){
			var de = $(this).attr('checked') ? false : true;
			$('#numperpage').attr('disabled',de);
			$('#pagerbarpos').attr('disabled',de);
			// clear value when disable checkbox
			if (de)
			{
				$('#numperpage').val("");
				$('#pagerbarpos').val("");
			}
		});
		
		// 根据画面显示的UI类型变换属性
		$('#ui_type').change(function(){
			var v = $(this).val();
			var tr_chk    = $('#tr_chked_val');
			var tr_url    = $('#tr_tgt_url');
			var chked_val = $('#chked_val');
			var tgt_url   = $('#tgt_url');
			
			if (v == 'checkbox')
			{
				tr_chk.show();
				tr_url.hide();
				tgt_url.val('');
			}
			else if(v == 'href')
			{
				tr_chk.hide();
				tr_url.show();
				chked_val.val('');
			}else{
				tr_chk.hide();
				tr_url.hide();
				chked_val.val('');
				tgt_url.val('');
			}
		});
		// 是否允许排序
		$('#sort_allow').change(function(){
			var tr_sort_type = $('#tr_sort_type');
			var tr_sort_seq  = $('#tr_sort_seq');			
			if ($(this).attr('checked'))
			{
				tr_sort_type.show();
				tr_sort_seq.show();
			}else{
				tr_sort_type.hide();
				tr_sort_seq.hide();
				$('#sort_type').val('');
				$('#sort_seq').val('');
			}
		});
		
		// 是否允许分组统计
		$('#groupby_allow').change(function(){
			var tr_groupby_type = $('#tr_groupby_type');
			if ($(this).attr('checked'))
			{
				tr_groupby_type.show();
			}else{
				tr_groupby_type.hide();
				$('#groupby_type').val('');
			}
		});
		
		// 负数格式选其它时
		$('#unsign_fmt').change(function(){
			var tr_uf_font_color = $('#tr_uf_font_color');
			var tr_uf_bg_color = $('#tr_uf_bg_color');
			if ($(this).val() == 'others')
			{
				tr_uf_font_color.show();
				tr_uf_bg_color.show();
			}else{
				tr_uf_font_color.hide();
				tr_uf_bg_color.hide();
				$('#uf_font_color').val('');
				$('#uf_bg_color').val('');
			}
		});
		//　如果查询条件是下接清单时
		$('#is_list_cond').change(function(){
			var tr_list_cond = $('#tr_list_data_source');
			if($(this).val() != '')
			{
				tr_list_cond.show();
			}else{
				tr_list_cond.hide();
				$('#is_list_cond').val('');
				$('#list_data_source').val('');
			}
		});
	}
	/**
	* 打开栏位分组Dialog 之前检查是否有选取栏位
	*/
	function _checkDisColsBeforeOpen()
	{
		if($dis_col_list.children().length == 0)
		{
			alert('未选取任何栏位不能分组.');
			return false;
		}else{
			$ui_col_list.html($dis_col_list.html());
			_removeExistsItem($ui_col_list.children(),$col_grp_acc.children());
			_initDD('ui_col_list','ui_group_col_list');
		}
		return true;
	}

	/**
	* Init Dragdrop Container
	* @param lContainer drag from 
	* @param rContainer drop to
	*/
	function _initDD(lContainer,rContainer)
	{
		$('#'+lContainer+',#'+rContainer).sortable({
			placeholder: 'ui-state-highlight',
			connectWith: '.connectedSortable'
		}).disableSelection();
	}

	/**
	 * Get column list by view or table name
	 */
	/*
	function _initColsList()
	{
		// 如果 view 名称没有改变就不再去 DB 拿资料
		var viewname = $('input[name=datasource]:checked').val();
		viewname = typeof(viewname) == 'undefined' ? lastDsName : viewname;
		//alert('vname->'+viewname+'----lastviewname:'+lastViewName);
		if (viewname != '' && viewname != lastViewName)
		{
			//alert('Current view name->'+lastDsName+'   Last view name--->'+lastViewName);
			$.ajax({
				type:'post',
				url:'?scriptname=user_def_rpt_wiz', // redirect only get GET variables
				async: false, // 必须是 false, 否则会跳到下一步
				dataType: 'json',
				data: {
					func: 'getColumnsByView',
					arg1: viewname,
					ajaxcall: 1
				},
				success: function(data){
					if(data.length>0)
					{
						lastViewName = viewname; // store the current view had fetch cols
						colsList = data; 		 // store the columns for next step use
					}
				},
				error: function(data){
					alert('读取数据来源出错');
				}
			});
		}
		/* 是日期时显示日期挑选 dialog (复制 row 时有问题, 暂时不用此功能)
		$('#where_tab .combox').change(function(){
			var x = $(this).val();
			for (var i in colsList)
			{
				if (colsList[i]['COLUMN_NAME'] == x)
				{
					if(colsList[i]['DATA_TYPE'] == 'DATE')
					{
						$(this).parent().parent().find('#col_value1,#col_value2').datepicker();
					}else{
						$(this).parent().parent().find('#col_value1,#col_value2').datepicker('destroy');
					}
					break;
				}
			}
		});**
	}*/

	/**
	 * Get column list by view or table name and store into a global variable
	 *
	 * @param string viewname view or table name
	 * @return void
	 * @author Dennis
	 */
	function _initColsList(viewname)
	{
		console.log('colsList['+viewname+'] type->:'+typeof colsList[viewname]);
		// only get once, 
		if (typeof colsList[viewname] == 'undefined')
		{
			console.log('fetch datasource columns '+viewname);
			$.ajax({
				type:'post',
				url:'?scriptname=user_def_rpt_wiz', // redirect only get GET variables
				async: false,// 必须是 false, 否则会跳到下一步
				dataType: 'json',
				data: {
					func: 'getColumnsByView',
					arg1: viewname,
					ajaxcall: 1
				},
				success: function(data){
					if(data.length>0)
					{
						colsList[viewname] = data; // store the columns for next step use
						console.log('After ajax get columns by viewname,the colsList len->'+colsList.length)
					}
				},
				error: function(data){
					alert('读取数据来源出错');
				}
			});
		}
	}
	/**
	* Help Function of init
	* Hide default hidden objects
	*/
	function _defaultHide()
	{
		var hideObjs = ['btn_complete',
		                'dialog_def_where',
		                'dialog_help_pulldownlist',
		                'dialog_add_colsgroup',
		                'srow_property'];
		
		var c = hideObjs.length;
		for (var i=0; i<c; i++)
		{
			$('#'+hideObjs[i]).hide();
		}
	}
	
	/**
	* Click image set radio button checked
	*/
	function _setRadioChk(imgid)
	{
		switch(imgid)
		{
			case 'img_layout_srow':
			case 'radio_layout_srow':
				var chkd = true;
				$('#radio_layout_srow').attr('checked',chkd);
				_showSingleRowAttr(chkd);
				_showMultiRowAttr(!chkd);
				break;
			case 'img_layout_mrow':
			case 'radio_layout_mrow':
				var chkd = true;
				$('#radio_layout_mrow').attr('checked',chkd);
				_showSingleRowAttr(!chkd);
				_showMultiRowAttr(chkd);
				break;
			default:break;
		}
		
	}
	
	/**
	* show or hide single rows report attributes setting
	*
	* @param boolean is_show
	* @return void
	*/
	function _showSingleRowAttr(is_show)
	{
		// single row 进阶设定 step 2
		if (is_show)
		{
			$('#srow_property').show();
			$('#step3_tab_t6').show();
			$('#step3-tab-6').show();			
		}else{
			$('#srow_property').hide();
			$('#step3_tab_t6').hide();
			$('#step3-tab-6').hide();
		}
	}
	
	/**
	* show or hide multiple rows report attributes setting
	*
	* @param boolean is_show
	* @return void
	*/
	function _showMultiRowAttr(is_show)
	{
		// single row 进阶设定 step 2
		if (is_show)
		{
			$('#mrow_property').show();
			$('#step3_tab_t2').show();
			$('#step3_tab_t3').show();
			$('#step3_tab_t4').show();
			$('#step3_tab_t5').show();
			$('#step3-tab-2').show();
			$('#step3-tab-3').show();
			$('#step3-tab-4').show();
			$('#step3-tab-5').show();
		}else{
			$('#mrow_property').hide();
			$('#step3_tab_t2').hide();
			$('#step3_tab_t3').hide();
			$('#step3_tab_t4').hide();
			$('#step3_tab_t5').hide();
			$('#step3-tab-2').hide();
			$('#step3-tab-3').hide();
			$('#step3-tab-4').hide();
			$('#step3-tab-5').hide();
		}
	}
			
	/**
	* Help Function of init
	* init auto complete field
	*/
	function _initAutoComplete()
	{
		// 系统变量
		var sysVars = ['1.我的公司代码',
		               '2.我的部门代码',
		               '3.我的员工代码',
		               '4.系统日期'];
		// init the autocomplete columns
   		$("#dialog_def_where .sysvars").autocomplete({
   			source: sysVars,
   			minLength: 1
   		});
	}
	
	/**
	*　初始化每一步骤上的资料 
	*  如第二步需要抓 view, 第三步需要抓所选取 View 上的栏位
	* @param number step
	*/
	function _initWizData(step)
	{
		//alert('init wiz step->'+step);
		switch(step)
		{
			case 1:// set report name to wizard title
				var rpt_name = $('#report_name').val();
				$('#rpt_desc').val(rpt_name); // store the report name to hidden field for insert to db
				break;
			case 2:// 取得数据来源 (table or views)
				_initDatasource(); 			// get & set data source (get tables list and add to UI)
				_initDataSourcePageEvent(); // binding events to "advanced tab" buttons
			break;			
			case 3: // 画面显示栏位设定
				_initUICol();
			break;
			case 4: // 单笔布局栏位资料分组
				colGroup = new Array(); // before store clear old data
				alert('group acc lenght->'+$col_grp_acc.children().length);
				if ($col_grp_acc.children().length>0)
					_storeColGrpSetting();
			break;
			default:break;
		}
	}
		
	/**
	* binding events to "advanced tab" buttons
	* @param no
	* @author Dennis 2012-08-13
	*/
	function _initDataSourcePageEvent()
	{
		// open default where dialog
		$('#open_def_where_dlg').unbind('click'); // clear event before event binding
		$('#open_def_where_dlg').click(function(){
			var dlgId = 'dialog_def_where';
			var $dlg = $('#'+dlgId);			
			if (datasourceList.length > 0)
			{
				if(currWhereHtml != '' && $default_where_dis.val() != '' && currWhereVals.length>0){
					//alert('记录条件'+currWhereHtml);
					$dlg.empty();// 移除原来的 where condtion table
					$dlg.append(currWhereHtml); // 恢复保存的 where conidtion table
					// 恢复 event
					var i = 0;
					$('#where_tab tr').each(function(){
						var selectop = $(this).find('#select_operator');
						var addbtn   = $(this).find('#btn_add');
						var delbtn   = $(this).find('#btn_remove');
						_initDlgCondAddDelBtn(addbtn,delbtn); // init 画面上的 button(add/delete)
						$(this).find('#select_cols').val(currWhereVals[i]['col']);
						selectop.val(currWhereVals[i]['opr']);
						$(this).find('#col_value1').val(currWhereVals[i]['v1']);
						$(this).find('#col_value2').val(currWhereVals[i]['v2']);
						i++;
						selectop.unbind('change');
						_initDlgCondOpList(selectop);
					});
				}
				_initDialog(dlgId); // 重新初始化 Dialog 及 Dialog 上的  elements
				$dlg.dialog('open');
				return true;
			}else{
				alert('请选取数据来源后才能设定预设条件');
				return false;
			}
		});
		
		// clear default where
		$('#clear_query_where').unbind('click');// unbinding events before event bind for back
		$('#clear_query_where').click(function(){
			if ($default_where_dis.val() != ''){
				if(confirm('确定要清除预设查询条件?'))
				{
					_clearDefWhere('where_tab');	
				}
				return false;
			}else{
				alert('未设定预设查询条件');
				return false;
			}
			return true;
		});
	}
		
	function _initUICol()
	{
		var layout_type = $('input[name=layout_type]:checked').val();
		if ($dis_col_list.children().length == 0)
		{
			_addCol2UL($def_col_list);
			
			_initDD('def_col_list','dis_col_list');
			
			if (layout_type == '2'){ // 多笔显示
				_initDD('dis_col_list1','cond_col_list');
				_initDD('dis_col_list2','sort_col_list');
				_initDD('dis_col_list3','stts_col_list');
			}
		}
		
		if (typeof(rptColsList) == 'object'){
			_setDisplayCol(rptColsList['display']);
		}
		
		if (layout_type == '1'){
			// bind event to link
			$('#reset_col_grp').unbind('click');
			$('#reset_col_grp').click(function(){
				if($col_grp_acc.children().length > 0 && confirm('确定要重置所有分组?'))
				{
					$col_grp_acc.empty(); 					// clear column group on screen
					$ui_col_list.empty();					// clear dialog ui column list for re-fill
					$ui_col_list.html($dis_col_list.html());// refill display column to dialog ui_col_list
					colGroup = new Array();					// clear global variables
				}else{
					alert('无分组栏位,无须重置');
				}
			});
		}
	}

	/**
	 * Get all datasource(tables,views) list (only once if not fetched)
	 * @param no
	 * @author Dennis
	 */
	function _initDatasource()
	{
		//console.log('init datasource, get datasource from db and add it to UI. now datasource count->'+$('.datasource').length );
		// check data source is fetched
		if ($('.datasource').length == 0)
		{
			$.ajax({
				type:'post',
				url:'?scriptname=user_def_rpt_wiz', // redirect only get GET variables
				//async: false, // 必须是 false, 否则会跳到下一步
				dataType: 'json',
				data: {
					func:'getDbViewList',
					arg1:'', // get all datasource -- modify by dennis 2012-08-13
					ajaxcall: 1
				},
				success: function(data){
					_addDS2Table(data,dsTableId);
				},
				error: function(){
					alert('读取报表数据来源出错.\n'+data);
				}
			});
		}
	}
	/**
	* Add column to UL element for dragdrap
	*/
	function _addCol2UL(ulobj)
	{
		ulobj.empty();
		// loop 目前选中的 datasource
		for(ds_name in datasourceList)
		{
			var tv_name = datasourceList[ds_name];
			var tv_label = $('#'+tv_name+'_label').val();
			var col_list = colsList[tv_name];
			var c = col_list.length;			
			for (var i=0; i<c; i++)
			{
				// remove the pk,fk column
				if (noDisColList.indexOf(col_list[i]['COLUMN_NAME'])== -1)
				{
					console.log('column->'+col_list[i]['COLUMN_NAME']+', column data type->'+col_list[i]['DATA_TYPE']);
					ulobj.last().append('<li class="ui-state-default ui-corner-all" id="'+tv_name+'.'+col_list[i]['COLUMN_NAME']+'">'+
						'<span class="ui-icon ui-icon-tag"></span>'+tv_label+'.'+col_list[i]['COLUMN_DESC']+
						'<input type="hidden" class="hide_data_type" value="'+col_list[i]['DATA_TYPE']+'"/>'+
						'<input type="hidden" id="col_desc"       value="'+col_list[i]['COLUMN_DESC']+'"/>'+
						'<input type="hidden" id="data_type_cn"   value="'+col_list[i]['DATA_TYPE_CN']+'"/>'+
						'</li>');
				}
			}
		}
	}
	
	/**
	 * Help Function
	 * add datasource to table
	 * @param ds_list
	 * @param tab_id
	 * @author Dennis
	 */
	function _addDS2Table(ds_list,tab_id)
	{
		var len =  ds_list.length;
		var $ds_table = $("#"+tab_id);
		if (len > 0)
		{
			for (var i=0; i<len; i++)
			{
				$ds_table.last().append('<tr>'+
						'<td>'+
							'<input type="checkbox" class="datasource" '+
									'name="datasource[]" '+
									'id  ="'+ ds_list[i]['TAB_NAME']+'" '+
									'value="'+ ds_list[i]['TAB_NAME']+'"/>'+
							//'<input type="hidden" name="module_id" value="'+ds_list[i]['MODULE_ID']+'"/>'+
							'<input type="hidden" id="'+ds_list[i]['TAB_NAME']+'_label" value="'+ds_list[i]['TAB_DESC']+'"/>'+
						'</td>'+
						'<td>'+
							'<label for="'+ds_list[i]['TAB_NAME']+'">'+
									(ds_list[i]['TAB_DESC'] ? ds_list[i]['TAB_DESC'] : ds_list[i]['TAB_NAME'])+
							'</label>'+
						'</td>'+
						'<td>'+ ds_list[i]['TAB_REMARK']+'</td>'+
					'</tr>');
			}
			_bindEvent2DS($ds_table);
		}else{
			// no datasource
			$ds_table.last().append(_noViewsFound());
		}
	}
	
	/**
	 * bind event to datasource hanlder(checkbox)
	 * @param ds_tab_obj
	 */
	function _bindEvent2DS(ds_tab_obj)
	{
		ds_tab_obj.find('.datasource').change(function(){
			// max supprt 3 tables or views join 
			if (datasourceList.length > 3)
			{
				$(this).attr('checked',false);// restore to unchecked
				alert('报表性能原因，最多可以选不超 过三个数据源');
				return false;
			}
			lastDsName = $(this).val();	// store the current view name to global variabls
			// clear the default where condition if data source changed
			if ($default_where_dis.val()!= '' || $dis_col_list.children().length >0 )
			{
				if(confirm('预设查询条件或已选取栏位,如果更改数据来源将会清除后面的设定,确定要更改吗?'))
				{
					_clearDefWhere('where_tab');	// Clear 预设条件画面且保留第一行
					_clearDisColAttrs();			// Clear UI and Column Attribute Values
				}else{
					//restore to previous value
					//console.log('you click the cancle button');
					$('#'+lastDsName).attr('checked',true);
					return false; // 取消后面的就不执行
				}
			}
			
			if ($(this).attr('checked'))
			{
				//$('#moduleid').val($(this).next().val());	// store the module id // remark by dennis, all report in the ENSR
				dsLabel.push($('#'+lastDsName+'_label').val());// store the datasource label to global variable
				datasourceList.push(lastDsName); 			// store the data source name to global variable
				_initColsList(lastDsName); 	   				// fetch table or view columns into global variabl

			}else{
				_rmEleFromArray(lastDsName,datasourceList);	// remove datasource from ds list
				//for(i in colsList) console.log('after uncheck, now colsList array'+colsList[i]);
			}
		});
	}
	
	/**
	 * Clear all columns on display & column's attributes
	 */
	function _clearDisColAttrs()
	{
		$attr_dis_col_list.empty();	// clear the columsn attribute setting
		$col_grp_acc.empty();		// clear column group setting UI
		lastLi	= '';				// clear last select column li object 
		colAttrVals = new Array(); 	// clear the column attribute values
		_clearColAttrUI();			// clear column attribute setting UI
		colGroup = new Array();		// clear the column group setting
		$dis_col_list.empty();		// clear the display column setting
		$dis_col_list1.empty();		// 清除画面显示栏位设定 (定义可查询栏位)
		$dis_col_list2.empty();		// 清除画面显示栏位设定 (定义可排序栏位)
		$dis_col_list3.empty();		// 清除画面显示栏位设定 (定义统计分组栏位)
		$cond_col_list.empty();		// 清除可查询栏位
		$sort_col_list.empty();		// 清除可排序栏位
		$stts_col_list.empty();		// 清除可统计栏位
	}
	
	/**
	 * add selected datasource columns to select list 
	 * @param cols_list {Array}
	 * @param list_id   {String}
	 * @author Dennis
	 */
	function _addItem2List(list_id)
	{
		var $select_ele = $('#'+list_id);
		$select_ele.empty();
		// 多数据源时,只加目前在 datasourceList 中的  table 的 column
		for(ds_name in datasourceList)
		{
			var tv_name = datasourceList[ds_name]; // table or view name
			var clist = colsList[tv_name];
			var c = clist.length;
			$select_ele.append('<optgroup label="'+$('#'+tv_name+'_label').val()+'"></optgroup>');
			for(var i=0; i<c; i++)
			{
				if (noDisColList.indexOf(clist[i]['COLUMN_NAME'])== -1)
				{
					$select_ele.append('"<option style="text-indent:25px;" value="' + clist[i]['COLUMN_NAME'] + '">' +
										(clist[i]['COLUMN_DESC'] ? clist[i]['COLUMN_DESC'] : clist[i]['COLUMN_NAME'])+ 
										'</option>"');
				}
			}
		}
	}
	
	/**
	 * remove element from array
	 * @param {Mixed} el
	 * @param {Array} arr
	 * @returns {Array}
	 */
	function _rmEleFromArray(el,arr)
	{
		var idx = arr.indexOf(el); // find the element index
		return arr.splice(idx,1);
	}
	
	/**
	* 未找到可用的 view 时，显示 no data found
	*/
	function _noViewsFound()
	{
		return '<tr><td colspan="3"><div class="ui-state-highlight ui-corner-all">'+
			   '<span class="ui-icon ui-icon-info" style="float:left;margin:2px;padding:2px;"></span>'+
			   '无相关数据来源,请洽询管理员</div></td></tr>';
	}
	/**
	* 恢复 default where condition　dialog 到初始状态
	*/
	function _clearDefWhere(dlgtabid)
	{
		//alert('呼叫重置 Dialog _clearDefWhere');		
		$default_where_dis.val(''); 			// clear 显示的 where condition
		$('#default_where').val('');	 		// clear 实际的 where condition
		currWhereHtml = '';					 	// clear 记录的 where condition
		currWhereVals = new Array();			// clear 记录的 where conditon fact values
		$('#'+dlgtabid+' tr:gt(0)').remove(); 	// remove rows except first row
		_initDefWhereRow($('#'+dlgtabid+' tr'));// restore first row to default
		_initDlgCondAddDelBtn($('#btn_add'),$('#btn_remove'));
	}
	/**
	* Validate Wizard Every Step
	* Check Input Data & Required
	* Help Function of w
	*/
	function _validateWiz(step)
	{
		//alert('_validateWiz  step->'+step);
		switch(step)
		{
			case 1:
				var ajaxResult = true;
				var $reportname = $('#report_name');
				if ($reportname.val() == '')
				{
					alert('请输入报表名称');
					$reportname.focus();
					return false;
				}
				// check report name unique
				// 新增/修改时去 check 是否有重复的名称
				if ($reportname.val() != $('#rpt_desc').val())
				{
					$.ajax({
						type:'post',
						url:'?scriptname=user_def_rpt_wiz', // redirect only get GET variables
						async: false, 						// 必须是 false, 否则会跳到下一步
						dataType: 'json',
						data: {
							func:'checkRptNameUnique',
							arg1:$reportname.val(),
							ajaxcall: 1
						},
						success: function(data){
							// 新增和修改时判断的不一样
							if (parseInt(data['isexists'])>=1)
							{
								alert('报表名称已经存在,请修改报表名称');
								$reportname.focus();
								ajaxResult =  false;
							}
						},
						error: function(data){
							alert('检查报表名称唯一性错误:'.data['error']);
							$reportname.focus();
							ajaxResult =  false;
						}
					});
				}
				//alert('ajaxResult->'+ajaxResult);
				//alert('now report name value is ->'+$reportname.val()+'   program no value->'+$('#program_no').val());
				var app_desc = $('#panel_title').text();
				if ($('#program_no').val() == '' &&  $reportname.val() != '') 
				{
					$('#panel_title').text($reportname.val());
				}
				return ajaxResult;
				break;
			case 3:
				console.log('current datasource lenght->'+datasourceList.length);
				for(i in datasourceList) console.log('datasource->'+datasourceList[i]);
				if(datasourceList.length == 0)
				{
					alert('请选择数据来源');
					return false;
				}
				// when change report type default select first tab
				$('#step3_tab').tabs('select', 0);
				//$('#data_source_desc').text();// remark by dennis 20120822
				return true;
				break;
			case 4:
				if ($dis_col_list.children().length == 0)
				{
					alert('未选取任何栏位,至少要选取一个栏位');
					return false;
				}				
			default:break;
		}
		return true;
	}
	
	/**
	 * 多笔资料或单笔显示不分组略过栏位分组设定
	 * @param ac string 'next' or 'back' text
	 * @author Dennis 2012-07-31 update
	 */
	function _adjustStep(ac)
	{
		/* remark by dennis 2012-08-13 not needed jump step now
		var curr_step = $wiz_step.val();
		
		if (( curr_step == 3 && ac == 'next') || (ac == 'back' && curr_step == 5))
		{
			if ($('input[name=layout_type]:checked').value == '2' || 
				$allow_col_group.attr('checked') == false) return 2;
		}*/
		return 1;
	}
	
	/**
	* init Help Function
	* init all tabs
	*/
	function _initTabs()
	{
		for (var i=0; i<=6; i++)
		{
			$('#step'+i+'_tab').tabs();
			if (i>0) $('#step'+i).hide();
		}		
		$('#step3_tab').bind('tabsselect', function(event,ui){
			// copy display item to attribute setting
			_bindEvent2Col(ui.index);
			switch(ui.index)
			{
				case 1:
					if (typeof(rptColsList) == 'object' && rptColsList['cond'].length>0){
						_setQueryAllowCol(rptColsList['cond']);
						rptColsList['cond'] = new Array(); // clear cols list after set
					}
					_removeExistsItem($dis_col_list1.children(),$cond_col_list.children());
				break;
				case 2:
					if (typeof(rptColsList) == 'object' && rptColsList['sort'].length>0){
						_setSortAllowCol(rptColsList['sort']);
						rptColsList['sort'] = new Array(); // clear cols list after set
					}
					_removeExistsItem($dis_col_list2.children(),$sort_col_list.children());
				break;
				case 3:
					if (typeof(rptColsList) == 'object' && rptColsList['stts'].length>0){
						_setSttsAllowCol(rptColsList['stts']);
						rptColsList['stts'] = new Array(); // clear cols list after set
					}
					_removeExistsItem($dis_col_list3.children(),$stts_col_list.children());
				break;
				case 4:
				// store query cols, order by cols, group by cols
				// 如果拖拽设定过,在进阶属性设定中也要显示设定的属性
				// ???? BUG 这里有 bug,当设定两个以上的栏位时, 点到属性设定栏位,属性却读不到第一个栏位的
				// 已经 trace 过,在 _bindEvent2Col 中的 click 事件,click 之前还是有值的,就是没有读到画面上去 
				// ??? BUG				
				_storeColSetting();
				break;
			}
			/*
			if(ui.index == 3)
			{
				_bindEvent2Col();
			}
			*/
			// 如果属性设定那边有调整栏，点到基本设定时，同步栏位顺序
			/* 不允许属性设定时调顺序
			if (ui.index == 0)
			{
				$dis_col_list.html($attr_dis_col_list.html());
			}
			if (ui.index == 4)
			{
				_storeColSetting();
			}
			*/
		});
	}
	
	/**
	 * Remove item from LContainer if exits rContainer
	 */
	function _removeExistsItem(lContainer,rContainer)
	{
		if (lContainer.length>0 && rContainer.length>0)
		{
			lContainer.each(function(){
				var LLi = $(this);
				rContainer.each(function(){
					var RLi = $(this);
					//alert(LLi.attr('id')+' -> '+RLi.attr('id'));
					if (LLi.attr('id') == RLi.attr('id')) LLi.remove();
				});
			});
		}
	}
	
	/**
	* Bind event to the columns will display on screen
	*/
	function _bindEvent2Col(tabidx)
	{
		var colsli = $dis_col_list.children();
		if (colsli.length != 0)
		{
			var discols = $dis_col_list.html();
			//alert(('#dis_col_list'+tabidx).html());
			$('#dis_col_list'+tabidx).html(discols);
			if (tabidx == 4)
			{
				// copy display column to attribute setting
				$attr_dis_col_list.html(discols);				
				// init colAttrVals array where display column setting
				
				/* 设定属性时不允许 Sort
				$attr_dis_col_list.sortable({
					placeholder: 'ui-state-highlight'
				});
				*/
				/*
				 *<li class="ui-state-default ui-corner-all ui-state-highlight" id="hr_rpt_reward_v.CDAY">
				 *<span class="ui-icon ui-icon-tag"></span>员工奖惩.归属日期
				 *<input type="hidden" class="hide_data_type" value="DATE">
				 *<input type="hidden" id="col_desc" value="归属日期">
				 *<input type="hidden" id="data_type_cn" value="日期">
				 *</li>
				 */
				$('#attr_dis_col_list li').bind('click',function(){
					var datatype = $(this).children('input:nth-child(2)').val();
					// hide/show attribute where column name change
					_switchAttrRow(datatype);
					var colid = $(this).attr('id');
					// 如果是varchar2 时日期或是数字类型的属性隐藏起来
					// switch css & icons when li click
					if (lastLi !='' && lastLi.attr('id') != colid)
					{
						// store last column attribute values
						_storeColAttrVals(lastLi.attr('id'));
						// clear current attribute values
						_clearColAttrUI();
						// read the current column attribute from global variables
						_readColAttrVals(colid);
						// clear last li css to default
						lastLi.removeClass('ui-state-highlight');
						lastLi.find('span').removeClass('ui-icon-flag');
						lastLi.find('span').addClass('ui-icon-tag');
					}
					// store current li as last li and change css to selected
					lastLi = $(this);
					lastLi.addClass('ui-state-highlight');
					lastLi.find('span').removeClass('ui-icon-tag');
					lastLi.find('span').addClass('ui-icon-flag');
					// set title to current select col	and store column default attributes to hidden input			
					$('#col_attr_tab #colname').text(' - ['+lastLi.text()+']');
					var data_type_cn = lastLi.children('input:nth-child(4)').val();
					$('#col_attr_tab #col_data_type').text(data_type_cn);
					// store the data type (varchar2,date) to hidden input
					$('#col_attr_tab #attr_data_type').val(datatype);
					var col_desc = lastLi.children('input:nth-child(3)').val();
					$('#col_attr_tab #attr_col_title').val(col_desc);
				});
				_initColAttrVals(colsli);
			}
		}
	}
	
	function _initColAttrVals(colsli)
	{
		// 如果没有值才会来 Init		
		if (_lenOfAssArray(colAttrVals) == 0)
		{
			//alert('执行重置栏位属性值');
			colAttrVals = new Array();
			colsli.each(function(){
				var colname = $(this).attr('id');
				colAttrVals[colname] = new Array();
				for (var i in colAttrKeys)
				{
					colAttrVals[colname][colAttrKeys[i]] = '';
				}
				// 未做任何属性设定时, DB 必须的标准栏位给出预设值
				colAttrVals[colname]['ui_type']  = 'text'; 
				colAttrVals[colname]['attr_data_type'] = $(this).find('.hide_data_type').val();
				colAttrVals[colname]['attr_col_title'] = $(this).find('#col_desc').val();
			});
		}
	}
	
	/**
	 * 
	 * Help Function of _initColAttrVals()
	 * 
	 * Javascript Does Not Support Associative Arrays
	 * An associative array is an array which uses a 
	 * string instead of a number as an index.
	 * @param array arr Associative arrray index by string
	 * @return number
	 * @author Dennis
	 */
	function _lenOfAssArray(arr)
	{
		var j = 0;
		for (var i in arr)
		{
			j++;
		}
		return j;
	}
	
	
	/**
	* show/hide property according the data type
	*/
	function _switchAttrRow(datatype)
	{
		var tr_date_fmt		= $('#tr_date_fmt');
		var tr_num_format	= $('#tr_num_format');
		var tr_dec_num 		= $('#tr_dec_num');
		var tr_unsign_fmt	= $('#tr_unsign_fmt');
		switch(datatype.toLowerCase())
		{
			case 'varchar2':
				tr_date_fmt.hide();
				tr_num_format.hide();
				tr_dec_num.hide();
				tr_unsign_fmt.hide();
				break;
			case 'date':
				tr_date_fmt.show();
				tr_num_format.hide();
				tr_dec_num.hide();
				tr_unsign_fmt.hide();
				break;
			case 'number':
				tr_date_fmt.hide();
				tr_num_format.show();
				tr_dec_num.show();
				tr_unsign_fmt.show();
				break;
			default:break;
		}
	}
	
	/**
	* Store column attribute values to Array
	* indexed by the attrkey
	*/
	function _storeColAttrVals(colname)
	{
		// clear old value before store new value
		colAttrVals[colname] = new Array();
		var $attrtab = $('#col_attr_tab');
		for (var i in colAttrKeys)
		{
			var k = colAttrKeys[i];
			var attrobj = $attrtab.find('#'+ k);
			var v = attrobj.val();
			if (attrobj.attr('tagName') == 'INPUT' && attrobj.attr('type') == 'checkbox' )
			{
				v = attrobj.attr('checked') == true ? 1 : '';
			}
			//alert(k+'->store->'+v);
			colAttrVals[colname][k] = typeof(v) != 'undefined' ? v : '';
		}
	}
	
	/**
	* Read column attruibutes from array to UI
	*/
	function _readColAttrVals(colname)
	{
		if (typeof(colAttrVals[colname]) != 'undefined')
		{
			for (var i in colAttrKeys)
			{
				var k = colAttrKeys[i];
				var attrobj = $('#'+k);
				var v = colAttrVals[colname][k];
				// get & assign value
				attrobj.val(v);
				// if the element is select fire the onchange event
				if (attrobj.attr('tagName') == 'SELECT') attrobj.change();
				
				if (attrobj.attr('tagName') == 'INPUT' && attrobj.attr('type') == 'checkbox') 
				{
					var chk = v=='1' ? true : false;
					attrobj.attr('checked',chk);
					attrobj.change();
				}
			}
		}
	}
	
	/**
	* 清除属性设定画面上所有值
	*/
	function _clearColAttrUI()
	{
		// clear property
		$('#col_attr_tab #colname').text('');
		$('#col_attr_tab #col_data_type').text('');
		$('#col_attr_tab #attr_data_type').val('');
		$('#col_attr_tab #attr_col_title').val('');
		
		var defHideRows = ['groupby_type',
		                   'uf_font_color',
		                   'uf_bg_color',
		                   'list_data_source',
		                   'sort_type',
		                   'sort_seq'];
		// clear value to default
		for(var i in colAttrKeys)
		{
			var attrobj = $('#'+colAttrKeys[i]);
			// clear value
			attrobj.val('');
			// set checkbox unchecked
			if (attrobj.attr('type') != 'undefined' && attrobj.attr('type') == 'checkbox')
				attrobj.attr('checked',false);
		}
		// hide default hide row
		for(var j in defHideRows)
		{
			$('#tr_'+defHideRows[j]).hide();
		}
	}
	
	/**
	* Init dialog before open
	* @param dialogId string  the dialog id
	* @author Dennis
	*/
	function _initDialog(dialogId)
	{
		switch(dialogId)
		{
			case 'dialog_def_where':
				// 不能放在 dialog 的 create 里 create 只会 init 一次，换 view 之后栏位没有重新换
				_addItem2List('select_cols');  //打开之前填充栏位清单 List
				// init all autocomplete column before open
				_initAutoComplete();			
				// init default where dialog
				$('#'+dialogId).dialog({
					autoOpen: false,
					modal: true,
					width: 535,
					height:300,
					buttons:[{
						text: "确定",
						click: function(){
							_combine2Where(); // 组合查询条件
							_storeDefWhere(dialogId);　// 记录当前条件物件
							$(this).dialog("close");
						}
			         },
			         {
			        	 text: "取消",
			        	 click: function(){
			        		 if ($default_where_dis.val() == '' && $('#where_tab').attr('rows').length>1) _clearDefWhere('where_tab');
			        		 $(this).dialog("close");
			        	 }
			         }],
					create:function(event){
						// execute once code here
						_initDlgCondAddDelBtn($('#btn_add'),$('#btn_remove')); // 打开之前 init 画面上的 button(add/delete)
						_initDlgCondOpList($('#select_operator'));  		   // 打开之前 init 画面上的 Select Onchange 事件
					}
				});
				break;
			case 'dialog_help_pulldownlist':
				// pulldownlist help dialog 
				$('#'+dialogId).dialog({
					autoOpen: false,
					modal: true,
					width: 500,
					buttons:[{
			        	 text: "关闭",
			        	 click: function(){ $(this).dialog("close");}
			        }]
				});
				break;
			case 'dialog_add_colsgroup':
				// init default where dialog 
				$('#'+dialogId).dialog({
					autoOpen: false,
					modal: true,
					width: 535,
					buttons:[{
			        	text: "确定",
			        	click: function(){
			        		var grpdesc = $('#colgroup_name');
			        		if ($.trim(grpdesc.val()) == '')
			        		{
			        			alert('请输入分组名称');
			        			return false;
			        		}
			        		if($ui_group_col_list.children().length ==0)
			        		{
			        			alert('至少要选取一个栏位');
			        			return false;
			        		}
			        		_addCol2Grp(grpdesc,$ui_group_col_list);
			        		$(this).dialog("close");
			        	}
			         },
			         {
			        	 text: "取消",
			        	 click: function(){
			        	 	$(this).dialog("close");
			        	 }
			         }]
				});
				break;
			default:break;
		}
	}
	/**
	 * Delete Column Group
	 */
	function _removeGrp(ao)
	{
		if(confirm('确定要删除此群组?'))
		{
			var accordionObj = ao.parent().parent();
			// restore columns to ui_col_lis container
			$ui_col_list.last().append(accordionObj.find('div ul').html());
			// remove current panel
			accordionObj.remove();
		}
	}
	
	/**
	 * trim white space
	 * tmp not used
	 */
	function trim(stringToTrim) {
		return stringToTrim.replace(/^\s+|\s+$/g,"");
	}
	/**
	* Init The Where Condtion Setting Dialog's 
	* Operator select box
	* 
	*/
	function _initDlgCondOpList(selectObj)
	{
		// 如果区间条件 show 另外一个栏位
		selectObj.change(function(){
			// 因为 row 会被 clone 所以 ID 不一定是唯一了,只能用以下方法在 row 里 find
			var col2 = $(this).parent().parent().find('#col_value2');
			if('between' == $(this).val())
			{
				col2.show();
			}else{
				col2.val('');
				col2.hide();
			}
		});
	}
	/**
	* init dialog add/remove button
	* init css & binding event
	*/
	function _initDlgCondAddDelBtn(addbtn,delbtn)
	{
		// unbind click event before init 
		addbtn.unbind('click');
		delbtn.unbind('click');
				
		// init 预设查询条件 Dialog 上的 add/remove button
		_initAddDelBtnUI(addbtn,delbtn);		
        addbtn.css('width','24px');
		addbtn.css('height','24px');
		addbtn.css('margin-bottom','-8px');

        addbtn.click(function(){
        	$('#where_tab').last().append($(this).parent().parent().clone(true));
        	$('#where_tab tr:last').find('#col_value2').hide();
        	// 已知 Issue, 添加新 row 没有 autocomplete 功能
        	// init system variables after clone row
        	// _initAutoComplete();
        });
        
		delbtn.click(function(){
        	var tr_row = $(this).parent().parent();
        	if (tr_row.parent().attr('rows').length == 1 && tr_row.attr('rowIndex') == 0)
        	{
        		// 第一行不删除，恢复成刚打开的样子
        		_initDefWhereRow(tr_row);
        	}else{
        		tr_row.remove();
        		// 打开 dialog 就按 "+" 添加新记录，然后从最下面一笔删除时会出现 button 的 css 丢失的情形
        		// 这里重 init 一次
        		_initAddDelBtnUI(addbtn,delbtn);
        	}
        });
        
		delbtn.css('width','24px');
		delbtn.css('height','24px');
		delbtn.css('margin-bottom','-8px');
	}
	
	/**
	 * 重新初始化 add/delete Button UI
	 */
	function _initAddDelBtnUI(addbtn,delbtn)
	{
		addbtn.button({
            icons: {
            	primary:"ui-icon-plusthick"
            },
            text: false
        });
		delbtn.button({
            icons: {
            	primary:"ui-icon-trash"
            },
            text: false
        });
	}
	/**
	* restore the first row to default
	* @para object tr table tr object
	*
	*/
	function _initDefWhereRow(tr)
	{
		tr.find('td').each(function(){
    		var curr_obj = $(this).children();
    		var objid 	 = curr_obj.attr('id');
    		//alert(objid);
    		switch(objid)
    		{
    			case 'select_cols':
    				_addItem2List(objid);
    				break;
    			case 'select_operator':
    				curr_obj.val('=');
    				break;
    			case 'col_value1':
    			case 'col_value2':
    				curr_obj.val('');
    				break;    			
    			default:break;
    		}
    		if ($('#col_value2').is(':visible')) $('#col_value2').hide();
    	});
	}
		
	/**
	* init Help Function
	* init all buttons in the wizard
	* @author Dennis 2011-04-08
	*/
	function _initButtons()
	{
		$('#btn_back').button({
			icons: {
        		primary:"ui-icon-carat-1-e"
	        },
			text:false
		}).bind('click',function(){
			var step = parseInt($wiz_step.val())-_adjustStep('back');
			if (step>=0)
			{
				//  Back Step Not Need Validation
				w(step,this);
				$wiz_step.val(step);
			}
		}).hide();
		
		$('#btn_next').button({
			icons: {
            	primary:"ui-icon-carat-1-e"
            },
			text:false
		}).bind('click',function(){
			var step = parseInt($wiz_step.val())+_adjustStep('next');
			if (step <= 6)
			{
				// Validation Success to Next Step
				if(w(step,this)) $wiz_step.val(step);
			}
		});
		
		$('#reset_dis_cols').bind('click',function(){
			if ($dis_col_list.children().length>0 && confirm('重置会清除栏位相关设定,确定要重置吗?'))
			{
				_addCol2UL($def_col_list); 	// restore default columns
				_clearDisColAttrs();		// clear all display columns setting
			}else{
				alert('未选取任何栏位,无须重置');
			}
			return false;
		});
		
		$('#dis_all_cols').bind('click',function(){
			$def_col_list.empty();
			_addCol2UL($dis_col_list);
			return false;
		});
	}
	
	/**
	* 初始化需要验证的栏位
	*/
	function _initValidation()
	{
		 $("#form1").validate({
			 rules: {
				 report_name: "required",
				 numperpage : "number",
				 sort_seq : 'number',
				 col_width: 'number',
				 /*
				 email: {
					 required: true,
					 email: true
				},
			   	password: {
				    required: true,
				    minlength: 5
			   },
			   confirm_password: {
				    required: true,
				    minlength: 5,
				    equalTo: "#password"
			   }*/
		  },
		  messages: {
			  report_name: '请输入报表名称',
			  numperpage:  '请输入数字',
			  sort_seq:    '请输入数字',
			  col_width:   '请输入数字'
			  /*
			  email: {
				  required: "请输入Email地址",
				  email: "请输入正确的email地址"
			},
			password: {
				required: "请输入密码",
				minlength: jQuery.format("密码不能小于{0}个字符")
			},
			confirm_password: {
				required: "请输入确认密码",
				minlength: "确认密码不能小于5个字符",
				equalTo: "两次输入密码不一致不一致"
			}*/
		  }
		});
	}
	/**
	* 组合设定的 Where 条件
	*/
	function _combine2Where()
	{
		var wherecond_dis = ''; // 画面上显示条件(文字)
		var wherecond     = ''; // 真实的条件         (SQL Where)
		$('#where_tab tr').each(function(){		// loop tr
			$(this).find('td').each(function(){	// loop td
				var _curr_obj 	  = $(this).children(); // current element(first child of the TD)
				var _curr_obj_val = _curr_obj.val();    // current element value
				var _curr_id 	  = _curr_obj.attr('id');// current element id
				var _pre_obj_val  = $(this).prev().children().val(); // pervious td's first child element value
				
				// 画面上显示的条件
				if(_curr_obj.attr('tagName') == 'SELECT')
				{
					wherecond_dis += ' '+_curr_obj.find("option:selected").text()+' ';
				}else{
					// 处理 between and 和  like
					if(_pre_obj_val == 'between' ||
					    _pre_obj_val == 'like_b'  ||
					    _pre_obj_val == 'like_e'){
						wherecond_dis =  wherecond_dis.replace('..'," '"+_curr_obj_val + (_pre_obj_val == 'between' ? "' 和 ** " : "' "));
					}else{
						//alert(_curr_obj_val);
						wherecond_dis +=  " '"+_curr_obj_val+"'";
					}
				}
				// 实际隐藏真实的条件
				if (_curr_id == 'col_value1')
				{
					// like 语句特殊处理 like_b 以... 开头, like_e 以..结尾
					if(_pre_obj_val.substring(0,4) == 'like'){
						if (_pre_obj_val == 'like')   wherecond += " '%"+ _curr_obj_val + "%'";
						if (_pre_obj_val == 'like_b') wherecond += " '" + _curr_obj_val + "%'";
						if (_pre_obj_val == 'like_e') wherecond += " '%"+ _curr_obj_val + "'"
					}else{
						wherecond += " '"+_curr_obj_val+"' ";
					}
				}else{
					_curr_obj_val = _curr_obj_val.replace('like_b','like');
					_curr_obj_val = _curr_obj_val.replace('like_e','like');
					wherecond    += " "+ _curr_obj_val;
				}
				// 如是在 ... 之间
				var col2 = $(this).children('#col_value2');
				if(typeof(col2.val()) != 'undefined' && col2.is(':visible'))
				{
					wherecond    += " and '" + col2.val()+"' ";
					wherecond_dis =  wherecond_dis.replace('**'," '" + col2.val()+ "' ");
				}
			});
			wherecond　        += ' and ';
			wherecond_dis += ' (并且) \r\n';
		});
		wherecond = wherecond.substring(0,wherecond.length-5);
		//alert(wherecond);
		wherecond_dis =  wherecond_dis.substring(0,wherecond_dis.length-7);
		//alert(wherecond_dis);
		$default_where_dis.val(wherecond_dis);
		$('#default_where').val(wherecond);
	}
	/*
	* 点确定时记录设定的 where 条件以备下次再打开时显示
	* 因为如果不记录，User 在画面点 "+" 添加了几个条件,按了取消按钮
	* 下次打开时这些本来没有的条件还留在上面
	*/
	function _storeDefWhere(tabid)
	{
		var tab = $('#'+tabid);
		currWhereHtml = tab.html();
		var i = 0;
		// store fact values
		tab.find('tr').each(function(){
			currWhereVals[i] = new Array();
			currWhereVals[i]['col'] = $(this).find('#select_cols').val();
			currWhereVals[i]['opr'] = $(this).find('#select_operator').val();
			currWhereVals[i]['v1']  = $(this).find('#col_value1').val();
			if($(this).find('#col_value2').is(':visible'))
			{
				currWhereVals[i]['v2']  = $(this).find('#col_value2').val();
			}else{
				currWhereVals[i]['v2']  = '';
			}
			i++;
		});
	}
	
	/**
	 * Store the query allowed columns
	 * store the sortable columns
	 * store the statistic columns
	 */
	function _storeColSetting()
	{
		$cond_cols = $cond_col_list.children();
		$sort_cols = $sort_col_list.children();
		$stts_cols = $stts_col_list.children();
		for (var i in colAttrVals)
		{
			if ($cond_cols.length>0)
			{
				$cond_cols.each(function(){
					if (i == $(this).attr('id'))
					{
						colAttrVals[i]['query_allow'] = 1;
					}
				});
			}
			
			if ($sort_cols.length>0)
			{
				$sort_cols.each(function(){
					var k = 0;
					if ( i == $(this).attr('id'))
					{
						colAttrVals[i]['sort_allow'] = 1;
						colAttrVals[i]['sort_seq'] = k;
						k++;
					}
				});
			}
			if ($stts_cols.length>0)
			{
				$stts_cols.each(function(){
					if (i == $(this).attr('id'))
					{
						colAttrVals[i]['groupby_allow'] = 1;
					}
				});
			}
		}
	}
	
	/**
	 * 把相关栏位加到指定的分组下面
	 * @param object grp_desc 分组名称 Object
	 * @param object cols_grp 栏位清单 Object
	 * 
	 */
	function _addCol2Grp(grp_desc,cols_grp)
	{
		var stop = false;
		$col_grp_acc.find('h3').click(function(event) {
			if (stop) {
				event.stopImmediatePropagation();
				event.preventDefault();
				stop = false;
			}
		});
		
		// 不能重复 accordion,执行 accordion 之前先 destory
		$col_grp_acc.accordion('destroy');
		var html = '<div><h3><a href="#">'+
				   '<input type="hidden" name="colgrp[]" value="'+grp_desc.val()+'"/>'+
				   grp_desc.val()+'</a></h3><div><ul>'+
				   cols_grp.html()+'</ul>'+
				   '<div class="ui-icon ui-icon-close" onclick="_removeGrp($(this));" style="float:right;"></div></div></div>';
		$col_grp_acc.last().append(html).accordion({ 
			header: "> div > h3",
			collapsible:true,
			navigation: true,
			fillSpace: true,
			clearStyle: true,
			icons: {
				header: 'ui-icon-circle-plus',
				headerSelected:'ui-icon-circle-minus'
			}
		}).sortable({
			axis: "y",
			handle: "h3",
			stop: function(){
				stop = true;
			},
			placeholder: 'ui-state-highlight'
		});
		$col_grp_acc.find('ul').sortable({placeholder: 'ui-state-highlight'});
		grp_desc.val(' ');
		cols_grp.empty();
		$('#colgroup_title').text('分组名称');
	}
	
	/**
	 * Store column group settings
	 */
	function _storeColGrpSetting()
	{
		var i = 0;
		$col_grp_acc.children().each(function(){
			colGroup[i] = new Array();
			colGroup[i]['grp_name'] = $(this).find('input').val();
			colGroup[i]['col_list'] = new Array();
			var j = 0;
			$(this).find('div > ul').children().each(function(){
				colGroup[i]['col_list'][j] = $(this).attr('id');
				j++;
			});
			i++;
		});
	}
	
	/**
	* Wizard next step
	* Click Next Show Match Screen
	*/
	function w(step,eventBtn)
	{
		// validate required or user input when next step
		if (eventBtn.id == 'btn_next')
		{
			_initWizData(step);// fill data (get data from db) before show UI
			var r = _validateWiz(step);
			if (!r) return false;
		}
		var $next_btn = $('#btn_next');
		var $back_btn = $('#btn_back');
		var $comp_btn = $('#btn_complete');
		// display or hide other steps's UI
		for(var i=0; i<= wizCnt; i++)
		{
			if (i == step){
				$('#step'+i).show();
				if (i == wizCnt)
				{
					// 最后一步时
					$next_btn.hide();
					$comp_btn.button();
					$('#form1').submit(function(){
						_initColAttrVals($dis_col_list.children());
						// store sort columns, condition columns, statistic group columsn
						// 必须要放在 init 之后
						_storeColSetting();
						$('#colsattr').val(array2json(colAttrVals));
						$('#colsgroup').val(array2json(colGroup));
					});
					$comp_btn.show();
				}else{
					// 最后一步又倒回时
					$next_btn.show();
					$comp_btn.hide();
					if(0 == i)
					{
						$back_btn.hide();
					}else{
						$back_btn.button();
						$back_btn.show();
					}
				}
			}else{
				$('#step'+i).hide();
			}
		}
		_setCurrStep(step);
		return true;
	}
	
	function _setCurrStep(n)
	{
		$('#c_step').text(n+1);
	}
	
	/**
	 * javascript multi-dimestional array to JSON
	 * @param jsarray array
	 * @return json string
	 * @author Dennis 2011-05-03
	 */
	function array2json(jsarray)
	{
		var jsonstr = '';
		if (typeof jsarray == 'object' && _lenOfAssArray(jsarray) >0)
		{
			jsonstr = '{';
			for (var i in jsarray)
			{
				if (typeof jsarray[i] == 'object')
				{
					jsonstr += '"'+i+'":{"';
					for (var j in jsarray[i])
					{
						jsonstr +=　j+'":"'+jsarray[i][j]+'","';
					}
					jsonstr = jsonstr.substring(0,jsonstr.length-2);
					jsonstr += '},';
				}else{
					jsonstr += '"'+i+'":"'+ jsarray[i] + '",';
				}
			}
			jsonstr = jsonstr.substring(0,jsonstr.length-1);
			jsonstr += '}';
		}
		return jsonstr;
	}