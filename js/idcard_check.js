function getArea(cardno) {
		var area = {
			11 : "北京市",
			12 : "天津市",
			13 : "河北省",
			14 : "山西省",
			15 : "内蒙古",
			21 : "辽宁省",
			22 : "吉林省",
			23 : "黑龙江省",
			31 : "上海市",
			32 : "江苏省",
			33 : "浙江省",
			34 : "安徽省",
			35 : "福建省",
			36 : "江西省",
			37 : "山东省",
			41 : "河南省",
			42 : "湖北省",
			43 : "湖南省",
			44 : "广东省",
			45 : "广西",
			46 : "海南省",
			50 : "重庆市",
			51 : "四川省",
			52 : "贵州省",
			53 : "云南省",
			54 : "西藏",
			61 : "陕西省",
			62 : "甘肃省",
			63 : "青海省",
			64 : "宁夏",
			65 : "新疆",
			71 : "台湾",
			81 : "香港",
			82 : "澳门",
			91 : "国外"
		}
		return area[cardno.substr(0, 2)];
	}
	/**
	* Check 大陸身份證號碼是否合法
	*/
	function checkCnIdCard(idcard) {
		var Errors = new Array(
				'Y',
				"身份證號長度不對",
				"身份證號中出生年月日有誤.",
				"身份證號最後一碼錯誤.",
				"身份證號前兩位有誤");
		var idcard,Y,JYM;
		var S,M;
		var idcard_array = new Array();
		idcard_array = idcard.split("");
		//地区检验
		if (getArea(idcard) == null)
			return Errors[4];
		//身份号码位数及格式检验
		switch (idcard.length) {
			case 15:
				if ((parseInt(idcard.substr(6, 2)) + 1900) % 4 == 0 || ((parseInt(idcard.substr(6, 2)) + 1900) % 100 == 0 && (parseInt(idcard.substr(6, 2)) + 1900) % 4 == 0)) {
					ereg = /^[1-9][0-9]{5}[0-9]{2}((01|03|05|07|08|10|12)(0[1-9]|[1-2][0-9]|3[0-1])|(04|06|09|11)(0[1-9]|[1-2][0-9]|30)|02(0[1-9]|[1-2][0-9]))[0-9]{3}$/; //测试出生日期的合法性
				} else {
					ereg = /^[1-9][0-9]{5}[0-9]{2}((01|03|05|07|08|10|12)(0[1-9]|[1-2][0-9]|3[0-1])|(04|06|09|11)(0[1-9]|[1-2][0-9]|30)|02(0[1-9]|1[0-9]|2[0-8]))[0-9]{3}$/; //测试出生日期的合法性
				}
				if (ereg.test(idcard))
					return Errors[0];
				else
					return Errors[2];
				break;
			case 18:
				//18位身份号码检测
				//出生日期的合法性检查	
				//闰年月日:((01|03|05|07|08|10|12)(0[1-9]|[1-2][0-9]|3[0-1])|(04|06|09|11)(0[1-9]|[1-2][0-9]|30)|02(0[1-9]|[1-2][0-9]))		
				//平年月日:((01|03|05|07|08|10|12)(0[1-9]|[1-2][0-9]|3[0-1])|(04|06|09|11)(0[1-9]|[1-2][0-9]|30)|02(0[1-9]|1[0-9]|2[0-8]))
				if (parseInt(idcard.substr(6, 4)) % 4 == 0 || (parseInt(idcard.substr(6, 4)) % 100 == 0 && parseInt(idcard.substr(6, 4)) % 4 == 0)) {
					ereg = /^[1-9][0-9]{5}19[0-9]{2}((01|03|05|07|08|10|12)(0[1-9]|[1-2][0-9]|3[0-1])|(04|06|09|11)(0[1-9]|[1-2][0-9]|30)|02(0[1-9]|[1-2][0-9]))[0-9]{3}[0-9Xx]$/; //闰年出生日期的合法性正则表达式
				} else {
					ereg = /^[1-9][0-9]{5}19[0-9]{2}((01|03|05|07|08|10|12)(0[1-9]|[1-2][0-9]|3[0-1])|(04|06|09|11)(0[1-9]|[1-2][0-9]|30)|02(0[1-9]|1[0-9]|2[0-8]))[0-9]{3}[0-9Xx]$/; //平年出生日期的合法性正则表达式
				}
				if (ereg.test(idcard)) { //测试出生日期的合法性
					//计算校验位
					S = (parseInt(idcard_array[0]) + parseInt(idcard_array[10])) * 7
					 + (parseInt(idcard_array[1]) + parseInt(idcard_array[11])) * 9
					 + (parseInt(idcard_array[2]) + parseInt(idcard_array[12])) * 10
					 + (parseInt(idcard_array[3]) + parseInt(idcard_array[13])) * 5
					 + (parseInt(idcard_array[4]) + parseInt(idcard_array[14])) * 8
					 + (parseInt(idcard_array[5]) + parseInt(idcard_array[15])) * 4
					 + (parseInt(idcard_array[6]) + parseInt(idcard_array[16])) * 2
					 + parseInt(idcard_array[7]) * 1
					 + parseInt(idcard_array[8]) * 6
					 + parseInt(idcard_array[9]) * 3;
					Y = S % 11;
					M = "F";
					JYM = "10X98765432";
					M = JYM.substr(Y, 1); //判断校验位
					if (M == idcard_array[17])
						return Errors[0]; //检测ID的校验位
					else
						return Errors[3];
				} else
					return Errors[2];
				break;
			default:
				return Errors[1];
				break;
		}
	}
	/*
	* get gender from CN idcard by the
	*/
	function getGenderFromCnIdCard(cardno)
	{
		var chkcode = cardno.substr(16,1);
		return (chkcode%2 == 0 ? '女' : '男');
		
	}
	/*
	* get gender from TW idcard by the
	*/
	function getGenderFromTwIdCard(cardno)
	{
		return (cardno.substr(1,1) == 1 ? '男' : '女');	
	}
	
	//**************************************
	// 台灣身份證檢查簡短版 for Javascript
	// http://doublekai.org/blog/?p=482
	//**************************************
	function checkTwIdCard(id) {
		var Errors = new Array(
					"Y",
					"身份證號格式有誤,請檢查",
					"身份證號有誤,請檢查");
	 	//建立字母分數陣列(A~Z)
	 	var city = new Array(
	 			1, 10, 19, 28, 37, 46, 55, 64, 39, 73, 82, 2, 11,
	 			20, 48, 29, 38, 47, 56, 65, 74, 83, 21, 3, 12, 30)
	 		id = id.toUpperCase();
	 	// 使用「正規表達式」檢驗格式
	 	if (id.search(/^[A-Z](1|2)\d{8}$/i) == -1) {
	 		return Errors[1];
	 	} else {
	 		//將字串分割為陣列(IE必需這麼做才不會出錯)
	 		id = id.split('');
	 		//計算總分
	 		var total = city[id[0].charCodeAt(0) - 65];
	 		for (var i = 1; i <= 8; i++) {
	 			total += eval(id[i]) * (9 - i);
	 		}
	 		//補上檢查碼(最後一碼)
	 		total += eval(id[9]);
	 		//檢查比對碼(餘數應為0);
	 		if((total % 10 == 0))
			{
	 			return Errors[0];
			}else{
				return Errors[2];
			}
	 	}
	 }
	 
	/**
    * Get Star Sign According the Birthday
    * @param string birthday format: yyyymmdd (20120120)
    * @return array key and value with star sign name
    * @author Dennis
    */
    function getStarSign(birthday)
    {
        var starsigns = new Array();
        starsigns['C1']='水瓶';
        starsigns['C2']='雙魚';
        starsigns['C3']='牡羊';
        starsigns['C4']='金牛';
        starsigns['C5']='雙子';
        starsigns['C6']='巨蟹';
        starsigns['C7']='獅子';
        starsigns['C8']='處女';
        starsigns['C9']='天秤';
        starsigns['C10']='天蠍';
        starsigns['C11']='射手';
        starsigns['C12']='魔羯';
        var mon = birthday.substr(4,2);
        var day = birthday.substr(6,2);
        var res = new Array();
        res['k'] = '00';
        res['v'] = 'Error';
        switch(mon)
        {
            case '01':
                res['k'] = day<21 ? 'C12' : 'C1';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<21){res='魔羯';}else{res='水瓶';} break;
            case '02':
                res['k'] = day<20 ? 'C1' : 'C2';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<20){res='水瓶';}else{res='雙魚';} break;
            case '03':
                res['k'] = day<21 ? 'C2' : 'C3';
                res['v'] = starsigns[res['k']];
                break;
                //if(day<21){res='雙魚';}else{res='牧羊';} break;
            case '04':
                res['k'] = day<20 ? 'C3' : 'C4';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<20){res='牧羊';}else{res='金牛';} break;
            case '05':
                res['k'] = day<21 ? 'C4' : 'C5';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<21){res='金牛';}else{res='雙子';} break;
            case '06':
                res['k'] = day<22 ? 'C5' : 'C6';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<22){res='雙子';}else{res='巨蟹';} break;
            case '07':
                res['k'] = day<23 ? 'C6' : 'C7';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<23){res='巨蟹';}else{res='獅子';} break;
            case '08':
                res['k'] = day<23 ? 'C7' : 'C8';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<23){res='獅子';}else{res='處女';} break;
            case '09':
                res['k'] = day<23 ? 'C8' : 'C9';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<23){res='處女';}else{res='天秤';} break;
            case '10':
                res['k'] = day<24 ? 'C9' : 'C10';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<24){res='天秤';}else{res='天蠍';} break;
            case '11':
                res['k'] = day<22 ? 'C10' : 'C11';
                res['v'] = starsigns[res['k']];
                return res;
                //if(day<22){res='天蠍';}else{res='射手';} break;
            case '12':
                res['k'] = day<22 ? 'C11' : 'C12';
                res['v'] = starsigns[res['k']];
                return res;
        }
        return res;
    }