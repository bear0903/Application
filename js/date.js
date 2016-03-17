/*===================================================================
 Author: Matt Kruse
 
 View documentation, examples, and source code at:
     http://www.JavascriptToolbox.com/

 NOTICE: You may use this code for any purpose, commercial or
 private, without any further permission from the author. You may
 remove this notice from your final code if you wish, however it is
 appreciated by the author if at least the web site address is kept.

 This code may NOT be distributed for download from script sites, 
 open source CDs or sites, or any other distribution method. If you
 wish you share this code with others, please direct them to the 
 web site above.
 
 Pleae do not link directly to the .js files on the server above. Copy
 the files to your own server for use with your site or webapp.
 ===================================================================*/
Date.$VERSION = 1.01;
Date.LZ = function(x){return(x<0||x>9?"":"0")+x};Date.monthNames = new Array('January','February','March','April','May','June','July','August','September','October','November','December');Date.monthAbbreviations = new Array('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');Date.dayNames = new Array('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday');Date.dayAbbreviations = new Array('Sun','Mon','Tue','Wed','Thu','Fri','Sat');Date.preferAmericanFormat = true;if(!Date.prototype.getFullYear){Date.prototype.getFullYear = function(){var yy=this.getYear();return(yy<1900?yy+1900:yy);}}
Date.parseString = function(val, format){if(typeof(format)=="undefined" || format==null || format==""){var generalFormats=new Array('y-M-d','MMM d, y','MMM d,y','y-MMM-d','d-MMM-y','MMM d','MMM-d','d-MMM');var monthFirst=new Array('M/d/y','M-d-y','M.d.y','M/d','M-d');var dateFirst =new Array('d/M/y','d-M-y','d.M.y','d/M','d-M');var checkList=new Array(generalFormats,Date.preferAmericanFormat?monthFirst:dateFirst,Date.preferAmericanFormat?dateFirst:monthFirst);for(var i=0;i<checkList.length;i++){var l=checkList[i];for(var j=0;j<l.length;j++){var d=Date.parseString(val,l[j]);if(d!=null){return d;}}}return null;}
this.isInteger = function(val){for(var i=0;i < val.length;i++){if("1234567890".indexOf(val.charAt(i))==-1){return false;}}return true;};
this.getInt = function(str,i,minlength,maxlength){for(var x=maxlength;x>=minlength;x--){var token=str.substring(i,i+x);if(token.length < minlength){return null;}if(this.isInteger(token)){return token;}}return null;};val=val+"";format=format+"";var i_val=0;var i_format=0;var c="";var token="";var token2="";var x,y;var year=new Date().getFullYear();var month=1;var date=1;var hh=0;var mm=0;var ss=0;var ampm="";while(i_format < format.length){c=format.charAt(i_format);token="";while((format.charAt(i_format)==c) &&(i_format < format.length)){token += format.charAt(i_format++);}if(token=="yyyy" || token=="yy" || token=="y"){if(token=="yyyy"){x=4;y=4;}if(token=="yy"){x=2;y=2;}if(token=="y"){x=2;y=4;}year=this.getInt(val,i_val,x,y);if(year==null){return null;}i_val += year.length;if(year.length==2){if(year > 70){year=1900+(year-0);}else{year=2000+(year-0);}}}else if(token=="MMM" || token=="NNN"){month=0;var names =(token=="MMM"?(Date.monthNames.concat(Date.monthAbbreviations)):Date.monthAbbreviations);for(var i=0;i<names.length;i++){var month_name=names[i];if(val.substring(i_val,i_val+month_name.length).toLowerCase()==month_name.toLowerCase()){month=(i%12)+1;i_val += month_name.length;break;}}if((month < 1)||(month>12)){return null;}}else if(token=="EE"||token=="E"){var names =(token=="EE"?Date.dayNames:Date.dayAbbreviations);for(var i=0;i<names.length;i++){var day_name=names[i];if(val.substring(i_val,i_val+day_name.length).toLowerCase()==day_name.toLowerCase()){i_val += day_name.length;break;}}}else if(token=="MM"||token=="M"){month=this.getInt(val,i_val,token.length,2);if(month==null||(month<1)||(month>12)){return null;}i_val+=month.length;}else if(token=="dd"||token=="d"){date=this.getInt(val,i_val,token.length,2);if(date==null||(date<1)||(date>31)){return null;}i_val+=date.length;}else if(token=="hh"||token=="h"){hh=this.getInt(val,i_val,token.length,2);if(hh==null||(hh<1)||(hh>12)){return null;}i_val+=hh.length;}else if(token=="HH"||token=="H"){hh=this.getInt(val,i_val,token.length,2);if(hh==null||(hh<0)||(hh>23)){return null;}i_val+=hh.length;}else if(token=="KK"||token=="K"){hh=this.getInt(val,i_val,token.length,2);if(hh==null||(hh<0)||(hh>11)){return null;}i_val+=hh.length;hh++;}else if(token=="kk"||token=="k"){hh=this.getInt(val,i_val,token.length,2);if(hh==null||(hh<1)||(hh>24)){return null;}i_val+=hh.length;hh--;}else if(token=="mm"||token=="m"){mm=this.getInt(val,i_val,token.length,2);if(mm==null||(mm<0)||(mm>59)){return null;}i_val+=mm.length;}else if(token=="ss"||token=="s"){ss=this.getInt(val,i_val,token.length,2);if(ss==null||(ss<0)||(ss>59)){return null;}i_val+=ss.length;}else if(token=="a"){if(val.substring(i_val,i_val+2).toLowerCase()=="am"){ampm="AM";}else if(val.substring(i_val,i_val+2).toLowerCase()=="pm"){ampm="PM";}else{return null;}i_val+=2;}else{if(val.substring(i_val,i_val+token.length)!=token){return null;}else{i_val+=token.length;}}}if(i_val != val.length){return null;}if(month==2){if( ((year%4==0)&&(year%100 != 0) ) ||(year%400==0) ){if(date > 29){return null;}}else{if(date > 28){return null;}}}if((month==4)||(month==6)||(month==9)||(month==11)){if(date > 30){return null;}}if(hh<12 && ampm=="PM"){hh=hh-0+12;}else if(hh>11 && ampm=="AM"){hh-=12;}return new Date(year,month-1,date,hh,mm,ss);}
Date.isValid = function(val,format){return(Date.parseString(val,format) != null);}
Date.prototype.isBefore = function(date2){if(date2==null){return false;}return(this.getTime()<date2.getTime());}
Date.prototype.isAfter = function(date2){if(date2==null){return false;}return(this.getTime()>date2.getTime());}
Date.prototype.equals = function(date2){if(date2==null){return false;}return(this.getTime()==date2.getTime());}
Date.prototype.equalsIgnoreTime = function(date2){if(date2==null){return false;}var d1 = new Date(this.getTime()).clearTime();var d2 = new Date(date2.getTime()).clearTime();return(d1.getTime()==d2.getTime());}
Date.prototype.format = function(format){format=format+"";var result="";var i_format=0;var c="";var token="";var y=this.getYear()+"";var M=this.getMonth()+1;var d=this.getDate();var E=this.getDay();var H=this.getHours();var m=this.getMinutes();var s=this.getSeconds();var yyyy,yy,MMM,MM,dd,hh,h,mm,ss,ampm,HH,H,KK,K,kk,k;var value=new Object();if(y.length < 4){y=""+(+y+1900);}value["y"]=""+y;value["yyyy"]=y;value["yy"]=y.substring(2,4);value["M"]=M;value["MM"]=Date.LZ(M);value["MMM"]=Date.monthNames[M-1];value["NNN"]=Date.monthAbbreviations[M-1];value["d"]=d;value["dd"]=Date.LZ(d);value["E"]=Date.dayAbbreviations[E];value["EE"]=Date.dayNames[E];value["H"]=H;value["HH"]=Date.LZ(H);if(H==0){value["h"]=12;}else if(H>12){value["h"]=H-12;}else{value["h"]=H;}value["hh"]=Date.LZ(value["h"]);value["K"]=value["h"]-1;value["k"]=value["H"]+1;value["KK"]=Date.LZ(value["K"]);value["kk"]=Date.LZ(value["k"]);if(H > 11){value["a"]="PM";}else{value["a"]="AM";}value["m"]=m;value["mm"]=Date.LZ(m);value["s"]=s;value["ss"]=Date.LZ(s);while(i_format < format.length){c=format.charAt(i_format);token="";while((format.charAt(i_format)==c) &&(i_format < format.length)){token += format.charAt(i_format++);}if(value[token] != null){result=result + value[token];}else{result=result + token;}}return result;}
Date.prototype.getDayName = function(){return Date.dayNames[this.getDay()];}
Date.prototype.getDayAbbreviation = function(){return Date.dayAbbreviations[this.getDay()];}
Date.prototype.getMonthName = function(){return Date.monthNames[this.getMonth()];}
Date.prototype.getMonthAbbreviation = function(){return Date.monthAbbreviations[this.getMonth()];}
Date.prototype.clearTime = function(){this.setHours(0);this.setMinutes(0);this.setSeconds(0);this.setMilliseconds(0);
return this;}
Date.prototype.add = function(interval, number){if(typeof(interval)=="undefined" || interval==null || typeof(number)=="undefined" || number==null){
return this;}number = +number;if(interval=='y'){this.setFullYear(this.getFullYear()+number);}else if(interval=='M'){this.setMonth(this.getMonth()+number);}else if(interval=='d'){this.setDate(this.getDate()+number);}else if(interval=='w'){var step =(number>0)?1:-1;while(number!=0){this.add('d',step);while(this.getDay()==0 || this.getDay()==6){this.add('d',step);}number -= step;}}else if(interval=='h'){this.setHours(this.getHours() + number);}else if(interval=='m'){this.setMinutes(this.getMinutes() + number);}else if(interval=='s'){this.setSeconds(this.getSeconds() + number);}
return this;}

/*********************************************************************
* 判断字符串strDate是否为一个正确的日期格式：
* yyyy-M-d或yyyy-MM-dd
* 编写人：郑艳伟
* *******************************************************************/
function IsDate(strDate)
{
    // 先判断格式上是否正确
    var regDate = /^(\d{4})-(\d{1,2})-(\d{1,2})$/;
    if (!regDate.test(strDate))
    {
        return false;
    }
     
    // 将年、月、日的值取到数组arr中，其中arr[0]为整个字符串，arr[1]-arr[3]为年、月、日
    var arr = regDate.exec(strDate);
     
    // 判断年、月、日的取值范围是否正确
    return IsMonthAndDateCorrect(arr[1], arr[2], arr[3]);
}
 
/*********************************************************************
* 判断字符串strDateTime是否为一个正确的日期时间格式：
* yyyy-M-d H:m:s或yyyy-MM-dd HH:mm:ss
* 时间采用24小时制
* 编写人：郑艳伟
* *******************************************************************/
function IsDateTime(strDateTime,dateFormat)
{
	
    // 先判断格式上是否正确
    var regDateTime;
    switch(dateFormat){
	    case 'yyyy-mm-dd hh:mi':
	    	regDateTime = /^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2})$/;
	    	break;
	    case 'yyyy-mm-dd hh:mi:ss':
	    	regDateTime = /^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2})$/;
	    	break;
	    default:
    		break;
    }
    if (!regDateTime.test(strDateTime))
        return false;
         
    // 将年、月、日、时、分、秒的值取到数组arr中，其中arr[0]为整个字符串，arr[1]-arr[6]为年、月、日、时、分、秒
    var arr = regDateTime.exec(strDateTime);
     
    // 判断年、月、日的取值范围是否正确
    if (!IsMonthAndDateCorrect(arr[1], arr[2], arr[3]))
        return false;
         
    // 判断时、分、秒的取值范围是否正确
    if (arr[4] >= 24)
        return false;
    if (arr[5] >= 60)
        return false;
    if (arr[6] >= 60)
        return false;
     
    // 正确的返回
    return true;
}
 
// 判断年、月、日的取值范围是否正确
function IsMonthAndDateCorrect(nYear, nMonth, nDay)
{
    // 月份是否在1-12的范围内，注意如果该字符串不是C#语言的，而是JavaScript的，月份范围为0-11
    if (nMonth > 12 || nMonth <= 0)
        return false;
 
    // 日是否在1-31的范围内，不是则取值不正确
    if (nDay > 31 || nMonth <= 0)
        return false;
     
    // 根据月份判断每月最多日数
    var bTrue = false;
    switch(nMonth)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 8:
        case 10:
        case 12:
            bTrue = true;    // 大月，由于已判断过nDay的范围在1-31内，因此直接返回true
            break;
        case 4:
        case 6:
        case 9:
        case 11:
            bTrue = (nDay <= 30);    // 小月，如果小于等于30日返回true
            break;
    }
     
    if (!bTrue)
        return true;
     
    // 2月的情况
    // 如果小于等于28天一定正确
    if (nDay <= 28)
        return true;
    // 闰年小于等于29天正确
    if (IsLeapYear(nYear))
        return (nDay <= 29);
    // 不是闰年，又不小于等于28，返回false
    return false;
}
 
// 是否为闰年，规则：四年一闰，百年不闰，四百年再闰
function IsLeapYear(nYear)
{
    // 如果不是4的倍数，一定不是闰年
    if (nYear % 4 != 0)
        return false;
    // 是4的倍数，但不是100的倍数，一定是闰年
    if (nYear % 100 != 0)
        return true;
     
    // 是4和100的倍数，如果又是400的倍数才是闰年
    return (nYear % 400 == 0);
}

