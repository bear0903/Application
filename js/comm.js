/*
 * 共用 JS 
 *  $HeadURL: https://192.168.0.101/svn/ehr/trunk/eHR/js/comm.js $
 *  $Id: comm.js 712 2008-11-19 07:11:56Z dennis $
 *  $Rev: 712 $ 
 *  $Date: 2008-11-19 15:11:56 +0800 (周三, 19 十一月 2008) $
 *  $Author: dennis $   
 *  $LastChangedDate: 2008-11-19 15:11:56 +0800 (周三, 19 十一月 2008) $
 ****************************************************************************/

/**
*	set Cookie
*/
function setCookie(cookieName,cookieValue,nDays) {
	var today = new Date();
	var expire = new Date();
	//if (nDays==null || nDays==0) nDays=1;
	//expire.setTime(today.getTime() + 3600000*24*nDays);
	document.cookie = cookieName+"="+escape(cookieValue);//+ ";expires="+expire.toGMTString();
}

/*
*  Help function for ge_column_list()
*/
function getCookie(name) {
   var mm_cookie = document.cookie;
   var index = mm_cookie.indexOf(name + "=");
   if (index == -1) return null;
   index = mm_cookie.indexOf("=", index) + 1; // first character
   var endstr = mm_cookie.indexOf(";", index);
   if (endstr == -1) endstr = mm_cookie.length; // last character
   return unescape(mm_cookie.substring(index, endstr));    
}
/*
*  Help function for get_column_list()
*  reference function getCookie()
*/
function deleteCookie (name) {
  var exp = new Date();
  exp.setTime (exp.getTime() - 1);  // This cookie is history
  var cval = getCookie(name);
  document.cookie = name + "=" + cval + "; expires=" + exp.toGMTString();
}

/**
*  @function:goto_index
*  @desc 
*     complete logout when session timeout, location to the index page
*  @para no parameter
*  @return boolean value
*  @author: Dennis.Lan
*  @lastupdate: 2005-02-25 14:54:16 
*/
function goto_index()
{
   try
   {
      if (typeof(top.topFrame.document)=="object")
      {
         top.location = document.location;
      }
   }
   catch (e)
   {
      // no code here
   }
   return true;
}

/**
*  @function get_next_year()
*  @desc get next year date after the old_date
*  @param days , the add days, must be a integer
*  @return date string, format: yyyymm not full format string
*  @author: dennis lan
*  @last update: 2005-10-09 11:25:34 
*/
function get_next_year(p_date){
   var li_year, li_month;
   li_year = Number(p_date.substr(0,4));
   li_month = Number(p_date.substr(4,2));
   li_year  += 1;

   if (li_month - 1 == 0){
      li_month = 12;
      li_year -= 1;
   }else{
      li_month = li_month-1;
   }

   li_month = li_month <10 ? '0'+li_month : li_month;
   return li_year.toString() + li_month.toString();
}

/*


       ���ܣ�ͨ��JavaScript�ű������

       ��(��

                     1.Trim(str)����ȥ���ַ�}�ߵĿո�

                     2.XMLEncode(str)�������ַ����XML����

            3.ShowLabel(str,str)���������ʾ���ܣ���ʾ�ַ���ʾ�ַ�

                     4.IsEmpty(obj)������֤������Ƿ�Ϊ��

                     5.IsInt(objStr,sign,zero)������֤�Ƿ�Ϊ����

                     6.IsFloat(objStr,sign,zero)������֤�Ƿ�Ϊ������

                     7.IsEnLetter(objStr,size)������֤�Ƿ�Ϊ26����ĸ

 

    ���ߣ�����

    ���ڣ�2004/04/14

*/

 
/*********************************************
1. LTrim(str)ȥ��str��ߵĿհ��ַ�(�ո񣬻��У��س�)
2. RTrim(str)ȥ��ste�ұߵĿհ��ַ�(�ո񣬻��У��س�)
3. Trim(str)ȥ��ste}�ߵĿհ��ַ�(�ո񣬻��У��س�)
*********************************************/

function LTrim(str) { 
    return str.replace(/^[ \t\n\r]+/g, "");
}

function RTrim(str) {
    return str.replace(/[ \t\n\r]+$/g, "");
}

function Trim(str) {
    return RTrim(LTrim(str));
}

/*

================================================================================

XMLEncode(string):���ַ����XML����

================================================================================

*/

function XMLEncode(str)

{

       str=Trim(str);

       str=str.replace("&","&amp;");

       str=str.replace("<","&lt;");

       str=str.replace(">","&gt;");

       str=str.replace("'","&apos;");

       str=str.replace("\"","&quot;");

       return str;

}

 

/*

================================================================================

��֤�ຯ��

================================================================================

*/

 

function IsEmpty(obj)

{

    obj=document.getElementsByName(obj).item(0);

    if(Trim(obj.value)=="")

    {

        alert("�ֶβ���Ϊ�ա�");        

        if(obj.disabled==false && obj.readOnly==false)

        {

            obj.focus();

        }

    }

}

 

/*

IsInt(string,string,int or string):(�����ַ�,+ or - or empty,empty or 0)

���ܣ��ж��Ƿ�Ϊ��������������������+0��������+0

*/

function IsInt(objStr,sign,zero)

{

    var reg;    

    var bolzero;    

    

    if(Trim(objStr)=="")

    {

        return false;

    }

    else

    {

        objStr=objStr.toString();

    }    

    

    if((sign==null)||(Trim(sign)==""))

    {

        sign="+-";

    }

    

    if((zero==null)||(Trim(zero)==""))

    {

        bolzero=false;

    }

    else

    {

        zero=zero.toString();

        if(zero=="0")

        {

            bolzero=true;

        }

        else

        {

            alert("����Ƿ��0����ֻ��Ϊ(�ա�0)");

        }

    }

    

    switch(sign)

    {

        case "+-":

            //����

            reg=/(^-?|^\+?)\d+$/;            

            break;

        case "+": 

            if(!bolzero)           

            {

                //������

                reg=/^\+?[0-9]*[1-9][0-9]*$/;

            }

            else

            {

                //������+0

                //reg=/^\+?\d+$/;

                reg=/^\+?[0-9]*[0-9][0-9]*$/;

            }

            break;

        case "-":

            if(!bolzero)

            {

                //������

                reg=/^-[0-9]*[1-9][0-9]*$/;

            }

            else

            {

                //������+0

                //reg=/^-\d+$/;

                reg=/^-[0-9]*[0-9][0-9]*$/;

            }            

            break;

        default:

            alert("����Ų���ֻ��Ϊ(�ա�+��-)");

            return false;

            break;

    }

    

    var r=objStr.match(reg);

    if(r==null)

    {

        return false;

    }

    else

    {        

        return true;     

    }

}

 

/*

IsFloat(string,string,int or string):(�����ַ�,+ or - or empty,empty or 0)

���ܣ��ж��Ƿ�Ϊ���������������������+0����������+0

*/

function IsFloat(objStr,sign,zero)
{
    var reg;
    var bolzero; 
    if(Trim(objStr)=="")
    {
        return false;
    }
    else
    {
        objStr=objStr.toString();
    }
    if((sign==null)||(Trim(sign)==""))
    {
        sign="+-";
    }
    if((zero==null)||(Trim(zero)==""))
    {
        bolzero=false;
    }
    else
    {
        zero=zero.toString();
        if(zero=="0")
        {
            bolzero=true;
        }
        else
        {
            alert("����Ƿ��0����ֻ��Ϊ(�ա�0)");
        }
    }
    switch(sign)
    {
        case "+-":
            //������
            reg=/^((-?|\+?)\d+)(\.\d+)?$/;
            break;
        case "+": 
            if(!bolzero)
            {
                //�����
                reg=/^\+?(([0-9]+\.[0-9]*[1-9][0-9]*)|([0-9]*[1-9][0-9]*\.[0-9]+)|([0-9]*[1-9][0-9]*))$/;
            }
            else
            {
                //�����+0
                reg=/^\+?\d+(\.\d+)?$/;
            }
            break;
        case "-":

            if(!bolzero)

            {

                //��������

                reg=/^-(([0-9]+\.[0-9]*[1-9][0-9]*)|([0-9]*[1-9][0-9]*\.[0-9]+)|([0-9]*[1-9][0-9]*))$/;

            }

            else

            {

                //��������+0

                reg=/^((-\d+(\.\d+)?)|(0+(\.0+)?))$/;

            }            

            break;

        default:

            alert("����Ų���ֻ��Ϊ(�ա�+��-)");

            return false;

            break;

    }

    

    var r=objStr.match(reg);

    if(r==null)

    {

        return false;

    }

    else

    {        

        return true;     

    }

}
/*

IsEnLetter(string,string):�����ַ���Сд(UL,U,L or ul,u,l)

*/

function IsEnLetter(objStr,size)

{

    var reg;

    

    if(Trim(objStr)=="")

    {

        return false;

    }

    else

    {

        objStr=objStr.toString();

    }    

    

    if((size==null)||(Trim(size)==""))

    {

        size="UL";

    }

    else

    {

        size=size.toUpperCase();

    }

    

    switch(size)

    {

        case "UL":

            //��Сд

            reg=/^[A-Za-z]+$/;

            break;

        case "U": 

            //��д

            reg=/^[A-Z]+$/;

            break;

        case "L":

            //Сд

            reg=/^[a-z]+$/;

            break;

        default:

            alert("����Сд����ֻ��Ϊ(�ա�UL��U��L)");

            return false;

            break;

    }

    

    var r=objStr.match(reg);

    if(r==null)

    {

        return false;

    }

    else

    {        

        return true;     

    }

}

//支持ff，ie的收藏

function addToFavorite()
{
    kdocTitle = document.title;//标题 
    if(kdocTitle == null){ 
        var t_titles = document.getElementByTagName("title") 
        if(t_titles && t_titles.length >0) 
        { 
           kdocTitle = t_titles[0]; 
        }else{ 
           kdocTitle = ""; 
        } 
    } 
    if (document.all)
        window.external.addFavorite(window.location.href, kdocTitle);
    else if (window.sidebar)
        window.sidebar.addPanel(kdocTitle, window.location.href, "");
}
 
