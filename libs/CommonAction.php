<?php

//add by bear[2016/3/16]
//thinkPHP实现移动端访问自动切换主题模板
class CommonAction extends Action{
	public function _initialize(){
		//移动设别浏览，则切换模板
		if(ismobile()){
			//设置默认默认主题为Mobile
			C('DEFAULT_THEME','Mobile');
		}
		//更多我的代码
		
	}
}